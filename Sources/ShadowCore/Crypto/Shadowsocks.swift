import Foundation
import CryptoKit
import Security

/// Shadowsocks AEAD（SIP004）加密方式。
public enum SSMethod: Sendable {
    case aes128gcm
    case aes256gcm
    case chacha20poly1305

    public init?(_ method: String) {
        switch method.lowercased() {
        case "aes-128-gcm": self = .aes128gcm
        case "aes-256-gcm": self = .aes256gcm
        case "chacha20-ietf-poly1305", "chacha20-poly1305": self = .chacha20poly1305
        default: return nil
        }
    }

    public var keyLength: Int {
        switch self {
        case .aes128gcm: return 16
        case .aes256gcm, .chacha20poly1305: return 32
        }
    }
    public var saltLength: Int { keyLength }
}

/// Shadowsocks 金鑰衍生與 AEAD 分塊密碼。
public enum ShadowsocksCrypto {

    /// 由密碼導出主金鑰：OpenSSL EVP_BytesToKey（MD5、無 salt、單回合）。
    public static func masterKey(password: String, keyLength: Int) -> Data {
        let pw = Data(password.utf8)
        var key = Data()
        var prev = Data()
        while key.count < keyLength {
            var md5 = Insecure.MD5()
            md5.update(data: prev)
            md5.update(data: pw)
            prev = Data(md5.finalize())
            key.append(prev)
        }
        return key.prefix(keyLength)
    }

    /// 每連線子金鑰：HKDF-SHA1(masterKey, salt, "ss-subkey")。
    public static func subkey(masterKey: Data, salt: Data, keyLength: Int) -> SymmetricKey {
        HKDF<Insecure.SHA1>.deriveKey(
            inputKeyMaterial: SymmetricKey(data: masterKey),
            salt: salt,
            info: Data("ss-subkey".utf8),
            outputByteCount: keyLength)
    }

    public static func randomSalt(_ length: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: length)
        guard SecRandomCopyBytes(kSecRandomDefault, length, &bytes) == errSecSuccess else {
            fatalError("SecRandomCopyBytes 失敗：拒絕以可預測 salt 出站")   // fail-closed
        }
        return Data(bytes)
    }
}

/// 單把子金鑰的 AEAD 封裝；nonce 由呼叫端提供（12 位元組）。
/// 輸出/輸入皆為 ciphertext‖tag(16) 的串接（Shadowsocks 線格式）。
public struct SSCipher: Sendable {
    public let method: SSMethod
    private let key: SymmetricKey

    public init(method: SSMethod, subkey: SymmetricKey) {
        self.method = method
        self.key = subkey
    }

    public func seal(_ plaintext: Data, nonce: Data) throws -> Data {
        switch method {
        case .chacha20poly1305:
            let box = try ChaChaPoly.seal(plaintext, using: key, nonce: ChaChaPoly.Nonce(data: nonce))
            var sealed = Data()              // 保證 0 起始；Data 切片串接會沿用索引基準
            sealed.append(box.ciphertext)
            sealed.append(box.tag)
            return sealed
        case .aes128gcm, .aes256gcm:
            let box = try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(data: nonce))
            var sealed = Data()              // 保證 0 起始；Data 切片串接會沿用索引基準
            sealed.append(box.ciphertext)
            sealed.append(box.tag)
            return sealed
        }
    }

    public func open(_ data: Data, nonce: Data) throws -> Data {
        guard data.count >= 16 else { throw ProxyError.protocolError("AEAD 區塊過短") }
        let ct = Data(data.prefix(data.count - 16))
        let tag = Data(data.suffix(16))
        switch method {
        case .chacha20poly1305:
            let box = try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: nonce), ciphertext: ct, tag: tag)
            return try ChaChaPoly.open(box, using: key)
        case .aes128gcm, .aes256gcm:
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: ct, tag: tag)
            return try AES.GCM.open(box, using: key)
        }
    }
}

/// 12 位元組小端序遞增 nonce 計數器。
final class SSNonce {
    private var bytes = [UInt8](repeating: 0, count: 12)
    func next() -> Data {
        let current = Data(bytes)
        var i = 0
        while i < bytes.count {
            bytes[i] = bytes[i] &+ 1
            if bytes[i] != 0 { break }
            i += 1
        }
        return current
    }
}

/// Shadowsocks AEAD 串流：把底層明文 TCP 包成加密雙工串流。
/// 送：salt ‖ AEAD(len)‖AEAD(payload) … ；收：對方 salt ‖ 加密分塊。
public final class ShadowsocksStream: ByteStream, @unchecked Sendable {
    private let under: NWStream
    private let method: SSMethod
    private let masterKey: Data
    private let target: Target

    private var sendCipher: SSCipher?
    private let sendNonce = SSNonce()
    private var recvCipher: SSCipher?
    private let recvNonce = SSNonce()
    private var headerSent = false

    private static let maxChunk = 0x3FFF   // 16383

    public init(under: NWStream, method: SSMethod, masterKey: Data, target: Target) {
        self.under = under
        self.method = method
        self.masterKey = masterKey
        self.target = target
    }

    /// 送出 salt + 第一個分塊（= SOCKS 目標位址），讓伺服器立即知道要連去哪。
    private func ensureHeaderSent() async throws {
        guard !headerSent else { return }
        headerSent = true
        let salt = ShadowsocksCrypto.randomSalt(method.saltLength)
        let subkey = ShadowsocksCrypto.subkey(masterKey: masterKey, salt: salt, keyLength: method.keyLength)
        sendCipher = SSCipher(method: method, subkey: subkey)
        try await under.write(salt)
        try await writeChunk(SocksAddress.encode(target))
    }

    private func writeChunk(_ plaintext: Data) async throws {
        guard let cipher = sendCipher else { return }
        let len = UInt16(plaintext.count)
        let lenData = Data([UInt8(len >> 8), UInt8(len & 0xff)])
        let encLen = try cipher.seal(lenData, nonce: sendNonce.next())
        let encPayload = try cipher.seal(plaintext, nonce: sendNonce.next())
        try await under.write(encLen + encPayload)
    }

    public func write(_ data: Data) async throws {
        try await ensureHeaderSent()
        var idx = data.startIndex
        while idx < data.endIndex {
            let step = min(Self.maxChunk, data.distance(from: idx, to: data.endIndex))
            let end = data.index(idx, offsetBy: step)
            try await writeChunk(Data(data[idx..<end]))
            idx = end
        }
    }

    public func read() async throws -> Data {
        if recvCipher == nil {
            let salt = try await under.readExactly(method.saltLength)
            let subkey = ShadowsocksCrypto.subkey(masterKey: masterKey, salt: salt, keyLength: method.keyLength)
            recvCipher = SSCipher(method: method, subkey: subkey)
        }
        guard let cipher = recvCipher else { return Data() }

        let encLen: Data
        do {
            encLen = try await under.readExactly(2 + 16)
        } catch NWStream.StreamError.eof {
            return Data()   // 乾淨 EOF
        }
        let lenData = try cipher.open(encLen, nonce: recvNonce.next())
        let i0 = lenData.startIndex            // 不假設 0 起始
        let payloadLen = Int(lenData[i0]) << 8 | Int(lenData[lenData.index(after: i0)])
        guard payloadLen > 0 else { return Data() }
        let encPayload = try await under.readExactly(payloadLen + 16)
        return try cipher.open(encPayload, nonce: recvNonce.next())
    }

    public func close() { under.close() }
}
