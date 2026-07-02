import Foundation
import CryptoKit

public enum TLS13Error: Error, CustomStringConvertible {
    case unexpectedEOF
    case decodeError(String)
    case unsupported(String)
    case handshakeFailure(String)
    case alert(UInt8, UInt8)   // level, description

    public var description: String {
        switch self {
        case .unexpectedEOF: return "TLS: 連線在握手中中斷"
        case .decodeError(let m): return "TLS 解碼錯誤：\(m)"
        case .unsupported(let m): return "TLS 不支援：\(m)"
        case .handshakeFailure(let m): return "TLS 握手失敗：\(m)"
        case .alert(let l, let d): return "TLS alert level=\(l) desc=\(d)"
        }
    }
}

enum ContentType {
    static let changeCipherSpec = 0x14
    static let alert = 0x15
    static let handshake = 0x16
    static let applicationData = 0x17
}

enum AEADCipher {
    case aes128gcm   // TLS_AES_128_GCM_SHA256 (0x1301)
    case aes256gcm   // TLS_AES_256_GCM_SHA384 (0x1302)
    case chacha20    // TLS_CHACHA20_POLY1305_SHA256 (0x1303)

    var keyLength: Int { self == .aes128gcm ? 16 : 32 }
    var hash: TLS13Hash { self == .aes256gcm ? .sha384 : .sha256 }

    /// AEAD seal：回傳 ciphertext‖tag。
    func seal(_ plaintext: Data, key: SymmetricKey, nonce: Data, aad: Data) throws -> Data {
        switch self {
        case .aes128gcm, .aes256gcm:
            let box = try AES.GCM.seal(plaintext, using: key, nonce: AES.GCM.Nonce(data: nonce), authenticating: aad)
            return box.ciphertext + box.tag
        case .chacha20:
            let box = try ChaChaPoly.seal(plaintext, using: key, nonce: ChaChaPoly.Nonce(data: nonce), authenticating: aad)
            return box.ciphertext + box.tag
        }
    }

    /// AEAD open：輸入 ciphertext‖tag(16)。
    func open(_ data: Data, key: SymmetricKey, nonce: Data, aad: Data) throws -> Data {
        guard data.count >= 16 else { throw TLS13Error.decodeError("record 過短") }
        let ct = data.prefix(data.count - 16)
        let tag = data.suffix(16)
        switch self {
        case .aes128gcm, .aes256gcm:
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonce), ciphertext: ct, tag: tag)
            return try AES.GCM.open(box, using: key, authenticating: aad)
        case .chacha20:
            let box = try ChaChaPoly.SealedBox(nonce: ChaChaPoly.Nonce(data: nonce), ciphertext: ct, tag: tag)
            return try ChaChaPoly.open(box, using: key, authenticating: aad)
        }
    }
}

/// 在底層原始 ByteStream（通常是 NWStream，raw TCP）之上讀寫 TLS record，並管理讀/寫方向的
/// AEAD 金鑰與序號。ServerHello 前為明文；之後 outer type=application_data(0x17) 的 record 皆加密。
final class TLS13RecordLayer {
    private let under: ByteStream
    private var inbuf = Data()

    // 讀方向（server → client）
    private var readCipher: AEADCipher?
    private var readKey: SymmetricKey?
    private var readIV: Data?
    private var readSeq: UInt64 = 0

    // 寫方向（client → server）
    private var writeCipher: AEADCipher?
    private var writeKey: SymmetricKey?
    private var writeIV: Data?
    private var writeSeq: UInt64 = 0

    init(under: ByteStream) { self.under = under }

    /// 安裝讀方向金鑰（握手→應用 各呼叫一次），序號歸零。
    func installReadKey(cipher: AEADCipher, key: Data, iv: Data) {
        readCipher = cipher; readKey = SymmetricKey(data: key); readIV = iv; readSeq = 0
    }
    func installWriteKey(cipher: AEADCipher, key: Data, iv: Data) {
        writeCipher = cipher; writeKey = SymmetricKey(data: key); writeIV = iv; writeSeq = 0
    }

    private func readExactly(_ n: Int) async throws -> Data {
        while inbuf.count < n {
            let chunk = try await under.read()
            if chunk.isEmpty { throw TLS13Error.unexpectedEOF }
            inbuf.append(chunk)
        }
        let out = Data(inbuf.prefix(n))
        inbuf = Data(inbuf.dropFirst(n))
        return out
    }

    /// 送出明文 record（ClientHello、ChangeCipherSpec）。
    func writePlaintext(type: Int, body: Data, recordVersion: Int = 0x0303) async throws {
        var w = ByteWriter()
        w.u8(type); w.u16(recordVersion); w.u16Vec(body)
        try await under.write(w.data)
    }

    /// 送出加密 record：inner = content ‖ realType，外層 type=application_data。
    func writeEncrypted(content: Data, type: Int) async throws {
        guard let c = writeCipher, let key = writeKey, let iv = writeIV else {
            throw TLS13Error.handshakeFailure("寫金鑰未安裝")
        }
        var inner = content
        inner.append(UInt8(type))
        var header = ByteWriter()
        header.u8(ContentType.applicationData); header.u16(0x0303); header.u16(inner.count + 16)
        let nonce = TLS13KeySchedule.perRecordNonce(staticIV: iv, sequence: writeSeq)
        let sealed = try c.seal(inner, key: key, nonce: nonce, aad: header.data)
        writeSeq += 1
        try await under.write(header.data + sealed)
    }

    /// 讀下一個 record。回傳 (contentType, payload)。
    /// outer=application_data 時用讀金鑰解密並回傳「inner 內容型別 + 去尾 0 後的內容」；
    /// 其餘（handshake/CCS/alert）為明文原樣回傳。
    func readRecord() async throws -> (type: Int, payload: Data) {
        let header = try await readExactly(5)
        let outerType = Int(header[header.startIndex])
        let length = Int(header[header.startIndex + 3]) << 8 | Int(header[header.startIndex + 4])
        let body = try await readExactly(length)

        if outerType == ContentType.applicationData, let c = readCipher, let key = readKey, let iv = readIV {
            let nonce = TLS13KeySchedule.perRecordNonce(staticIV: iv, sequence: readSeq)
            let inner = try c.open(body, key: key, nonce: nonce, aad: header)
            readSeq += 1
            let arr = [UInt8](inner)
            var i = arr.count - 1
            while i >= 0 && arr[i] == 0 { i -= 1 }
            guard i >= 0 else { throw TLS13Error.decodeError("record 全為 padding") }
            return (Int(arr[i]), Data(arr[0..<i]))
        }
        return (outerType, body)
    }
}
