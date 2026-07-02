import Foundation
import CryptoKit
import Network

/// Shadowsocks 2022（SIP022，2022-blake3-*）。與 SIP004 不同：PSK 為 base64 原始金鑰、session subkey 用
/// BLAKE3 derive_key、含帶時間戳與 salt 綁定的標頭、chunk 上限 0xFFFF、12-byte 小端序 nonce。
public enum SS2022Method: Sendable {
    case aes128gcm     // 2022-blake3-aes-128-gcm
    case aes256gcm     // 2022-blake3-aes-256-gcm
    case chacha20      // 2022-blake3-chacha20-poly1305

    public init?(_ method: String) {
        switch method.lowercased() {
        case "2022-blake3-aes-128-gcm": self = .aes128gcm
        case "2022-blake3-aes-256-gcm": self = .aes256gcm
        case "2022-blake3-chacha20-poly1305": self = .chacha20
        default: return nil
        }
    }

    /// 金鑰長度 = salt 長度。
    public var keySize: Int { self == .aes128gcm ? 16 : 32 }

    var aead: SSMethod {
        switch self {
        case .aes128gcm: return .aes128gcm
        case .aes256gcm: return .aes256gcm
        case .chacha20: return .chacha20poly1305
        }
    }
}

/// SS-2022 串流：把明文載荷包成帶標頭的 AEAD chunk 流。
public final class SS2022Stream: ByteStream, @unchecked Sendable {
    private enum StreamEnd: Error { case eof }

    private let under: ByteStream
    private let method: SS2022Method
    private let psk: Data           // keySize bytes
    private let target: Target

    private static let context = "shadowsocks 2022 session subkey"
    private static let maxChunk = 0xFFFF

    private var inbuf = Data()
    private var sendCipher: SSCipher?
    private let sendNonce = SSNonce()
    private var recvCipher: SSCipher?
    private let recvNonce = SSNonce()
    private var sentSalt = Data()
    private var headerSent = false
    private var responseParsed = false

    public init(under: ByteStream, method: SS2022Method, psk: Data, target: Target) {
        self.under = under
        self.method = method
        self.psk = psk
        self.target = target
    }

    private func readExactly(_ n: Int) async throws -> Data {
        while inbuf.count < n {
            let chunk = try await under.read()
            if chunk.isEmpty { throw StreamEnd.eof }
            inbuf.append(chunk)
        }
        let out = Data(inbuf.prefix(n)); inbuf = Data(inbuf.dropFirst(n)); return out
    }

    private func sessionKey(salt: Data) -> SSCipher {
        let sub = BLAKE3.deriveKey(context: Self.context, keyMaterial: psk + salt, length: method.keySize)
        return SSCipher(method: method.aead, subkey: SymmetricKey(data: sub))
    }

    private static func u16BE(_ v: Int) -> Data { Data([UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]) }
    private static func timestampBE() -> Data {
        let t = UInt64(Date().timeIntervalSince1970)
        var d = Data(); for i in (0..<8).reversed() { d.append(UInt8((t >> (8 * i)) & 0xff)) }
        return d
    }
    private static func randomBytes(_ n: Int) -> Data {
        var b = [UInt8](repeating: 0, count: n)
        guard SecRandomCopyBytes(kSecRandomDefault, n, &b) == errSecSuccess else {
            fatalError("SecRandomCopyBytes 失敗：拒絕以可預測 salt/nonce 出站")   // fail-closed，避免金鑰/nonce 重用
        }
        return Data(b)
    }

    // MARK: 送出

    /// salt ‖ AEAD(固定頭: type0 ‖ ts8 ‖ varLen2) ‖ AEAD(可變頭: SOCKS位址 ‖ padLen2 ‖ padding)，一次寫出。
    private func sendHeader() async throws {
        let salt = Self.randomBytes(method.keySize)
        sentSalt = salt
        let cipher = sessionKey(salt: salt)
        sendCipher = cipher

        // 可變頭（只放位址 + 隨機 padding，載荷走後續 chunk；padding-only 合法）
        let addr = SocksAddress.encode(target)
        let padLen = Int.random(in: 1...900)
        var varHeader = addr
        varHeader.append(Self.u16BE(padLen))
        varHeader.append(Self.randomBytes(padLen))

        var fixed = Data([0x00])                    // HeaderTypeClientStream
        fixed.append(Self.timestampBE())            // 8-byte unix time
        fixed.append(Self.u16BE(varHeader.count))   // 可變頭長度

        var out = salt
        out.append(try cipher.seal(fixed, nonce: sendNonce.next()))       // nonce 0
        out.append(try cipher.seal(varHeader, nonce: sendNonce.next()))   // nonce 1
        try await under.write(out)
        headerSent = true
    }

    private func writeChunk(_ plaintext: Data) async throws {
        guard let cipher = sendCipher else { return }
        var out = try cipher.seal(Self.u16BE(plaintext.count), nonce: sendNonce.next())
        out.append(try cipher.seal(plaintext, nonce: sendNonce.next()))
        try await under.write(out)
    }

    public func write(_ data: Data) async throws {
        if !headerSent { try await sendHeader() }
        var idx = data.startIndex
        while idx < data.endIndex {
            let step = Swift.min(Self.maxChunk, data.distance(from: idx, to: data.endIndex))
            let end = data.index(idx, offsetBy: step)
            try await writeChunk(Data(data[idx..<end]))
            idx = end
        }
    }

    // MARK: 讀取

    /// 回應：salt ‖ AEAD(固定頭: type1 ‖ ts8 ‖ requestSalt ‖ len2)（兼作首個長度）‖ AEAD(payload) ‖ …
    public func read() async throws -> Data {
        if recvCipher == nil {
            let salt = try await readExactly(method.keySize)
            recvCipher = sessionKey(salt: salt)
            guard let cipher = recvCipher else { return Data() }
            let fixedLen = 1 + 8 + method.keySize + 2
            let enc = try await readExactly(fixedLen + 16)
            let header = try cipher.open(enc, nonce: recvNonce.next())    // nonce 0
            let h = [UInt8](header)
            guard h.count == fixedLen, h[0] == 0x01 else {
                throw ProxyError.protocolError("SS2022 回應標頭型別錯誤")
            }
            let reqSalt = Data(h[9..<9 + method.keySize])
            guard reqSalt == sentSalt else {
                throw ProxyError.protocolError("SS2022 回應 request-salt 不符（反射攻擊防護）")
            }
            let length = Int(h[fixedLen - 2]) << 8 | Int(h[fixedLen - 1])
            responseParsed = true
            if length > 0 {
                let encPayload = try await readExactly(length + 16)
                return try cipher.open(encPayload, nonce: recvNonce.next())   // nonce 1
            }
            // length == 0：首回應無初始 payload，落入下方 chunk 迴圈讀真正的下一 chunk
        }
        guard let cipher = recvCipher else { return Data() }
        // 迴圈讀 length+payload chunk；0 長度 chunk 為合法（跳過、保持 nonce 對齊），只有真 EOF 才回空。
        while true {
            let encLen: Data
            do {
                encLen = try await readExactly(2 + 16)
            } catch StreamEnd.eof {
                return Data()   // 唯一的乾淨 EOF
            }
            let lenData = try cipher.open(encLen, nonce: recvNonce.next())
            let l = [UInt8](lenData)
            let payloadLen = Int(l[0]) << 8 | Int(l[1])
            if payloadLen == 0 { continue }   // 合法 0 長度分塊：勿當 EOF
            let encPayload = try await readExactly(payloadLen + 16)
            return try cipher.open(encPayload, nonce: recvNonce.next())
        }
    }

    public func close() { under.close() }
}

/// SS-2022 出站：連到伺服器，回傳自動 AEAD 收發的串流。password 為 base64 編碼的 PSK。
public struct SS2022Outbound: Outbound {
    public let name: String
    private let server: Target
    private let method: SS2022Method
    private let psk: Data

    public init?(name: String, host: String, port: UInt16, method: String, password: String) {
        guard let m = SS2022Method(method) else { return nil }
        guard let key = Data(base64Encoded: password), key.count == m.keySize else { return nil }
        self.name = name
        self.server = Target(host: host, port: port)
        self.method = m
        self.psk = key
    }

    public func connect(to target: Target, queue: DispatchQueue) async throws -> ByteStream {
        let tcp = NWStream(host: server.host, port: server.port, queue: queue)
        try await tcp.start()
        return SS2022Stream(under: tcp, method: method, psk: psk, target: target)
    }

    public func openUDPRelay(queue: DispatchQueue) async throws -> UDPRelaySession {
        guard let codec = SS2022UDPCodec(psk: psk, method: method) else {
            throw ProxyError.unsupported("SS-2022 UDP 不支援 chacha20（UDP 構造不同）")
        }
        let udp = NWDatagramSession(host: server.host, port: server.port, queue: queue)
        try await udp.start()
        return SS2022UDPRelay(udp: udp, codec: codec)
    }
}
