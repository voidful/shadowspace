import Foundation
import CryptoKit
import CommonCrypto
import Network

/// Shadowsocks 2022 UDP 封包編解碼（SIP022 §3.2）。
/// 封包 = AES-ECB(PSK, 分離頭 16B = sessionID8 ‖ packetID(u64be)8) ‖ AES-GCM(sessionKey, nonce=分離頭[4..16], body)。
/// sessionKey = BLAKE3.derive_key("shadowsocks 2022 session subkey", PSK ‖ sessionID)。
/// body（送）= type0 ‖ ts(u64be) ‖ padLen(u16be) ‖ padding ‖ SOCKS位址 ‖ payload。
/// body（收）= type1 ‖ ts ‖ clientSessionID(8) ‖ padLen ‖ padding ‖ SOCKS位址 ‖ payload。
/// 僅支援 AES 系（2022-blake3-aes-128/256-gcm）；chacha20 的 UDP 構造不同，未支援。
public final class SS2022UDPCodec: @unchecked Sendable {
    public enum CodecError: Error { case unsupportedMethod, decodeFailed, badType, sessionMismatch, aesFailed }

    private let psk: Data
    private let keySize: Int
    private let clientSessionID: Data     // 8 bytes
    private var packetID: UInt64 = 0
    private static let context = "shadowsocks 2022 session subkey"

    /// psk 為已解碼原始金鑰；method 須為 aes 系（chacha20 UDP 構造不同，未支援）。
    public init?(psk: Data, method: SS2022Method) {
        guard method != .chacha20, psk.count == method.keySize else { return nil }
        self.psk = psk
        self.keySize = method.keySize
        var sid = [UInt8](repeating: 0, count: 8)
        guard SecRandomCopyBytes(kSecRandomDefault, 8, &sid) == errSecSuccess else {
            fatalError("SecRandomCopyBytes 失敗：拒絕以可預測 session ID 出站")   // fail-closed
        }
        self.clientSessionID = Data(sid)
    }

    /// method 為字串（如 "2022-blake3-aes-256-gcm"）；password 為 base64 PSK。
    public convenience init?(method: String, password: String) {
        guard let m = SS2022Method(method), let key = Data(base64Encoded: password) else { return nil }
        self.init(psk: key, method: m)
    }

    /// 本 session 的客戶端 session ID（relay 對映、測試用）。
    public var sessionID: Data { clientSessionID }

    private func sessionCipher(sessionID: Data) -> SSCipher {
        let sub = BLAKE3.deriveKey(context: Self.context, keyMaterial: psk + sessionID, length: keySize)
        let aead: SSMethod = keySize == 16 ? .aes128gcm : .aes256gcm
        return SSCipher(method: aead, subkey: SymmetricKey(data: sub))
    }

    private static func u16BE(_ v: Int) -> Data { Data([UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]) }
    private static func u64BE(_ v: UInt64) -> Data {
        var d = Data(); for i in (0..<8).reversed() { d.append(UInt8((v >> (8 * i)) & 0xff)) }; return d
    }
    private static func now() -> UInt64 { UInt64(Date().timeIntervalSince1970) }

    /// AES-ECB 單塊（16 bytes），無 padding。key 長度決定 AES-128/256。
    private static func aesECB(key: Data, block: Data, encrypt: Bool) throws -> Data {
        precondition(block.count == 16)
        var out = [UInt8](repeating: 0, count: 16)
        var moved = 0
        let op = CCOperation(encrypt ? kCCEncrypt : kCCDecrypt)
        let status = key.withUnsafeBytes { kp in
            block.withUnsafeBytes { bp in
                CCCrypt(op, CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
                        kp.baseAddress, key.count, nil,
                        bp.baseAddress, 16, &out, 16, &moved)
            }
        }
        guard status == kCCSuccess, moved == 16 else { throw CodecError.aesFailed }
        return Data(out)
    }

    /// 編碼一個「送往 target 的 payload」為完整 UDP 封包。
    public func encode(payload: Data, to target: Target) throws -> Data {
        let sep = clientSessionID + Self.u64BE(packetID)   // 16B
        packetID &+= 1
        let encSep = try Self.aesECB(key: psk, block: sep, encrypt: true)

        var body = Data([0x00])                            // type = client
        body.append(Self.u64BE(Self.now()))               // timestamp
        body.append(Self.u16BE(0))                          // padding length = 0
        body.append(SocksAddress.encode(target))
        body.append(payload)

        let cipher = sessionCipher(sessionID: clientSessionID)
        let nonce = sep.suffix(12)                          // 分離頭[4..16]
        let encBody = try cipher.seal(body, nonce: Data(nonce))
        return encSep + encBody
    }

    /// 解碼伺服器回來的 UDP 封包 → (來源位址, payload)。
    public func decode(_ packet: Data) throws -> (from: Target, payload: Data) {
        guard packet.count >= 16 + 16 else { throw CodecError.decodeFailed }
        let encSep = Data(packet.prefix(16))
        let sep = try Self.aesECB(key: psk, block: encSep, encrypt: false)
        let serverSessionID = Data(sep.prefix(8))
        let cipher = sessionCipher(sessionID: serverSessionID)
        let nonce = sep.suffix(12)
        let body = try cipher.open(Data(packet.dropFirst(16)), nonce: Data(nonce))

        let b = [UInt8](body)
        // type1 ‖ ts(8) ‖ clientSessionID(8) ‖ padLen(2) ‖ padding ‖ SOCKS位址 ‖ payload
        guard b.count >= 1 + 8 + 8 + 2, b[0] == 0x01 else { throw CodecError.badType }
        let cSid = Data(b[9..<17])
        guard cSid == clientSessionID else { throw CodecError.sessionMismatch }
        let padLen = Int(b[17]) << 8 | Int(b[18])
        let addrOff = 19 + padLen
        guard let (target, next) = SocksAddress.parse(b, at: addrOff) else { throw CodecError.decodeFailed }
        return (target, Data(b[next...]))
    }
}

/// SS-2022 UDP relay：一條連到伺服器的 UDP socket + 一個 codec；send/receive 以 codec 多工目標。
public final class SS2022UDPRelay: UDPRelaySession, @unchecked Sendable {
    private let udp: NWDatagramSession
    private let codec: SS2022UDPCodec

    public init(udp: NWDatagramSession, codec: SS2022UDPCodec) {
        self.udp = udp
        self.codec = codec
    }

    public func send(_ payload: Data, to target: Target) async throws {
        try await udp.send(try codec.encode(payload: payload, to: target))
    }

    public func receive() async throws -> (payload: Data, from: Target) {
        let pkt = try await udp.receive()
        guard !pkt.isEmpty else { throw ProxyError.protocolError("SS-2022 UDP 收到空封包（EOF）") }
        let d = try codec.decode(pkt)
        return (d.payload, d.from)
    }

    public func close() { udp.close() }
}
