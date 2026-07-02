import Foundation
import CryptoKit

/// key_share 支援群組。
enum KeyShareGroup: Int {
    case x25519 = 0x001d
    case x25519mlkem768 = 0x11ec   // draft-ietf-tls-ecdhe-mlkem，現代 Chrome 主群組
}

/// 客戶端 key_share 私鑰載體：序列化時給出公開 share，收到 ServerHello 後算 ECDHE 祕密。
final class TLS13KeyExchange {
    let group: KeyShareGroup
    private let x25519: Curve25519.KeyAgreement.PrivateKey
    private let mlkem: Any?   // macOS 26+ 才有的 MLKEM768.PrivateKey；以 Any 避免 ABI 觸及新型別

    init(group: KeyShareGroup) {
        self.group = group
        self.x25519 = Curve25519.KeyAgreement.PrivateKey()
        if group == .x25519mlkem768, #available(macOS 26.0, *) {
            self.mlkem = try? MLKEM768.PrivateKey()
        } else {
            self.mlkem = nil
        }
    }

    /// 放進 key_share 的 key_exchange 位元組。hybrid = ML-KEM ek(1184) ‖ X25519 pub(32)。
    func publicShare() -> Data {
        let x = x25519.publicKey.rawRepresentation
        if group == .x25519mlkem768, #available(macOS 26.0, *), let sk = mlkem as? MLKEM768.PrivateKey {
            return sk.publicKey.rawRepresentation + x
        }
        return x
    }

    /// 與任意 32-byte X25519 公鑰做 ECDH（REALITY authKey 用：對端為伺服器 pbk，非 TLS key_share）。
    func x25519SharedSecret(withRawPublicKey pub: Data) throws -> Data {
        let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: pub)
        return try x25519.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
    }

    /// 由 server 回傳的 key_exchange 算出 ECDHE 祕密（handshake extract 的 IKM）。
    /// hybrid：server share = ML-KEM ct(1088) ‖ X25519 pub(32)；祕密 = ML-KEM ss(32) ‖ X25519 ss(32)。
    func sharedSecret(peerShare: Data) throws -> Data {
        switch group {
        case .x25519:
            let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerShare)
            return try x25519.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
        case .x25519mlkem768:
            guard #available(macOS 26.0, *), let sk = mlkem as? MLKEM768.PrivateKey else {
                throw TLS13Error.unsupported("此系統無 ML-KEM（需 macOS 26+）")
            }
            guard peerShare.count == 1088 + 32 else {
                throw TLS13Error.decodeError("hybrid server share 長度 \(peerShare.count) 非 1120")
            }
            let ct = Data(peerShare.prefix(1088))
            let xpub = Data(peerShare.suffix(32))
            let mlss = try sk.decapsulate(ct).withUnsafeBytes { Data($0) }
            let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: xpub)
            let xss = try x25519.sharedSecretFromKeyAgreement(with: peer).withUnsafeBytes { Data($0) }
            return mlss + xss
        }
    }
}

/// 指紋預設。`.chrome` 於 macOS 26+ 送現代 Chrome 的 X25519MLKEM768 混合 key_share，
/// 舊系統回退純 X25519 的 pin Chrome 指紋。
public enum FingerprintPreset: String, Sendable {
    case chrome
    case chromeX25519   // 強制純 X25519（相容 macOS 14）

    public init(_ raw: String?) {
        switch (raw ?? "").lowercased() {
        case "chrome", "": self = .chrome
        default: self = .chrome
        }
    }
}

/// 組出瀏覽器風格的 ClientHello（含 GREASE、Chrome 擴充順序、可控 key_share）。
struct ClientHelloBuilder {
    let sni: String
    let alpn: [String]
    let preset: FingerprintPreset
    /// REALITY 設定；非 nil 時強制純 X25519、省略憑證壓縮、並把認證封進 session_id。
    var reality: RealityClientConfig? = nil
    /// REALITY session_id 的 unixtime；0 = 取當前時間（測試時可固定）。
    var now: UInt32 = 0

    /// 產物：完整握手訊息位元組（type ‖ u24(len) ‖ body，可直接餵 transcript 與 record）與 key_share 私鑰群。
    struct Output {
        let handshakeMessage: Data
        let keyExchanges: [TLS13KeyExchange]
        /// REALITY 時 = authKey（同時用於 session_id 封裝與伺服器 HMAC-SHA512 憑證驗證）。
        let authKey: Data?
    }

    private static func randomBytes(_ n: Int) -> Data {
        var b = [UInt8](repeating: 0, count: n)
        guard SecRandomCopyBytes(kSecRandomDefault, n, &b) == errSecSuccess else {
            fatalError("SecRandomCopyBytes 失敗：拒絕以可預測 random/key_share 出站")   // fail-closed
        }
        return Data(b)
    }

    private static func ext(_ type: Int, _ data: Data) -> Data {
        var w = ByteWriter(); w.u16(type); w.u16Vec(data); return w.data
    }

    func build() throws -> Output {
        // GREASE：cipher/group/keyshare/version 共用 g1（不同命名空間可重用）；
        // 但首、尾兩個 GREASE「擴充型別」必須相異，否則屬重複擴充 → decode_error。
        let g1 = GREASE.values[0]   // 0x0a0a
        let g2 = GREASE.values[3]   // 0x3a3a（尾端 GREASE 擴充，須 ≠ g1）

        let isReality = reality != nil
        // 決定 key_share 群組：REALITY 一律純 X25519（伺服器以 X25519 keyshare 做認證 ECDH，避免混合模式歧義）；
        // 否則 macOS 26+ 用 hybrid + X25519。
        var kexes: [TLS13KeyExchange] = []
        var useHybrid = false
        if !isReality, preset == .chrome, #available(macOS 26.0, *) { useHybrid = true }
        if useHybrid { kexes.append(TLS13KeyExchange(group: .x25519mlkem768)) }
        kexes.append(TLS13KeyExchange(group: .x25519))

        // --- cipher_suites ---
        var cs = ByteWriter()
        cs.u16(g1)
        for s in [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030,
                  0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035] { cs.u16(s) }

        // --- 各擴充 ---
        // server_name
        var sniList = ByteWriter(); sniList.u8(0); sniList.u16Vec(Data(sni.utf8))
        var sniExtData = ByteWriter(); sniExtData.u16Vec(sniList.data)
        // ALPN
        var alpnList = ByteWriter(); for p in alpn { alpnList.u8Vec(Data(p.utf8)) }
        var alpnExtData = ByteWriter(); alpnExtData.u16Vec(alpnList.data)
        // supported_groups（僅列我們能提供 share 的群組 → 避免 HelloRetryRequest）
        var groups = ByteWriter(); groups.u16(g1)
        if useHybrid { groups.u16(KeyShareGroup.x25519mlkem768.rawValue) }
        groups.u16(KeyShareGroup.x25519.rawValue)
        var groupsExtData = ByteWriter(); groupsExtData.u16Vec(groups.data)
        // signature_algorithms
        var sigs = ByteWriter()
        for s in [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601] { sigs.u16(s) }
        var sigsExtData = ByteWriter(); sigsExtData.u16Vec(sigs.data)
        // key_share：GREASE(1-byte) + 各 kex
        var shares = ByteWriter()
        shares.u16(g1); shares.u16Vec(Data([0x00]))
        for k in kexes { shares.u16(k.group.rawValue); shares.u16Vec(k.publicShare()) }
        var keyShareExtData = ByteWriter(); keyShareExtData.u16Vec(shares.data)
        // supported_versions：GREASE, TLS1.3, TLS1.2
        var vers = ByteWriter(); vers.u16(g1); vers.u16(0x0304); vers.u16(0x0303)
        var versExtData = ByteWriter(); versExtData.u8Vec(vers.data)

        var exts = Data()
        exts += Self.ext(g1, Data())                                  // GREASE（首）
        exts += Self.ext(0x0000, sniExtData.data)                     // server_name
        exts += Self.ext(0x0017, Data())                              // extended_master_secret
        exts += Self.ext(0xff01, Data([0x00]))                        // renegotiation_info
        exts += Self.ext(0x000a, groupsExtData.data)                  // supported_groups
        exts += Self.ext(0x000b, Data([0x01, 0x00]))                  // ec_point_formats: uncompressed
        exts += Self.ext(0x0023, Data())                              // session_ticket
        exts += Self.ext(0x0010, alpnExtData.data)                    // ALPN
        exts += Self.ext(0x0005, Data([0x01, 0x00, 0x00, 0x00, 0x00])) // status_request (OCSP)
        exts += Self.ext(0x000d, sigsExtData.data)                    // signature_algorithms
        exts += Self.ext(0x0012, Data())                              // signed_certificate_timestamp
        exts += Self.ext(0x0033, keyShareExtData.data)                // key_share
        exts += Self.ext(0x002d, Data([0x01, 0x01]))                  // psk_key_exchange_modes: psk_dhe_ke
        exts += Self.ext(0x002b, versExtData.data)                    // supported_versions
        // compress_certificate：REALITY 省略，避免伺服器回壓縮憑證(0x19)，因我們需解析未壓縮 leaf 憑證做驗證。
        if !isReality { exts += Self.ext(0x001b, Data([0x02, 0x00, 0x02])) }  // compress_certificate: brotli
        exts += Self.ext(g2, Data([0x00]))                            // GREASE（尾，須 ≠ g1）

        // random 與 session_id 只生成一次；REALITY 先用 32 個 0（AAD 需為此狀態），封裝後再回填。
        let clientRandom = Self.randomBytes(32)
        let sessionId = isReality ? Data(repeating: 0, count: 32) : Self.randomBytes(32)

        // --- 組 body（padding 前）以計算 padding ---
        func assemble(paddingLen: Int) -> Data {
            var b = ByteWriter()
            b.u16(0x0303)                          // legacy_version
            b.raw(clientRandom)                    // random
            b.u8Vec(sessionId)                     // legacy_session_id
            b.u16Vec(cs.data)                      // cipher_suites
            b.u8Vec(Data([0x00]))                  // compression: null
            var allExts = exts
            if paddingLen >= 0 {
                allExts += Self.ext(0x0015, Data(repeating: 0, count: paddingLen))
            }
            b.u16Vec(allExts)
            return b.data
        }
        // 目標：ClientHello record 補到 ~512 bytes（含 4-byte 握手 header）。
        let bodyNoPad = assemble(paddingLen: -1)
        let target = 512
        let overhead = 4 + 2 + 2   // 握手 header + padding ext header
        var padLen = target - (bodyNoPad.count + overhead)
        if padLen < 0 { padLen = 0 }
        let body = assemble(paddingLen: padLen)

        var msg = ByteWriter()
        msg.u8(0x01); msg.u24(body.count); msg.raw(body)
        var message = msg.data

        // --- REALITY：算 authKey、封 session_id、回填 ---
        var authKey: Data? = nil
        if let r = reality {
            guard let kex = kexes.first(where: { $0.group == .x25519 }) else {
                throw TLS13Error.handshakeFailure("REALITY 需要 X25519 key_share")
            }
            let shared = try kex.x25519SharedSecret(withRawPublicKey: r.publicKey)
            let ak = RealityCrypto.authKey(x25519Shared: shared, helloRandom: clientRandom)
            let ts = now == 0 ? UInt32(truncatingIfNeeded: Int(Date().timeIntervalSince1970)) : now
            let pt = RealityCrypto.sessionIDPlaintext(shortID: r.shortID, now: ts)
            // AAD = 整個握手訊息（session_id 此刻為 zeros，與伺服器重建的 AAD 一致）
            let ct = try RealityCrypto.sealSessionID(authKey: ak, helloRandom: clientRandom, plaintext16: pt, aad: message)
            precondition(ct.count == 32)
            let sidOffset = 4 + 2 + 32 + 1   // type(1)+len(3)+ver(2)+random(32)+sidLen(1)
            let lo = message.index(message.startIndex, offsetBy: sidOffset)
            let hi = message.index(lo, offsetBy: 32)
            message.replaceSubrange(lo..<hi, with: ct)
            authKey = ak
        }
        return Output(handshakeMessage: message, keyExchanges: kexes, authKey: authKey)
    }
}
