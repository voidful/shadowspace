import Foundation
import CryptoKit
import Network

/// 純 Swift/CryptoKit 的 TLS 1.3 客戶端，疊在原始 TCP（NWStream）之上，ClientHello 完全可控
/// （瀏覽器指紋、可選 REALITY）。取代不可自訂握手的 Apple NWProtocolTLS，是 uTLS/REALITY/Vision 的地基。
///
/// M1 範圍：完整 1-RTT 握手（X25519 或 macOS 26+ 的 X25519MLKEM768）、AEAD record、應用資料雙工。
/// 不驗證憑證鏈（對應現行 allowInsecure；REALITY 於 M2 另做認證）。不支援 HelloRetryRequest（僅提供
/// 有 share 的群組故不觸發）、client cert、0-RTT。
public final class NativeTLS13Client: ByteStream, @unchecked Sendable {

    private let under: ByteStream
    private let records: TLS13RecordLayer
    private let sni: String
    private let alpn: [String]
    private let preset: FingerprintPreset
    private let reality: RealityClientConfig?

    private var hsBuffer = Data()          // 已解密、尚未切出訊息的握手位元組
    private var appBuffer = Data()          // 握手後溢出的應用資料（罕見）
    private var appCipher: AEADCipher = .aes128gcm
    // 交握後 KeyUpdate 輪替所需（於握手完成時填入）
    private var appHash: TLS13Hash = .sha256
    private var appKeyLen = 16
    private var readAppSecret = Data()
    private var writeAppSecret = Data()

    public init(under: ByteStream, sni: String, alpn: [String], preset: FingerprintPreset,
                reality: RealityClientConfig? = nil) {
        self.under = under
        self.records = TLS13RecordLayer(under: under)
        self.sni = sni
        self.alpn = alpn
        self.preset = preset
        self.reality = reality
    }

    /// 撥出 raw TCP 並完成 TLS 1.3 握手。
    public static func dial(host: String, port: UInt16, sni: String, alpn: [String],
                            preset: FingerprintPreset, reality: RealityClientConfig? = nil,
                            queue: DispatchQueue) async throws -> NativeTLS13Client {
        let tcp = NWStream(host: host, port: port, queue: queue)   // raw TCP，內含 disablingSystemProxy
        try await tcp.start()
        let client = NativeTLS13Client(under: tcp, sni: sni, alpn: alpn, preset: preset, reality: reality)
        do {
            try await client.handshake()   // 握手常態擲回（REALITY 驗證失敗、alert…）
        } catch {
            tcp.close()                    // 釋放底層 socket/FD，避免重試迴圈累積孤兒連線
            throw error
        }
        return client
    }

    /// 從 TLS 1.3 Certificate(0x0b) 訊息 body 取 leaf 憑證 DER。
    /// body = cert_request_context(u8Vec) ‖ certificate_list(u24Vec){ cert_data(u24Vec) ‖ ext(u16Vec) … }
    private static func parseLeafCert(_ body: Data) -> Data? {
        var r = ByteReader(body)
        guard (try? r.u8Vec()) != nil, let list = try? r.u24Vec() else { return nil }
        var lr = ByteReader(list)
        guard let der = try? lr.u24Vec() else { return nil }
        return Data(der)
    }

    // MARK: - 握手

    private func cipher(from suite: Int) throws -> AEADCipher {
        switch suite {
        case 0x1301: return .aes128gcm
        case 0x1302: return .aes256gcm
        case 0x1303: return .chacha20
        default: throw TLS13Error.handshakeFailure("伺服器選了非 TLS1.3 密碼套件 0x\(String(suite, radix: 16))")
        }
    }

    private static let hrrRandom: [UInt8] = [
        0xCF,0x21,0xAD,0x74,0xE5,0x9A,0x61,0x11,0xBE,0x1D,0x8C,0x02,0x1E,0x65,0xB8,0x91,
        0xC2,0xA2,0x11,0x16,0x7A,0xBB,0x8C,0x5E,0x07,0x9E,0x09,0xE2,0xC8,0xA8,0x33,0x9C]

    /// 解析 ServerHello，回傳 (cipher suite, 選定群組, server key_exchange)。
    private func parseServerHello(_ body: Data) throws -> (suite: Int, group: Int, keyExchange: Data) {
        var r = ByteReader(body)
        _ = try r.u16()                                  // legacy_version
        let random = try r.take(32)
        if random == Self.hrrRandom { throw TLS13Error.unsupported("HelloRetryRequest（M1 未支援）") }
        _ = try r.u8Vec()                                // legacy_session_id_echo
        let suite = try r.u16()
        _ = try r.u8()                                   // legacy_compression_method
        let extBytes = try r.u16Vec()
        var er = ByteReader(extBytes)
        var group: Int? = nil
        var keyExchange: Data? = nil
        var version13 = false
        while er.remaining >= 4 {
            let et = try er.u16()
            let ed = try er.u16Vec()
            switch et {
            case 0x002b:   // supported_versions（selected）
                if ed.count == 2, Int(ed[0]) << 8 | Int(ed[1]) == 0x0304 { version13 = true }
            case 0x0033:   // key_share（selected）
                var kr = ByteReader(ed)
                group = try kr.u16()
                keyExchange = Data(try kr.u16Vec())
            default: break
            }
        }
        guard version13 else { throw TLS13Error.handshakeFailure("伺服器未選 TLS 1.3") }
        guard let g = group, let ke = keyExchange else { throw TLS13Error.handshakeFailure("ServerHello 缺 key_share") }
        return (suite, g, ke)
    }

    /// 從解密後的握手位元組流切出下一則完整握手訊息。必要時讀更多 record。
    private func nextHandshakeMessage() async throws -> (type: Int, raw: Data, body: Data) {
        while true {
            if hsBuffer.count >= 4 {
                let b = [UInt8](hsBuffer)
                let type = Int(b[0])
                let len = Int(b[1]) << 16 | Int(b[2]) << 8 | Int(b[3])
                if hsBuffer.count >= 4 + len {
                    let raw = Data(b[0..<(4 + len)])
                    let bodyStart = 4
                    let body = Data(b[bodyStart..<(4 + len)])
                    hsBuffer = Data(b[(4 + len)...])
                    return (type, raw, body)
                }
            }
            let (t, payload) = try await records.readRecord()
            switch t {
            case ContentType.handshake: hsBuffer.append(payload)
            case ContentType.changeCipherSpec: continue      // 相容模式 CCS，丟棄
            case ContentType.alert:
                let a = [UInt8](payload)
                throw TLS13Error.alert(a.first ?? 0, a.count > 1 ? a[1] : 0)
            default: hsBuffer.append(payload)
            }
        }
    }

    private func handshake() async throws {
        // 1. ClientHello（明文）+ CCS（相容模式）
        let ch = try ClientHelloBuilder(sni: sni, alpn: alpn, preset: preset, reality: reality).build()
        try await records.writePlaintext(type: ContentType.handshake, body: ch.handshakeMessage, recordVersion: 0x0301)
        try await records.writePlaintext(type: ContentType.changeCipherSpec, body: Data([0x01]))

        // 2. ServerHello（明文握手）
        let sh = try await nextHandshakeMessage()
        guard sh.type == 0x02 else { throw TLS13Error.handshakeFailure("預期 ServerHello，收到 0x\(String(sh.type, radix: 16))") }
        let (suite, group, serverKE) = try parseServerHello(sh.body)
        let aead = try cipher(from: suite)
        let H = aead.hash
        self.appCipher = aead

        guard let kex = ch.keyExchanges.first(where: { $0.group.rawValue == group }) else {
            throw TLS13Error.handshakeFailure("伺服器選的群組 0x\(String(group, radix: 16)) 未提供 share")
        }
        let ecdhe = try kex.sharedSecret(peerShare: serverKE)

        // 3. transcript（CH ‖ SH）→ 握手金鑰
        var transcript = TLS13Transcript(H)
        transcript.update(ch.handshakeMessage)
        transcript.update(sh.raw)
        let thCHSH = transcript.current()

        let zeros = TLS13KeySchedule.zeros(H)
        let early = TLS13KeySchedule.extract(H, salt: zeros, ikm: zeros)
        let derivedES = TLS13KeySchedule.deriveSecret(H, secret: early, label: "derived", transcriptHash: H.hash(Data()))
        let hsSecret = TLS13KeySchedule.extract(H, salt: derivedES, ikm: ecdhe)
        let cHS = TLS13KeySchedule.deriveSecret(H, secret: hsSecret, label: "c hs traffic", transcriptHash: thCHSH)
        let sHS = TLS13KeySchedule.deriveSecret(H, secret: hsSecret, label: "s hs traffic", transcriptHash: thCHSH)
        let (cHSKey, cHSIV) = TLS13KeySchedule.trafficKeyIV(H, secret: cHS, keyLength: aead.keyLength)
        let (sHSKey, sHSIV) = TLS13KeySchedule.trafficKeyIV(H, secret: sHS, keyLength: aead.keyLength)
        records.installReadKey(cipher: aead, key: sHSKey, iv: sHSIV)   // 解密伺服器 flight

        // master secret（IKM=0，salt=derived(hs)）
        let derivedHS = TLS13KeySchedule.deriveSecret(H, secret: hsSecret, label: "derived", transcriptHash: H.hash(Data()))
        let master = TLS13KeySchedule.extract(H, salt: derivedHS, ikm: zeros)

        // 4. 讀伺服器 flight：EncryptedExtensions, [Certificate, CertificateVerify], Finished
        var sawFinished = false
        var thBeforeServerFinished = Data()
        var serverLeafCert: Data?
        while !sawFinished {
            let msg = try await nextHandshakeMessage()
            switch msg.type {
            case 0x08, 0x0b, 0x0f, 0x0c, 0x19:   // EncryptedExtensions / Certificate / CertificateVerify / CertRequest / CompressedCertificate
                // 不驗證憑證鏈：壓縮憑證(0x19)也原樣餵 transcript 即可（Finished 是對「已送出位元組」計算），無須解壓。
                if msg.type == 0x0b { serverLeafCert = Self.parseLeafCert(msg.body) }
                transcript.update(msg.raw)
            case 0x14:                     // server Finished
                thBeforeServerFinished = transcript.current()
                let finishedKey = TLS13KeySchedule.finishedKey(H, secret: sHS)
                let expected = TLS13KeySchedule.verifyData(H, finishedKey: finishedKey, transcriptHash: thBeforeServerFinished)
                guard Data(msg.body) == expected else {
                    throw TLS13Error.handshakeFailure("server Finished 驗證失敗")
                }
                transcript.update(msg.raw)
                sawFinished = true
            default:
                throw TLS13Error.handshakeFailure("非預期握手訊息 0x\(String(msg.type, radix: 16))")
            }
        }

        // 5. 應用金鑰（transcript = CH..serverFinished）
        let thCHSF = transcript.current()
        let cAP = TLS13KeySchedule.deriveSecret(H, secret: master, label: "c ap traffic", transcriptHash: thCHSF)
        let sAP = TLS13KeySchedule.deriveSecret(H, secret: master, label: "s ap traffic", transcriptHash: thCHSF)
        let (cAPKey, cAPIV) = TLS13KeySchedule.trafficKeyIV(H, secret: cAP, keyLength: aead.keyLength)
        let (sAPKey, sAPIV) = TLS13KeySchedule.trafficKeyIV(H, secret: sAP, keyLength: aead.keyLength)

        // 6. client Finished（用 c hs 金鑰加密），再切到應用金鑰
        records.installWriteKey(cipher: aead, key: cHSKey, iv: cHSIV)
        let cFinishedKey = TLS13KeySchedule.finishedKey(H, secret: cHS)
        let cVerifyData = TLS13KeySchedule.verifyData(H, finishedKey: cFinishedKey, transcriptHash: thCHSF)
        var fin = ByteWriter(); fin.u8(0x14); fin.u24(cVerifyData.count); fin.raw(cVerifyData)
        try await records.writeEncrypted(content: fin.data, type: ContentType.handshake)

        records.installWriteKey(cipher: aead, key: cAPKey, iv: cAPIV)
        records.installReadKey(cipher: aead, key: sAPKey, iv: sAPIV)

        // 保存以供交握後 KeyUpdate 金鑰輪替
        appHash = H; appKeyLen = aead.keyLength
        writeAppSecret = cAP; readAppSecret = sAP

        // 7. REALITY 伺服器驗證：leaf 憑證須為 Ed25519 且 HMAC-SHA512(authKey, pub) == 憑證簽章。
        //    失敗代表對方是 decoy 真站或 MITM，而非真正的 REALITY 伺服器 → 中止。
        if reality != nil {
            guard let ak = ch.authKey, let cert = serverLeafCert else {
                throw TLS13Error.handshakeFailure("REALITY：缺 authKey 或伺服器憑證")
            }
            guard RealityCrypto.verifyServer(authKey: ak, leafCertDER: cert) else {
                throw TLS13Error.handshakeFailure("REALITY 伺服器驗證失敗（憑證 HMAC 不符：可能遭 MITM 或此節點非 REALITY）")
            }
        }
    }

    // MARK: - ByteStream（握手後的應用資料）

    /// XTLS Vision splice：切 Direct 後，該方向不再走外層 TLS，直接讀/寫原始 TCP。
    private var readSplice = false
    private var writeSplice = false
    public func enterReadSplice() { readSplice = true }
    public func enterWriteSplice() { writeSplice = true }

    public func read() async throws -> Data {
        if !appBuffer.isEmpty { let d = appBuffer; appBuffer = Data(); return d }
        if readSplice { return try await records.rawRead() }
        while true {
            let (t, payload) = try await records.readRecord()
            switch t {
            case ContentType.applicationData:
                return payload
            case ContentType.handshake:
                // 交握後訊息。KeyUpdate(0x18) 必須處理：伺服器已輪替其送出金鑰，否則後續解密失敗。
                let hs = [UInt8](payload)
                if hs.count >= 5, hs[0] == 0x18 {
                    let requested = hs[4] == 0x01
                    readAppSecret = TLS13KeySchedule.nextTrafficSecret(appHash, secret: readAppSecret)
                    let (rk, riv) = TLS13KeySchedule.trafficKeyIV(appHash, secret: readAppSecret, keyLength: appKeyLen)
                    records.installReadKey(cipher: appCipher, key: rk, iv: riv)   // seq 歸零
                    if requested {
                        // 先以現行寫金鑰回送自身 KeyUpdate(update_not_requested)，再輪替寫金鑰（順序符合 RFC 8446）
                        try await records.writeEncrypted(content: Data([0x18, 0x00, 0x00, 0x01, 0x00]), type: ContentType.handshake)
                        writeAppSecret = TLS13KeySchedule.nextTrafficSecret(appHash, secret: writeAppSecret)
                        let (wk, wiv) = TLS13KeySchedule.trafficKeyIV(appHash, secret: writeAppSecret, keyLength: appKeyLen)
                        records.installWriteKey(cipher: appCipher, key: wk, iv: wiv)
                    }
                }
                continue   // KeyUpdate 已處理；NewSessionTicket 等忽略；續讀下一筆
            case ContentType.alert:
                let a = [UInt8](payload)
                if a.count >= 2 && a[1] == 0 { return Data() }   // close_notify = EOF
                throw TLS13Error.alert(a.first ?? 0, a.count > 1 ? a[1] : 0)
            default:
                continue
            }
        }
    }

    public func write(_ data: Data) async throws {
        if writeSplice { try await records.rawWrite(data); return }
        let maxRecord = 16384
        var idx = data.startIndex
        while idx < data.endIndex {
            let end = data.index(idx, offsetBy: min(maxRecord, data.distance(from: idx, to: data.endIndex)))
            try await records.writeEncrypted(content: Data(data[idx..<end]), type: ContentType.applicationData)
            idx = end
        }
    }

    public func close() { under.close() }
}
