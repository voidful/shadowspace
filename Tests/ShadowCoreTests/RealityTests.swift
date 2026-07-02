import XCTest
import CryptoKit
@testable import ShadowCore

/// REALITY 客戶端的離線正確性測試（真機另需 Xray REALITY 伺服器）。
/// 覆蓋：pbk/sid 解碼、session_id 封裝（AAD/offset/nonce 端到端）、X.509 抽取 + HMAC-SHA512 伺服器驗證。
final class RealityTests: XCTestCase {

    // MARK: pbk / sid 解碼

    func testPublicKeyBase64URLDecode() throws {
        let raw = Data((0..<32).map { UInt8($0) })
        // 產生 base64url（無補位）
        var b64 = raw.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
        while b64.hasSuffix("=") { b64.removeLast() }
        let cfg = RealityClientConfig(publicKeyString: b64, shortIDHex: "")
        XCTAssertEqual(cfg?.publicKey, raw)
        XCTAssertEqual(cfg?.shortID, Data())   // 空 sid 合法
    }

    func testShortIDHexDecode() {
        XCTAssertEqual(RealityClientConfig(publicKeyString: dummyPbk(), shortIDHex: "01ab")?.shortID,
                       Data([0x01, 0xab]))
        XCTAssertEqual(RealityClientConfig(publicKeyString: dummyPbk(), shortIDHex: "0102030405060708")?.shortID,
                       Data([1, 2, 3, 4, 5, 6, 7, 8]))
        // 超過 8 bytes（>16 hex）應拒絕
        XCTAssertNil(RealityClientConfig(publicKeyString: dummyPbk(), shortIDHex: "010203040506070809"))
    }

    func testBadPublicKeyRejected() {
        XCTAssertNil(RealityClientConfig(publicKeyString: "not-valid-key", shortIDHex: ""))
        XCTAssertNil(RealityClientConfig(publicKeyString: "", shortIDHex: ""))
    }

    // MARK: session_id 封裝（端到端）

    func testRealityClientHelloSessionIDSealRoundTrip() throws {
        // 產一組伺服器 REALITY 靜態金鑰
        let serverPriv = Curve25519.KeyAgreement.PrivateKey()
        let serverPub = serverPriv.publicKey.rawRepresentation
        let shortID = Data([0xde, 0xad, 0xbe, 0xef])
        let cfg = RealityClientConfig(publicKey: serverPub, shortID: shortID)
        let now: UInt32 = 0x11223344

        var builder = ClientHelloBuilder(sni: "www.decoy.example", alpn: ["h2", "http/1.1"], preset: .chrome)
        builder.reality = cfg
        builder.now = now
        let out = try builder.build()
        let msg = out.handshakeMessage
        let authKey = try XCTUnwrap(out.authKey)

        // session_id 位於 offset 39..71；random 位於 6..38
        let arr = [UInt8](msg)
        XCTAssertEqual(arr[38], 0x20, "session_id 長度欄應為 32")
        let ciphertext = Data(arr[39..<71])
        let random = Data(arr[6..<38])

        // 伺服器重建 AAD：把 session_id 區歸零
        var aad = arr
        for i in 39..<71 { aad[i] = 0 }

        // 用 authKey + nonce(random[20:32]) + AAD 解密，應還原 16-byte 明文
        let nonce = Data(random.suffix(12))
        let opened = try AEADCipher.aes256gcm.open(ciphertext, key: SymmetricKey(data: authKey),
                                                   nonce: nonce, aad: Data(aad))
        XCTAssertEqual(opened.count, 16)
        // 明文 = [26,6,27,0] ‖ now(4,BE) ‖ shortId(補 0 到 8)
        let expected = Data([26, 6, 27, 0, 0x11, 0x22, 0x33, 0x44, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0])
        XCTAssertEqual(opened, expected)
    }

    func testAuthKeyMatchesServerSide() throws {
        // 客戶端與伺服器各自算 X25519 → HKDF，authKey 必須一致（模擬伺服器端）
        let serverPriv = Curve25519.KeyAgreement.PrivateKey()
        let cfg = RealityClientConfig(publicKey: serverPriv.publicKey.rawRepresentation, shortID: Data())
        var builder = ClientHelloBuilder(sni: "a.com", alpn: ["h2"], preset: .chrome)
        builder.reality = cfg; builder.now = 1
        let out = try builder.build()
        let clientAuthKey = try XCTUnwrap(out.authKey)

        // 伺服器：從 ClientHello 取 client X25519 公鑰（key_share），與自己的私鑰 ECDH
        // 這裡改用 keyExchanges 的公鑰模擬（等價於伺服器讀到的 keyshare）
        let clientX25519Pub = out.keyExchanges.first { $0.group == .x25519 }!.publicShare()
        let clientPubKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: clientX25519Pub)
        let serverShared = try serverPriv.sharedSecretFromKeyAgreement(with: clientPubKey).withUnsafeBytes { Data($0) }
        let random = Data([UInt8](out.handshakeMessage)[6..<38])
        let serverAuthKey = RealityCrypto.authKey(x25519Shared: serverShared, helloRandom: random)
        XCTAssertEqual(clientAuthKey, serverAuthKey)
    }

    // MARK: X.509 抽取 + 伺服器驗證

    func testServerCertVerification() {
        let authKey = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let pub = Data((0..<32).map { UInt8($0 &+ 1) })
        let goodSig = Data(HMAC<SHA512>.authenticationCode(for: pub, using: SymmetricKey(data: authKey)))
        XCTAssertEqual(goodSig.count, 64)

        let goodCert = makeEd25519Cert(pub: pub, sig: goodSig)
        XCTAssertEqual(X509Minimal.ed25519PublicKey(certDER: goodCert), pub)
        XCTAssertEqual(X509Minimal.signatureValue(certDER: goodCert), goodSig)
        XCTAssertTrue(RealityCrypto.verifyServer(authKey: authKey, leafCertDER: goodCert))

        // 簽章被竄改 → 驗證失敗（模擬 MITM / decoy 真站）
        var badSig = goodSig; badSig[0] ^= 0xff
        XCTAssertFalse(RealityCrypto.verifyServer(authKey: authKey, leafCertDER: makeEd25519Cert(pub: pub, sig: badSig)))
        // 錯的 authKey → 失敗
        XCTAssertFalse(RealityCrypto.verifyServer(authKey: Data(repeating: 9, count: 32), leafCertDER: goodCert))
    }

    // MARK: helpers

    private func dummyPbk() -> String {
        var b64 = Data(repeating: 7, count: 32).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        while b64.hasSuffix("=") { b64.removeLast() }
        return b64
    }

    /// 造一個 REALITY 風格的最小 Ed25519 憑證 DER：SEQ{ tbs(含 SPKI), sigAlg(ed25519), sigValue(BITSTRING) }。
    private func makeEd25519Cert(pub: Data, sig: Data) -> Data {
        precondition(pub.count == 32 && sig.count == 64)
        let oid: [UInt8] = [0x06, 0x03, 0x2b, 0x65, 0x70]           // 1.3.101.112 (Ed25519)
        let spki: [UInt8] = [0x30, 0x2a, 0x30, 0x05] + oid + [0x03, 0x21, 0x00] + [UInt8](pub)
        let tbs: [UInt8] = [0x30, UInt8(spki.count)] + spki        // tbs = SEQ { SPKI }
        let sigAlg: [UInt8] = [0x30, 0x05] + oid
        let sigVal: [UInt8] = [0x03, 0x41, 0x00] + [UInt8](sig)    // BIT STRING(65) = 0 unused + 64
        let content = tbs + sigAlg + sigVal
        return Data([0x30, UInt8(content.count)] + content)
    }
}
