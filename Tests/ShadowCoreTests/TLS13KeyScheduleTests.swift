import XCTest
@testable import ShadowCore

/// RFC 8448 §3「Simple 1-RTT Handshake」官方測試向量的逐 byte 已知答案驗證。
/// 該範例用 TLS_AES_128_GCM_SHA256 → H = SHA-256、HashLen = 32、keyLen = 16。
/// 這是原生 TLS 1.3 客戶端唯一有可靠離線 oracle 的部分，也是一切握手金鑰的地基。
final class TLS13KeyScheduleTests: XCTestCase {

    private func hex(_ s: String) -> Data {
        Data(s.split(whereSeparator: { $0 == " " || $0 == "\n" })
            .map { UInt8($0, radix: 16)! })
    }

    private let H = TLS13Hash.sha256

    // RFC 8448 §3 向量
    private let ecdhe = "8b d4 05 4f b5 5b 9d 63 fd fb ac f9 f0 4b 9f 0d 35 e6 d6 3f 53 75 63 ef d4 62 72 90 0f 89 49 2d"
    private let hashCHSH = "86 0c 06 ed c0 78 58 ee 8e 78 f0 e7 42 8c 58 ed d6 b4 3f 2c a3 e6 e9 5f 02 ed 06 3c f0 e1 ca d8"
    private let hashCHSF = "96 08 10 2a 0f 1c cc 6d b6 25 0b 7b 7e 41 7b 1a 00 0e aa da 3d aa e4 77 7a 76 86 c9 ff 83 df 13"

    func testEmptyHash() {
        // SHA-256("") — Derive-Secret 的 "derived" 步驟會用到
        XCTAssertEqual(H.hash(Data()),
                       hex("e3 b0 c4 42 98 fc 1c 14 9a fb f4 c8 99 6f b9 24 27 ae 41 e4 64 9b 93 4c a4 95 99 1b 78 52 b8 55"))
    }

    func testEarlySecretExtract() {
        let early = TLS13KeySchedule.extract(H, salt: TLS13KeySchedule.zeros(H), ikm: TLS13KeySchedule.zeros(H))
        XCTAssertEqual(early,
                       hex("33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a"))
    }

    func testDerivedForHandshake() {
        let early = hex("33 ad 0a 1c 60 7e c0 3b 09 e6 cd 98 93 68 0c e2 10 ad f3 00 aa 1f 26 60 e1 b2 2e 10 f1 70 f9 2a")
        let derived = TLS13KeySchedule.deriveSecret(H, secret: early, label: "derived", transcriptHash: H.hash(Data()))
        XCTAssertEqual(derived,
                       hex("6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba"))
    }

    func testHandshakeSecretExtract() {
        let derived = hex("6f 26 15 a1 08 c7 02 c5 67 8f 54 fc 9d ba b6 97 16 c0 76 18 9c 48 25 0c eb ea c3 57 6c 36 11 ba")
        let hs = TLS13KeySchedule.extract(H, salt: derived, ikm: hex(ecdhe))
        XCTAssertEqual(hs,
                       hex("1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac"))
    }

    func testClientAndServerHandshakeTrafficSecrets() {
        let hs = hex("1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac")
        let cHS = TLS13KeySchedule.deriveSecret(H, secret: hs, label: "c hs traffic", transcriptHash: hex(hashCHSH))
        let sHS = TLS13KeySchedule.deriveSecret(H, secret: hs, label: "s hs traffic", transcriptHash: hex(hashCHSH))
        XCTAssertEqual(cHS, hex("b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21"))
        XCTAssertEqual(sHS, hex("b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38"))
    }

    func testMasterSecretExtract() {
        let hs = hex("1d c8 26 e9 36 06 aa 6f dc 0a ad c1 2f 74 1b 01 04 6a a6 b9 9f 69 1e d2 21 a9 f0 ca 04 3f be ac")
        let derivedHS = TLS13KeySchedule.deriveSecret(H, secret: hs, label: "derived", transcriptHash: H.hash(Data()))
        XCTAssertEqual(derivedHS, hex("43 de 77 e0 c7 77 13 85 9a 94 4d b9 db 25 90 b5 31 90 a6 5b 3e e2 e4 f1 2d d7 a0 bb 7c e2 54 b4"))
        let master = TLS13KeySchedule.extract(H, salt: derivedHS, ikm: TLS13KeySchedule.zeros(H))
        XCTAssertEqual(master, hex("18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a 47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19"))
    }

    func testHandshakeTrafficKeyIV() {
        // server 寫入（= 客戶端讀取）：由 s hs traffic 推導
        let sHS = hex("b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38")
        let sk = TLS13KeySchedule.trafficKeyIV(H, secret: sHS, keyLength: 16)
        XCTAssertEqual(sk.key, hex("3f ce 51 60 09 c2 17 27 d0 f2 e4 e8 6e e4 03 bc"))
        XCTAssertEqual(sk.iv,  hex("5d 31 3e b2 67 12 76 ee 13 00 0b 30"))
        // client 寫入（= server 讀取）：由 c hs traffic 推導
        let cHS = hex("b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21")
        let ck = TLS13KeySchedule.trafficKeyIV(H, secret: cHS, keyLength: 16)
        XCTAssertEqual(ck.key, hex("db fa a6 93 d1 76 2c 5b 66 6a f5 d9 50 25 8d 01"))
        XCTAssertEqual(ck.iv,  hex("5b d3 c7 1b 83 6e 0b 76 bb 73 26 5f"))
    }

    func testApplicationTrafficSecretsAndKeys() {
        let master = hex("18 df 06 84 3d 13 a0 8b f2 a4 49 84 4c 5f 8a 47 80 01 bc 4d 4c 62 79 84 d5 a4 1d a8 d0 40 29 19")
        let cAP = TLS13KeySchedule.deriveSecret(H, secret: master, label: "c ap traffic", transcriptHash: hex(hashCHSF))
        let sAP = TLS13KeySchedule.deriveSecret(H, secret: master, label: "s ap traffic", transcriptHash: hex(hashCHSF))
        XCTAssertEqual(cAP, hex("9e 40 64 6c e7 9a 7f 9d c0 5a f8 88 9b ce 65 52 87 5a fa 0b 06 df 00 87 f7 92 eb b7 c1 75 04 a5"))
        XCTAssertEqual(sAP, hex("a1 1a f9 f0 55 31 f8 56 ad 47 11 6b 45 a9 50 32 82 04 b4 f4 4b fb 6b 3a 4b 4f 1f 3f cb 63 16 43"))

        let sk = TLS13KeySchedule.trafficKeyIV(H, secret: sAP, keyLength: 16)
        XCTAssertEqual(sk.key, hex("9f 02 28 3b 6c 9c 07 ef c2 6b b9 f2 ac 92 e3 56"))
        XCTAssertEqual(sk.iv,  hex("cf 78 2b 88 dd 83 54 9a ad f1 e9 84"))
        let ck = TLS13KeySchedule.trafficKeyIV(H, secret: cAP, keyLength: 16)
        XCTAssertEqual(ck.key, hex("17 42 2d da 59 6e d5 d9 ac d8 90 e3 c6 3f 50 51"))
        XCTAssertEqual(ck.iv,  hex("5b 78 92 3d ee 08 57 90 33 e5 23 d9"))
    }

    func testFinishedKeys() {
        let sHS = hex("b6 7b 7d 69 0c c1 6c 4e 75 e5 42 13 cb 2d 37 b4 e9 c9 12 bc de d9 10 5d 42 be fd 59 d3 91 ad 38")
        XCTAssertEqual(TLS13KeySchedule.finishedKey(H, secret: sHS),
                       hex("00 8d 3b 66 f8 16 ea 55 9f 96 b5 37 e8 85 c3 1f c0 68 bf 49 2c 65 2f 01 f2 88 a1 d8 cd c1 9f c8"))
        let cHS = hex("b3 ed db 12 6e 06 7f 35 a7 80 b3 ab f4 5e 2d 8f 3b 1a 95 07 38 f5 2e 96 00 74 6a 0e 27 a5 5a 21")
        XCTAssertEqual(TLS13KeySchedule.finishedKey(H, secret: cHS),
                       hex("b8 0a d0 10 15 fb 2f 0b d6 5f f7 d4 da 5d 6b f8 3f 84 82 1d 1f 87 fd c7 d3 c7 5b 5a 7b 42 d9 c4"))
    }

    func testPerRecordNonce() {
        let iv = hex("5d 31 3e b2 67 12 76 ee 13 00 0b 30")
        // seq = 0 → nonce == static iv
        XCTAssertEqual(TLS13KeySchedule.perRecordNonce(staticIV: iv, sequence: 0), iv)
        // seq = 1 → 只有最後一 byte XOR 1
        XCTAssertEqual(TLS13KeySchedule.perRecordNonce(staticIV: iv, sequence: 1),
                       hex("5d 31 3e b2 67 12 76 ee 13 00 0b 31"))
        // seq = 0x0102 → 最後兩 byte XOR
        XCTAssertEqual(TLS13KeySchedule.perRecordNonce(staticIV: iv, sequence: 0x0102),
                       hex("5d 31 3e b2 67 12 76 ee 13 00 0a 32"))
    }
}
