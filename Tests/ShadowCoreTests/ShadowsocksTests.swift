import XCTest
import CryptoKit
@testable import ShadowCore

final class ShadowsocksTests: XCTestCase {

    // EVP_BytesToKey：master = MD5(pw) ‖ MD5(MD5(pw)‖pw) … 截斷
    func testMasterKeyVector() {
        let key = ShadowsocksCrypto.masterKey(password: "test", keyLength: 32)
        let m1 = Data(Insecure.MD5.hash(data: Data("test".utf8)))
        let m2 = Data(Insecure.MD5.hash(data: m1 + Data("test".utf8)))
        XCTAssertEqual(key, (m1 + m2).prefix(32))
        XCTAssertEqual(ShadowsocksCrypto.masterKey(password: "x", keyLength: 16).count, 16)
    }

    private func roundTrip(_ method: SSMethod) throws {
        let master = ShadowsocksCrypto.masterKey(password: "hunter2", keyLength: method.keyLength)
        let salt = ShadowsocksCrypto.randomSalt(method.saltLength)
        let subkey = ShadowsocksCrypto.subkey(masterKey: master, salt: salt, keyLength: method.keyLength)
        let enc = SSCipher(method: method, subkey: subkey)
        let dec = SSCipher(method: method, subkey: subkey)
        let encN = SSNonce(), decN = SSNonce()

        // 連送三個分塊，nonce 計數器需同步遞增
        for payload in [Data("你好 shadowsocks".utf8), Data(repeating: 0xAB, count: 4096), Data("bye".utf8)] {
            let lenData = Data([UInt8(payload.count >> 8), UInt8(payload.count & 0xff)])
            let encLen = try enc.seal(lenData, nonce: encN.next())
            let encPayload = try enc.seal(payload, nonce: encN.next())
            let gotLen = try dec.open(encLen, nonce: decN.next())
            XCTAssertEqual(Int(gotLen[0]) << 8 | Int(gotLen[1]), payload.count)
            let gotPayload = try dec.open(encPayload, nonce: decN.next())
            XCTAssertEqual(gotPayload, payload)
        }
    }

    func testAES256RoundTrip() throws { try roundTrip(SSMethod("aes-256-gcm")!) }
    func testAES128RoundTrip() throws { try roundTrip(SSMethod("aes-128-gcm")!) }
    func testChaCha20RoundTrip() throws { try roundTrip(SSMethod("chacha20-ietf-poly1305")!) }

    func testMethodParsing() {
        XCTAssertEqual(SSMethod("aes-128-gcm")?.keyLength, 16)
        XCTAssertEqual(SSMethod("aes-256-gcm")?.keyLength, 32)
        XCTAssertEqual(SSMethod("chacha20-poly1305")?.keyLength, 32)
        XCTAssertNil(SSMethod("rc4-md5"))
    }

    func testTamperDetectionFails() throws {
        let method = SSMethod("aes-256-gcm")!
        let subkey = ShadowsocksCrypto.subkey(
            masterKey: ShadowsocksCrypto.masterKey(password: "p", keyLength: 32),
            salt: ShadowsocksCrypto.randomSalt(32), keyLength: 32)
        let cipher = SSCipher(method: method, subkey: subkey)
        let nonce = Data(repeating: 0, count: 12)
        var sealed = try cipher.seal(Data("secret".utf8), nonce: nonce)
        sealed[0] ^= 0xFF   // 竄改
        do {
            _ = try cipher.open(sealed, nonce: nonce)
            XCTFail("竄改後仍應解開失敗")
        } catch { /* 預期丟出驗證失敗 */ }
    }

    func testWrongKeyFails() throws {
        let method = SSMethod("chacha20-ietf-poly1305")!
        let salt = ShadowsocksCrypto.randomSalt(32)
        let good = SSCipher(method: method, subkey: ShadowsocksCrypto.subkey(
            masterKey: ShadowsocksCrypto.masterKey(password: "right", keyLength: 32), salt: salt, keyLength: 32))
        let bad = SSCipher(method: method, subkey: ShadowsocksCrypto.subkey(
            masterKey: ShadowsocksCrypto.masterKey(password: "wrong", keyLength: 32), salt: salt, keyLength: 32))
        let nonce = Data(repeating: 0, count: 12)
        let sealed = try good.seal(Data("hi".utf8), nonce: nonce)
        do {
            _ = try bad.open(sealed, nonce: nonce)
            XCTFail("錯誤金鑰仍應解開失敗")
        } catch { /* 預期 */ }
    }
}
