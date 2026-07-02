import XCTest
import CryptoKit
@testable import ShadowCore

/// ClientHello 序列化與 record AEAD 的離線回歸測試（真機握手另在 shadow-demo --tls13 驗證）。
final class ClientHelloTests: XCTestCase {

    /// 解析 ClientHello 並回傳擴充型別清單，順便檢查所有長度自洽。
    private func parseExtensionTypes(_ msg: Data) throws -> [Int] {
        var r = ByteReader(msg)
        XCTAssertEqual(try r.u8(), 0x01, "handshake type = ClientHello")
        _ = try r.u24()                    // body length
        _ = try r.u16()                    // legacy_version
        _ = try r.take(32)                 // random
        _ = try r.u8Vec()                  // legacy_session_id
        _ = try r.u16Vec()                 // cipher_suites
        _ = try r.u8Vec()                  // compression_methods
        var er = ByteReader(try r.u16Vec())
        var types: [Int] = []
        while er.remaining >= 4 {
            let t = try er.u16()
            _ = try er.u16Vec()
            types.append(t)
        }
        XCTAssertEqual(er.remaining, 0, "擴充區塊長度自洽")
        return types
    }

    func testClientHelloWellFormedX25519() throws {
        let out = try ClientHelloBuilder(sni: "example.com", alpn: ["h2", "http/1.1"], preset: .chromeX25519).build()
        let types = try parseExtensionTypes(out.handshakeMessage)
        // 關鍵擴充齊備
        for required in [0x0000, 0x000a, 0x000d, 0x0033, 0x002b, 0x0010] {
            XCTAssertTrue(types.contains(required), "缺擴充 0x\(String(required, radix: 16))")
        }
        // 無重複擴充型別（曾因首尾 GREASE 同值 → decode_error 的回歸）
        XCTAssertEqual(types.count, Set(types).count, "擴充型別不可重複：\(types.map { String($0, radix: 16) })")
        // 至少兩個相異 GREASE 擴充（0x?a?a）
        let greases = types.filter { ($0 & 0x0f0f) == 0x0a0a && (($0 >> 8) == ($0 & 0xff)) }
        XCTAssertGreaterThanOrEqual(Set(greases).count, 2, "應有兩個相異 GREASE 擴充")
    }

    func testChromeX25519HasNoHybridGroup() throws {
        // 純 X25519 preset 不應宣告 0x11ec（避免宣告卻無對應 share）
        let out = try ClientHelloBuilder(sni: "a.com", alpn: ["http/1.1"], preset: .chromeX25519).build()
        XCTAssertEqual(out.keyExchanges.map { $0.group }, [.x25519])
    }

    func testAEADRoundTripAllCiphers() throws {
        for cipher in [AEADCipher.aes128gcm, .aes256gcm, .chacha20] {
            let key = SymmetricKey(size: cipher == .aes128gcm ? .bits128 : .bits256)
            let keyData = key.withUnsafeBytes { Data($0) }
            let iv = Data((0..<12).map { UInt8($0) })
            let plaintext = Data("the quick brown fox — 抗封鎖".utf8)
            let aad = Data([0x17, 0x03, 0x03, 0x00, 0x20])
            let nonce = TLS13KeySchedule.perRecordNonce(staticIV: iv, sequence: 3)
            let sealed = try cipher.seal(plaintext, key: SymmetricKey(data: keyData), nonce: nonce, aad: aad)
            XCTAssertEqual(sealed.count, plaintext.count + 16)
            let opened = try cipher.open(sealed, key: SymmetricKey(data: keyData), nonce: nonce, aad: aad)
            XCTAssertEqual(opened, plaintext, "\(cipher) round-trip")
            // 錯誤 AAD 應失敗
            XCTAssertThrowsError(try cipher.open(sealed, key: SymmetricKey(data: keyData), nonce: nonce, aad: Data([0x17, 0x03, 0x03, 0x00, 0x21])))
        }
    }
}
