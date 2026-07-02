import XCTest
import CryptoKit
@testable import ShadowCore

/// Shadowsocks-2022 離線測試。真機另需 SS-2022 伺服器。
/// 以「模擬伺服器」解碼客戶端請求、並編碼回應餵回客戶端，端到端驗證線格式與 salt 綁定。
final class SS2022Tests: XCTestCase {

    final class MemStream: ByteStream, @unchecked Sendable {
        var toRead = Data()
        var written = Data()
        func read() async throws -> Data { let d = toRead; toRead = Data(); return d }
        func write(_ data: Data) async throws { written.append(data) }
        func close() {}
    }

    private let context = "shadowsocks 2022 session subkey"
    private func key(_ psk: Data, _ salt: Data, _ n: Int) -> SSCipher {
        let sub = BLAKE3.deriveKey(context: context, keyMaterial: psk + salt, length: n)
        return SSCipher(method: .aes256gcm, subkey: SymmetricKey(data: sub))
    }

    func testMethodParsing() {
        XCTAssertEqual(SS2022Method("2022-blake3-aes-128-gcm")?.keySize, 16)
        XCTAssertEqual(SS2022Method("2022-blake3-aes-256-gcm")?.keySize, 32)
        XCTAssertEqual(SS2022Method("2022-blake3-chacha20-poly1305")?.keySize, 32)
        XCTAssertNil(SS2022Method("aes-256-gcm"))
    }

    func testOutboundRejectsBadPSK() {
        // 非 base64 或長度不符 → nil
        XCTAssertNil(SS2022Outbound(name: "x", host: "h", port: 1, method: "2022-blake3-aes-256-gcm", password: "not base64!!"))
        let short = Data(repeating: 1, count: 16).base64EncodedString()   // 16 bytes 給 aes-256（需 32）
        XCTAssertNil(SS2022Outbound(name: "x", host: "h", port: 1, method: "2022-blake3-aes-256-gcm", password: short))
        let ok = Data(repeating: 1, count: 32).base64EncodedString()
        XCTAssertNotNil(SS2022Outbound(name: "x", host: "h", port: 1, method: "2022-blake3-aes-256-gcm", password: ok))
    }

    func testRequestEncodeAndResponseDecodeRoundTrip() async throws {
        let psk = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let target = Target(host: "example.com", port: 443)
        let mem = MemStream()
        let client = SS2022Stream(under: mem, method: .aes256gcm, psk: psk, target: target)

        let payload = Data("GET / HTTP/1.1\r\n\r\n".utf8)
        try await client.write(payload)

        // ---- 模擬伺服器解碼請求 ----
        let req = [UInt8](mem.written)
        let salt = Data(req[0..<32])
        let cipher = key(psk, salt, 32)
        let nonce = SSNonce()
        var off = 32
        // 固定頭：type(1)+ts(8)+varLen(2) → 11 + 16
        let fixed = try cipher.open(Data(req[off..<off + 27]), nonce: nonce.next()); off += 27
        let fx = [UInt8](fixed)
        XCTAssertEqual(fx[0], 0x00, "type = client stream")
        let varLen = Int(fx[9]) << 8 | Int(fx[10])
        // 可變頭：addr + padLen(2) + padding
        let varH = try cipher.open(Data(req[off..<off + varLen + 16]), nonce: nonce.next()); off += varLen + 16
        let addr = SocksAddress.encode(target)
        XCTAssertEqual(Data([UInt8](varH).prefix(addr.count)), addr, "SOCKS 目標位址應與 target 相符")
        // payload chunk：len(2) + payload
        let encLen = try cipher.open(Data(req[off..<off + 2 + 16]), nonce: nonce.next()); off += 2 + 16
        let plen = Int([UInt8](encLen)[0]) << 8 | Int([UInt8](encLen)[1])
        let gotPayload = try cipher.open(Data(req[off..<off + plen + 16]), nonce: nonce.next())
        XCTAssertEqual(gotPayload, payload, "伺服器應解出原始載荷")

        // ---- 模擬伺服器編碼回應，餵回客戶端 read() ----
        let respSalt = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let respCipher = key(psk, respSalt, 32)
        let respNonce = SSNonce()
        let respPayload = Data("HTTP/1.1 200 OK\r\n\r\n".utf8)
        var respFixed = Data([0x01])                                  // type = server stream
        for i in (0..<8).reversed() { respFixed.append(UInt8((UInt64(1_700_000_000) >> (8 * i)) & 0xff)) }
        respFixed.append(salt)                                        // request salt（= 客戶端送出的 salt）
        respFixed.append(Data([UInt8((respPayload.count >> 8) & 0xff), UInt8(respPayload.count & 0xff)]))
        var resp = respSalt
        resp.append(try respCipher.seal(respFixed, nonce: respNonce.next()))     // nonce 0
        resp.append(try respCipher.seal(respPayload, nonce: respNonce.next()))   // nonce 1
        mem.toRead = resp

        let got = try await client.read()
        XCTAssertEqual(got, respPayload, "客戶端應解出回應載荷（且 request-salt 綁定通過）")
    }

    func testResponseSaltMismatchRejected() async throws {
        let psk = Data(repeating: 5, count: 32)
        let mem = MemStream()
        let client = SS2022Stream(under: mem, method: .aes256gcm, psk: psk, target: Target(host: "a.com", port: 80))
        try await client.write(Data("x".utf8))   // 設定 sentSalt

        // 伺服器用「錯誤的」 request salt（非客戶端送出的）→ 應被拒
        let respSalt = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let respCipher = key(psk, respSalt, 32)
        let respNonce = SSNonce()
        var respFixed = Data([0x01])
        for _ in 0..<8 { respFixed.append(0) }
        respFixed.append(Data(repeating: 0xAB, count: 32))   // 錯誤的 request salt
        respFixed.append(Data([0x00, 0x01]))
        var resp = respSalt
        resp.append(try respCipher.seal(respFixed, nonce: respNonce.next()))
        mem.toRead = resp

        do {
            _ = try await client.read()
            XCTFail("request-salt 不符應拋錯")
        } catch { /* 預期 */ }
    }
}
