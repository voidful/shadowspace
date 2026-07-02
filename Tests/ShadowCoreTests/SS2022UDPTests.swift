import XCTest
import CryptoKit
import CommonCrypto
@testable import ShadowCore

/// SS-2022 UDP 封包編解碼離線測試（SIP022 §3.2）。真機另需 SS-2022 伺服器。
final class SS2022UDPTests: XCTestCase {

    private let context = "shadowsocks 2022 session subkey"

    private func aesECB(_ key: Data, _ block: Data, encrypt: Bool) -> Data {
        var out = [UInt8](repeating: 0, count: 16); var moved = 0
        _ = key.withUnsafeBytes { kp in block.withUnsafeBytes { bp in
            CCCrypt(CCOperation(encrypt ? kCCEncrypt : kCCDecrypt), CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionECBMode), kp.baseAddress, key.count, nil,
                    bp.baseAddress, 16, &out, 16, &moved)
        }}
        return Data(out)
    }
    private func sessionCipher(_ psk: Data, _ sid: Data) -> SSCipher {
        let sub = BLAKE3.deriveKey(context: context, keyMaterial: psk + sid, length: psk.count)
        return SSCipher(method: psk.count == 16 ? .aes128gcm : .aes256gcm, subkey: SymmetricKey(data: sub))
    }

    func testRejectsChachaAndBadPSK() {
        XCTAssertNil(SS2022UDPCodec(method: "2022-blake3-chacha20-poly1305",
                                    password: Data(repeating: 1, count: 32).base64EncodedString()))
        XCTAssertNil(SS2022UDPCodec(method: "2022-blake3-aes-256-gcm", password: "not-b64!!"))
        XCTAssertNotNil(SS2022UDPCodec(method: "2022-blake3-aes-256-gcm",
                                       password: Data(repeating: 1, count: 32).base64EncodedString()))
    }

    func testEncodeDecodeRoundTrip() throws {
        let pskData = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let psk = pskData.base64EncodedString()
        let codec = try XCTUnwrap(SS2022UDPCodec(method: "2022-blake3-aes-256-gcm", password: psk))
        let target = Target(host: "8.8.8.8", port: 53)
        let payload = Data("dns-query-bytes".utf8)

        // ---- 編碼：模擬伺服器解碼客戶端封包 ----
        let pkt = [UInt8](try codec.encode(payload: payload, to: target))
        let sep = aesECB(pskData, Data(pkt[0..<16]), encrypt: false)
        let cSid = Data(sep[0..<8])
        XCTAssertEqual(cSid, codec.sessionID)
        let body = try sessionCipher(pskData, cSid).open(Data(pkt[16...]), nonce: Data(sep[4..<16]))
        let bb = [UInt8](body)
        XCTAssertEqual(bb[0], 0x00, "type = client")
        let padLen = Int(bb[9]) << 8 | Int(bb[10])
        let (gotTarget, next) = try XCTUnwrap(SocksAddress.parse(bb, at: 11 + padLen))
        XCTAssertEqual(gotTarget.host, "8.8.8.8"); XCTAssertEqual(gotTarget.port, 53)
        XCTAssertEqual(Data(bb[next...]), payload)

        // ---- 解碼：模擬伺服器編碼回應（type1 + clientSessionID）餵回 codec ----
        let source = Target(host: "8.8.8.8", port: 53)
        let respPayload = Data("dns-answer".utf8)
        let serverSid = Data((0..<8).map { _ in UInt8.random(in: 0...255) })
        let serverSep = serverSid + Data([0, 0, 0, 0, 0, 0, 0, 5])   // packetID 5
        let encSep = aesECB(pskData, serverSep, encrypt: true)
        var respBody = Data([0x01])                                   // type = server
        for _ in 0..<8 { respBody.append(0) }                          // timestamp（測試不驗）
        respBody.append(codec.sessionID)                               // client session ID
        respBody.append(Data([0x00, 0x00]))                            // padding length 0
        respBody.append(SocksAddress.encode(source))
        respBody.append(respPayload)
        let encBody = try sessionCipher(pskData, serverSid).seal(respBody, nonce: Data(serverSep[4..<16]))
        let resp = encSep + encBody

        let (from, got) = try codec.decode(resp)
        XCTAssertEqual(from.host, "8.8.8.8"); XCTAssertEqual(from.port, 53)
        XCTAssertEqual(got, respPayload)
    }

    func testPacketIDIncrements() throws {
        let psk = Data(repeating: 9, count: 16).base64EncodedString()
        let codec = try XCTUnwrap(SS2022UDPCodec(method: "2022-blake3-aes-128-gcm", password: psk))
        let p1 = [UInt8](try codec.encode(payload: Data([1]), to: Target(host: "1.1.1.1", port: 80)))
        let p2 = [UInt8](try codec.encode(payload: Data([1]), to: Target(host: "1.1.1.1", port: 80)))
        // 分離頭（前 16B 加密）應不同，因 packetID 遞增
        XCTAssertNotEqual(Data(p1[0..<16]), Data(p2[0..<16]))
    }
}
