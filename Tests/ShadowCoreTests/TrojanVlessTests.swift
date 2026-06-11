import XCTest
@testable import ShadowCore

/// 測試用假串流：read 依序吐出預設分塊，write 累積。
final class MockStream: ByteStream, @unchecked Sendable {
    private var queue: [Data]
    private(set) var written = Data()
    init(_ chunks: [Data]) { queue = chunks }
    func read() async throws -> Data { queue.isEmpty ? Data() : queue.removeFirst() }
    func write(_ data: Data) async throws { written.append(data) }
    func close() {}
}

final class TrojanTests: XCTestCase {

    func testSHA224KnownVector() {
        // SHA-224("") = d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f
        let hex = String(decoding: SHA224.hexLower(""), as: UTF8.self)
        XCTAssertEqual(hex, "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")
        XCTAssertEqual(SHA224.hexLower("anything").count, 56)
    }

    func testTrojanHeaderStructure() {
        let target = Target(host: "example.com", port: 443)
        let header = TrojanStream.buildHeader(password: "pw", target: target)
        let pwHex = SHA224.hexLower("pw")
        XCTAssertEqual(Data(header.prefix(56)), pwHex)         // 密碼雜湊
        let after = Array(header.dropFirst(56))
        XCTAssertEqual(Array(after.prefix(2)), [0x0D, 0x0A])    // CRLF
        XCTAssertEqual(after[2], 0x01)                          // CONNECT
        let addr = SocksAddress.encode(target)
        XCTAssertEqual(Array(after[3..<(3 + addr.count)]), Array(addr))
        XCTAssertEqual(Array(after.suffix(2)), [0x0D, 0x0A])    // 結尾 CRLF
    }
}

final class VlessTests: XCTestCase {

    func testParseUUID() {
        let uuid = VlessStream.parseUUID("23ad6b10-8d1a-40f7-8ad0-e3e35cd38297")
        XCTAssertEqual(uuid?.count, 16)
        XCTAssertEqual(uuid?.first, 0x23)
        XCTAssertEqual(uuid?.last, 0x97)
        XCTAssertNil(VlessStream.parseUUID("not-a-uuid"))
    }

    func testBuildRequestStructure() {
        let uuid = VlessStream.parseUUID("23ad6b10-8d1a-40f7-8ad0-e3e35cd38297")!
        let req = Array(VlessStream.buildRequest(uuid: uuid, target: Target(host: "example.com", port: 443)))
        XCTAssertEqual(req[0], 0x00)                       // version
        XCTAssertEqual(Array(req[1..<17]), Array(uuid))    // uuid
        XCTAssertEqual(req[17], 0x00)                      // addon length
        XCTAssertEqual(req[18], 0x01)                      // command tcp
        XCTAssertEqual(req[19], 0x01); XCTAssertEqual(req[20], 0xBB)  // port 443
        XCTAssertEqual(req[21], 0x02)                      // atyp = domain
        XCTAssertEqual(req[22], 11)                        // len("example.com")
        XCTAssertEqual(Array(req[23..<34]), Array("example.com".utf8))
    }

    func testWritePrependsHeader() async throws {
        let uuid = VlessStream.parseUUID("23ad6b10-8d1a-40f7-8ad0-e3e35cd38297")!
        let mock = MockStream([])
        let vless = VlessStream(under: mock, uuid: uuid, target: Target(host: "1.2.3.4", port: 80))
        try await vless.write(Data("GET /".utf8))
        let expected = VlessStream.buildRequest(uuid: uuid, target: Target(host: "1.2.3.4", port: 80)) + Data("GET /".utf8)
        XCTAssertEqual(mock.written, expected)
    }

    func testReadParsesResponseHeader_singleChunk() async throws {
        let uuid = VlessStream.parseUUID("23ad6b10-8d1a-40f7-8ad0-e3e35cd38297")!
        // 回應 = version(0) addonLen(0) + 載荷
        let mock = MockStream([Data([0x00, 0x00]) + Data("payload".utf8)])
        let vless = VlessStream(under: mock, uuid: uuid, target: Target(host: "1.2.3.4", port: 80))
        let got = try await vless.read()
        XCTAssertEqual(got, Data("payload".utf8))
    }

    func testReadParsesResponseHeader_splitChunks() async throws {
        let uuid = VlessStream.parseUUID("23ad6b10-8d1a-40f7-8ad0-e3e35cd38297")!
        // 標頭與載荷跨多個分塊送達，含 1 位元組 addon
        let mock = MockStream([Data([0x00]), Data([0x01, 0xAA]), Data("hello".utf8)])
        let vless = VlessStream(under: mock, uuid: uuid, target: Target(host: "1.2.3.4", port: 80))
        let got = try await vless.read()
        XCTAssertEqual(got, Data("hello".utf8))
    }
}
