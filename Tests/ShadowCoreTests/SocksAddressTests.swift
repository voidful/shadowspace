import XCTest
@testable import ShadowCore

final class SocksAddressTests: XCTestCase {

    func testEncodeIPv4() {
        let data = SocksAddress.encode(Target(host: "1.2.3.4", port: 443))
        XCTAssertEqual(Array(data), [0x01, 1, 2, 3, 4, 0x01, 0xBB])
    }

    func testEncodeDomain() {
        let data = SocksAddress.encode(Target(host: "example.com", port: 80))
        var expected: [UInt8] = [0x03, 11]
        expected.append(contentsOf: Array("example.com".utf8))
        expected.append(contentsOf: [0x00, 0x50])
        XCTAssertEqual(Array(data), expected)
    }

    func testEncodeIPv6() {
        let data = SocksAddress.encode(Target(host: "2001:db8::1", port: 8388))
        XCTAssertEqual(data.first, 0x04)
        XCTAssertEqual(data.count, 1 + 16 + 2)
        XCTAssertEqual(Array(data.suffix(2)), [0x20, 0xC4]) // 8388
    }
}
