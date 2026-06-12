import XCTest
@testable import ShadowCore

final class DNSMessageTests: XCTestCase {
    func testFirstQuestionName() {
        var query = Data([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00])
        query.append(3); query.append(Data("www".utf8))
        query.append(7); query.append(Data("example".utf8))
        query.append(3); query.append(Data("com".utf8))
        query.append(0)
        query.append(contentsOf: [0x00, 0x01, 0x00, 0x01])

        XCTAssertEqual(DNSMessage.firstQuestionName(in: query), "www.example.com")
    }

    func testMalformedQuestionReturnsNil() {
        let query = Data([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00])
        XCTAssertNil(DNSMessage.firstQuestionName(in: query))
    }
}
