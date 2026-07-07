import XCTest
@testable import ShadowSpaceKit

final class ImportServiceTests: XCTestCase {

    private func classify(_ s: String) -> ImportService.URLImport {
        ImportService.classifyURL(URL(string: s)!)
    }

    func testNonShadowspaceSchemeIsIgnoredSilently() {
        XCTAssertEqual(classify("https://example.com/sub"), .notOurs)
        XCTAssertEqual(classify("ss://abc@1.2.3.4:8388"), .notOurs)
    }

    func testQueryURLPayload() {
        XCTAssertEqual(
            classify("shadowspace://import?url=https://airport.example.com/sub"),
            .payload("https://airport.example.com/sub"))
    }

    func testQueryTextPayload() {
        XCTAssertEqual(
            classify("shadowspace://import?text=trojan://pw@a.com:443%23hk"),
            .payload("trojan://pw@a.com:443#hk"))
    }

    func testPathFallbackPayloadIsPercentDecoded() {
        // shadowspace://import/<百分比編碼內容>
        let encoded = "trojan://pw@a.com:443".addingPercentEncoding(
            withAllowedCharacters: .alphanumerics)!
        let result = classify("shadowspace://import/\(encoded)")
        XCTAssertEqual(result, .payload("trojan://pw@a.com:443"))
    }

    func testEmptyOurSchemeIsUnrecognized() {
        XCTAssertEqual(classify("shadowspace://import"), .unrecognized)
        XCTAssertEqual(classify("shadowspace://import/"), .unrecognized)
    }
}
