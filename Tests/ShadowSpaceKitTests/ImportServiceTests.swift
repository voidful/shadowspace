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

    func testReimportVisionUpgradesMatchingManualNode() throws {
        let uri = "vless://9a4b2c33-1111-2222-3333-444455556666@example.com:443/?security=reality&pbk=PUBKEY123&sid=ab12"
        var old = try XCTUnwrap(URIParser.parse(uri + "#Example"))
        old.dialerNodeID = UUID()
        let vision = try XCTUnwrap(URIParser.parse(uri + "&flow=xtls-rprx-vision#Example"))

        let result = ImportService.mergeNodes([vision, vision], into: [old])

        XCTAssertEqual(result.added, 0)
        XCTAssertEqual(result.upgraded, [old.id])
        XCTAssertEqual(result.nodes.count, 1)
        XCTAssertEqual(result.nodes.first?.id, old.id)
        XCTAssertEqual(result.nodes.first?.dialerNodeID, old.dialerNodeID)
        XCTAssertEqual(result.nodes.first?.flow, "xtls-rprx-vision")
    }

    func testReimportVisionKeepsSubscriptionAndDistinctManualNodes() throws {
        var old = try XCTUnwrap(URIParser.parse("vless://9a4b2c33-1111-2222-3333-444455556666@example.com:443#Example"))
        var vision = old
        vision.id = UUID()
        vision.flow = "xtls-rprx-vision"
        var other = old
        other.id = UUID()
        other.uuid = "9a4b2c33-1111-2222-3333-444455557777"
        old.subscriptionID = UUID()

        let result = ImportService.mergeNodes([vision], into: [old, other])

        XCTAssertEqual(result.added, 1)
        XCTAssertTrue(result.upgraded.isEmpty)
        XCTAssertEqual(result.nodes, [old, other, vision])
    }
}
