import XCTest
@testable import ShadowSpaceKit

final class SubscriptionManagerTests: XCTestCase {

    /// 純函式判型：一般分享連結內容走 URIParser 後備路徑。
    func testParseContentFallsBackToShareLinks() {
        let userinfo = Data("aes-256-gcm:pw".utf8).base64EncodedString()
        let text = "ss://\(userinfo)@1.2.3.4:8388#a\ntrojan://pw@5.6.7.8:443#b"
        let nodes = SubscriptionManager.parseContent(text, data: Data(text.utf8))
        XCTAssertEqual(nodes.count, 2)
        XCTAssertEqual(nodes.first?.proto, .shadowsocks)
        XCTAssertEqual(nodes.last?.proto, .trojan)
    }

    /// 整段 base64 包裝的分享連結（機場常見）也能解。
    func testParseContentDecodesBase64Wrapped() {
        let plain = "trojan://pw@a.example.com:443#hk"
        let wrapped = Data(plain.utf8).base64EncodedString()
        let nodes = SubscriptionManager.parseContent(wrapped, data: Data(wrapped.utf8))
        XCTAssertEqual(nodes.count, 1)
        XCTAssertEqual(nodes.first?.server, "a.example.com")
    }

    // MARK: - content-disposition 檔名解析

    func testFilenamePrefersRFC5987PercentDecoded() {
        // filename*=UTF-8''香港機場（百分比編碼）
        let disposition = "attachment; filename*=UTF-8''%E9%A6%99%E6%B8%AF; filename=\"fallback\""
        XCTAssertEqual(SubscriptionManager.filename(fromContentDisposition: disposition), "香港")
    }

    func testFilenamePlainQuotedStripped() {
        XCTAssertEqual(
            SubscriptionManager.filename(fromContentDisposition: "attachment; filename=\"my sub\""),
            "my sub")
    }

    func testFilenameAbsentOrEmptyReturnsNil() {
        XCTAssertNil(SubscriptionManager.filename(fromContentDisposition: "attachment"))
        XCTAssertNil(SubscriptionManager.filename(fromContentDisposition: "attachment; filename=\"\""))
    }

    func testFilenameMalformedPercentEncodingFallsBackToNil() {
        // 非法 % 序列解碼失敗時回 nil（呼叫端落回主機名），不可回傳未解碼原字串。
        XCTAssertNil(SubscriptionManager.filename(fromContentDisposition: "attachment; filename*=UTF-8''%ZZ"))
    }
}
