import XCTest
@testable import ShadowSpaceKit

final class SystemProxyTests: XCTestCase {

    /// 代理伺服器主機要被加進繞過清單（否則原生引擎連往伺服器會被系統代理繞回 → 迴圈 → 沒網路）。
    func testBypassDomainsIncludesProxyServerAndDedups() {
        let list = SystemProxyManager.bypassDomains(["th.t2.lol", "th.t2.lol", "  ", "localhost"])
        XCTAssertTrue(list.contains("th.t2.lol"))          // 代理伺服器主機已列入繞過
        XCTAssertTrue(list.contains("127.0.0.1"))           // 預設仍在
        XCTAssertTrue(list.contains("192.168.0.0/16"))      // 私有網段預設仍在
        XCTAssertEqual(list.filter { $0 == "th.t2.lol" }.count, 1)   // 去重
        XCTAssertEqual(list.filter { $0 == "localhost" }.count, 1)   // 與預設重複者不重覆
        XCTAssertFalse(list.contains(""))                   // 空白被濾掉
        XCTAssertFalse(list.contains("  "))
    }

    func testBypassDomainsEmptyExtraKeepsDefaults() {
        let list = SystemProxyManager.bypassDomains()
        XCTAssertTrue(list.contains("127.0.0.1"))
        XCTAssertTrue(list.contains("localhost"))
        XCTAssertFalse(list.contains("th.t2.lol"))
    }
}
