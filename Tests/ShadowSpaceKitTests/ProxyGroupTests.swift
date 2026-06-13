import XCTest
@testable import ShadowSpaceKit

final class ProxyGroupTests: XCTestCase {

    private func node(_ name: String) -> ProxyNode {
        var n = ProxyNode(name: name, proto: .trojan, server: "\(name).example.com", port: 443)
        n.password = "pw"; n.tls = true
        return n
    }

    func testGroupsGenerateOutbounds() {
        let a = node("HK"), b = node("JP")
        let sel = ProxyGroup(name: "手選群", type: .select, memberNodeIDs: [a.id, b.id])
        let auto = ProxyGroup(name: "自動群", type: .urltest, memberNodeIDs: [a.id, b.id])

        let result = SingBoxConfigBuilder.build(
            nodes: [a, b], selectedID: auto.id, settings: AppSettings(),
            mode: .rule, groups: [sel, auto])
        let outbounds = result.json["outbounds"] as? [[String: Any]] ?? []

        // 兩個群組各自成為 outbound，型別正確
        let selOut = outbounds.first { ($0["tag"] as? String) == "手選群" }
        XCTAssertEqual(selOut?["type"] as? String, "selector")
        XCTAssertEqual((selOut?["outbounds"] as? [String])?.count, 2)

        let autoOut = outbounds.first { ($0["tag"] as? String) == "自動群" }
        XCTAssertEqual(autoOut?["type"] as? String, "urltest")
        XCTAssertNotNil(autoOut?["url"])

        // PROXY 主 selector 含群組 tag，且 default 指向選定群組
        let proxy = outbounds.first { ($0["tag"] as? String) == "PROXY" }
        let members = proxy?["outbounds"] as? [String] ?? []
        XCTAssertTrue(members.contains("手選群"))
        XCTAssertTrue(members.contains("自動群"))
        XCTAssertEqual(proxy?["default"] as? String, "自動群")

        XCTAssertEqual(result.tagByGroupID[auto.id], "自動群")
    }

    func testEmptyGroupSkipped() {
        let a = node("HK")
        let empty = ProxyGroup(name: "空群", type: .select, memberNodeIDs: [])
        let result = SingBoxConfigBuilder.build(
            nodes: [a], selectedID: a.id, settings: AppSettings(), mode: .rule, groups: [empty])
        let outbounds = result.json["outbounds"] as? [[String: Any]] ?? []
        XCTAssertFalse(outbounds.contains { ($0["tag"] as? String) == "空群" })
        // 主 selector default 落回節點
        let proxy = outbounds.first { ($0["tag"] as? String) == "PROXY" }
        XCTAssertEqual(proxy?["default"] as? String, "HK")
    }

    func testGroupNameCollisionUniquified() {
        let a = node("HK")
        // 群組名稱與節點同名 → 應產生不同 tag
        let g = ProxyGroup(name: "HK", type: .select, memberNodeIDs: [a.id])
        let result = SingBoxConfigBuilder.build(
            nodes: [a], selectedID: nil, settings: AppSettings(), mode: .rule, groups: [g])
        XCTAssertNotEqual(result.tagByGroupID[g.id], result.tagByNodeID[a.id])
    }
}
