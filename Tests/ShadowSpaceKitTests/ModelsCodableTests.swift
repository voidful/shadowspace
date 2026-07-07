import XCTest
@testable import ShadowSpaceKit

/// 防禦性解碼：舊 state.json 缺欄位時不得整包解碼失敗，且 encode→decode 需逐欄還原。
final class ModelsCodableTests: XCTestCase {

    private func roundTrip<T: Codable>(_ value: T, as type: T.Type) throws -> T {
        let data = try JSONEncoder().encode(value)
        return try JSONDecoder().decode(type, from: data)
    }

    func testProxyNodeRoundTrip() throws {
        var node = ProxyNode(name: "節點", proto: .vless, server: "a.example.com", port: 443)
        node.uuid = "uuid-1"
        node.tls = true
        node.sni = "a.example.com"
        node.flow = "xtls-rprx-vision"
        node.alpn = ["h2", "http/1.1"]
        node.insecure = true
        node.network = "ws"
        node.wsPath = "/ws"
        node.wgLocalAddress = ["10.0.0.2/32"]
        node.dialerNodeID = UUID()
        node.subscriptionID = UUID()

        let decoded = try roundTrip(node, as: ProxyNode.self)
        XCTAssertEqual(decoded, node)
    }

    func testProxyNodeDecodesWithOnlyRequiredFields() throws {
        // 模擬最精簡的舊資料：只有必填欄位，其餘全缺。
        let json = """
        { "id": "\(UUID().uuidString)", "name": "舊節點", "proto": "shadowsocks",
          "server": "1.2.3.4", "port": 8388 }
        """.data(using: .utf8)!
        let node = try JSONDecoder().decode(ProxyNode.self, from: json)
        XCTAssertEqual(node.proto, .shadowsocks)
        XCTAssertEqual(node.port, 8388)
        XCTAssertFalse(node.tls)       // 缺 tls → 預設 false，而非解碼失敗
        XCTAssertFalse(node.insecure)
        XCTAssertNil(node.method)
    }

    func testUserRuleRoundTripAndDefaults() throws {
        var rule = UserRule()
        rule.type = .geosite
        rule.value = "netflix"
        rule.policy = .reject
        rule.enabled = false
        XCTAssertEqual(try roundTrip(rule, as: UserRule.self), rule)

        // 缺 enabled/policy 的舊規則 → 用預設值
        let json = #"{ "id": "\#(UUID().uuidString)", "type": "domainSuffix", "value": "x.com" }"#
            .data(using: .utf8)!
        let decoded = try JSONDecoder().decode(UserRule.self, from: json)
        XCTAssertTrue(decoded.enabled)
        XCTAssertEqual(decoded.policy, .proxy)
    }

    func testProxyGroupRoundTripAndDefaults() throws {
        var group = ProxyGroup(name: "香港", type: .urltest, memberNodeIDs: [UUID(), UUID()])
        XCTAssertEqual(try roundTrip(group, as: ProxyGroup.self), group)

        let json = #"{ "id": "\#(UUID().uuidString)", "name": "舊群組" }"#.data(using: .utf8)!
        let decoded = try JSONDecoder().decode(ProxyGroup.self, from: json)
        XCTAssertEqual(decoded.type, .select)
        XCTAssertEqual(decoded.memberNodeIDs, [])
    }

    func testSubscriptionRoundTrip() throws {
        var sub = Subscription(name: "機場", url: "https://example.com/sub")
        sub.rawUserInfo = "upload=1;download=2;total=100"
        XCTAssertEqual(try roundTrip(sub, as: Subscription.self), sub)
    }

    func testPersistedStateSurvivesUnknownAndMissingFields() throws {
        // 只有節點、其餘全缺——整包不得失敗。
        let json = """
        { "nodes": [ { "id": "\(UUID().uuidString)", "name": "n", "proto": "trojan",
          "server": "x.com", "port": 443 } ] }
        """.data(using: .utf8)!
        let state = try JSONDecoder().decode(PersistedState.self, from: json)
        XCTAssertEqual(state.nodes.count, 1)
        XCTAssertEqual(state.mode, .rule)
        XCTAssertTrue(state.groups.isEmpty)
    }
}
