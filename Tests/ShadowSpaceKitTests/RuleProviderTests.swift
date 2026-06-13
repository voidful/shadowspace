import XCTest
@testable import ShadowSpaceKit

final class RuleProviderTests: XCTestCase {

    private func trojan(_ name: String) -> ProxyNode {
        var n = ProxyNode(name: name, proto: .trojan, server: "\(name).com", port: 443)
        n.password = "p"; n.tls = true
        return n
    }

    func testRemoteRuleSetGenerated() {
        let a = trojan("HK")
        var rule = UserRule()
        rule.type = .ruleSet
        rule.value = "https://example.com/ads.srs"
        rule.policy = .reject

        let result = SingBoxConfigBuilder.build(
            nodes: [a], selectedID: a.id, settings: AppSettings(), mode: .rule, rules: [rule])
        let route = result.json["route"] as? [String: Any]

        // 遠端 rule_set 定義存在，.srs → binary
        let ruleSets = route?["rule_set"] as? [[String: Any]] ?? []
        let rs = ruleSets.first { ($0["url"] as? String) == "https://example.com/ads.srs" }
        XCTAssertEqual(rs?["type"] as? String, "remote")
        XCTAssertEqual(rs?["format"] as? String, "binary")

        // 對應的 route rule（reject）引用此 rule_set
        let routeRules = route?["rules"] as? [[String: Any]] ?? []
        XCTAssertTrue(routeRules.contains {
            ($0["action"] as? String) == "reject"
            && (($0["rule_set"] as? [String])?.first?.hasPrefix("ruleset-") ?? false)
        })
    }

    func testSourceFormatForJSON() {
        let a = trojan("HK")
        var rule = UserRule()
        rule.type = .ruleSet
        rule.value = "https://example.com/list.json"
        rule.policy = .proxy
        let result = SingBoxConfigBuilder.build(
            nodes: [a], selectedID: a.id, settings: AppSettings(), mode: .rule, rules: [rule])
        let ruleSets = (result.json["route"] as? [String: Any])?["rule_set"] as? [[String: Any]] ?? []
        let rs = ruleSets.first { ($0["url"] as? String) == "https://example.com/list.json" }
        XCTAssertEqual(rs?["format"] as? String, "source")
    }
}
