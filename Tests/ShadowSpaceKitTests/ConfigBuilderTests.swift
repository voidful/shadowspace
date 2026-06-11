import XCTest
@testable import ShadowSpaceKit

final class ConfigBuilderTests: XCTestCase {

    private func makeNode(name: String, server: String = "1.2.3.4", port: Int = 443) -> ProxyNode {
        var node = ProxyNode(name: name, proto: .trojan, server: server, port: port)
        node.password = "pw"
        node.tls = true
        node.sni = server
        return node
    }

    func testBuildBasicStructure() throws {
        let a = makeNode(name: "香港 01")
        let b = makeNode(name: "日本 01", server: "5.6.7.8")
        var settings = AppSettings()
        settings.mixedPort = 7777
        settings.apiPort = 9999

        let result = SingBoxConfigBuilder.build(
            nodes: [a, b], selectedID: b.id, settings: settings, mode: .rule)

        // 必須是合法 JSON
        let data = try SingBoxConfigBuilder.jsonData(result.json)
        XCTAssertFalse(data.isEmpty)

        // inbound 連接埠正確
        let inbounds = result.json["inbounds"] as? [[String: Any]]
        XCTAssertEqual(inbounds?.first?["listen_port"] as? Int, 7777)
        XCTAssertEqual(inbounds?.first?["listen"] as? String, "127.0.0.1")

        // selector 預設節點 = 所選節點
        let outbounds = result.json["outbounds"] as? [[String: Any]] ?? []
        let selector = outbounds.first { ($0["tag"] as? String) == "PROXY" }
        XCTAssertEqual(selector?["default"] as? String, "日本 01")

        // 多節點時要有 AUTO urltest
        XCTAssertTrue(outbounds.contains { ($0["tag"] as? String) == "AUTO" })

        // clash api 埠正確
        let experimental = result.json["experimental"] as? [String: Any]
        let clashAPI = experimental?["clash_api"] as? [String: Any]
        XCTAssertEqual(clashAPI?["external_controller"] as? String, "127.0.0.1:9999")
    }

    func testDuplicateNamesGetUniqueTags() {
        let a = makeNode(name: "節點")
        let b = makeNode(name: "節點", server: "5.6.7.8")
        let result = SingBoxConfigBuilder.build(
            nodes: [a, b], selectedID: nil, settings: AppSettings(), mode: .rule)
        let tags = Set(result.tagByNodeID.values)
        XCTAssertEqual(tags.count, 2, "重複名稱必須產生不同 tag")
    }

    func testModeRulesPresent() {
        let a = makeNode(name: "n")
        let result = SingBoxConfigBuilder.build(
            nodes: [a], selectedID: a.id, settings: AppSettings(), mode: .global)
        let route = result.json["route"] as? [String: Any]
        let rules = route?["rules"] as? [[String: Any]] ?? []
        XCTAssertTrue(rules.contains { ($0["clash_mode"] as? String) == "Global" })
        XCTAssertTrue(rules.contains { ($0["clash_mode"] as? String) == "Direct" })

        let experimental = result.json["experimental"] as? [String: Any]
        let clashAPI = experimental?["clash_api"] as? [String: Any]
        XCTAssertEqual(clashAPI?["default_mode"] as? String, "Global")
    }

    func testAllowLANChangesListenAddress() {
        var settings = AppSettings()
        settings.allowLAN = true
        let a = makeNode(name: "n")
        let result = SingBoxConfigBuilder.build(
            nodes: [a], selectedID: a.id, settings: settings, mode: .rule)
        let inbounds = result.json["inbounds"] as? [[String: Any]]
        XCTAssertEqual(inbounds?.first?["listen"] as? String, "0.0.0.0")
    }

    func testRealityOutbound() {
        var node = ProxyNode(name: "r", proto: .vless, server: "x.com", port: 443)
        node.uuid = "u"
        node.tls = true
        node.realityPublicKey = "PBK"
        node.realityShortID = "SID"
        node.fingerprint = "chrome"
        let ob = SingBoxConfigBuilder.outbound(for: node, tag: "r")
        let tls = ob["tls"] as? [String: Any]
        let reality = tls?["reality"] as? [String: Any]
        XCTAssertEqual(reality?["public_key"] as? String, "PBK")
        let utls = tls?["utls"] as? [String: Any]
        XCTAssertEqual(utls?["fingerprint"] as? String, "chrome")
    }

    func testWSEarlyDataPath() {
        var node = ProxyNode(name: "ws", proto: .vmess, server: "x.com", port: 443)
        node.uuid = "u"
        node.network = "ws"
        node.wsPath = "/path?ed=2048"
        let ob = SingBoxConfigBuilder.outbound(for: node, tag: "ws")
        let transport = ob["transport"] as? [String: Any]
        XCTAssertEqual(transport?["path"] as? String, "/path")
        XCTAssertEqual(transport?["max_early_data"] as? Int, 2048)
    }

    func testUserRulesAndAdBlock() {
        let a = makeNode(name: "n")
        var settings = AppSettings()
        settings.adBlock = true
        var rule1 = UserRule()
        rule1.type = .domainSuffix
        rule1.value = "youtube.com, ytimg.com"
        rule1.policy = .proxy
        var rule2 = UserRule()
        rule2.type = .geosite
        rule2.value = "netflix"
        rule2.policy = .direct
        var disabled = UserRule()
        disabled.enabled = false
        disabled.value = "x.com"

        let result = SingBoxConfigBuilder.build(
            nodes: [a], selectedID: a.id, settings: settings, mode: .rule,
            rules: [rule1, rule2, disabled])
        let route = result.json["route"] as? [String: Any]
        let rules = route?["rules"] as? [[String: Any]] ?? []

        // 廣告阻擋 reject 規則存在
        XCTAssertTrue(rules.contains {
            ($0["action"] as? String) == "reject" &&
            ($0["rule_set"] as? [String])?.contains("geosite-category-ads-all") == true
        })
        // 自訂網域規則：逗號分隔展開成陣列
        XCTAssertTrue(rules.contains {
            ($0["domain_suffix"] as? [String]) == ["youtube.com", "ytimg.com"]
        })
        // geosite 規則會自動補 rule_set 定義
        let ruleSets = (route?["rule_set"] as? [[String: Any]] ?? []).compactMap { $0["tag"] as? String }
        XCTAssertTrue(ruleSets.contains("geosite-netflix"))
        XCTAssertTrue(ruleSets.contains("geosite-category-ads-all"))
        // 停用的規則不會出現
        XCTAssertFalse(rules.contains { ($0["domain_suffix"] as? [String])?.contains("x.com") == true })
    }

    func testChinaDirectToggleOff() {
        let a = makeNode(name: "n")
        var settings = AppSettings()
        settings.chinaDirect = false
        let result = SingBoxConfigBuilder.build(
            nodes: [a], selectedID: a.id, settings: settings, mode: .rule)
        let route = result.json["route"] as? [String: Any]
        let rules = route?["rules"] as? [[String: Any]] ?? []
        XCTAssertFalse(rules.contains {
            ($0["rule_set"] as? [String])?.contains("geosite-cn") == true
        })
    }

    func testTunModeConfig() {
        let a = makeNode(name: "n")
        var settings = AppSettings()
        settings.tunMode = true
        let result = SingBoxConfigBuilder.build(
            nodes: [a], selectedID: a.id, settings: settings, mode: .rule)
        let inbounds = result.json["inbounds"] as? [[String: Any]] ?? []
        XCTAssertTrue(inbounds.contains { ($0["type"] as? String) == "tun" })
        // mixed inbound 仍保留
        XCTAssertTrue(inbounds.contains { ($0["type"] as? String) == "mixed" })
        let route = result.json["route"] as? [String: Any]
        XCTAssertEqual(route?["auto_detect_interface"] as? Bool, true)
        let rules = route?["rules"] as? [[String: Any]] ?? []
        XCTAssertTrue(rules.contains { ($0["action"] as? String) == "hijack-dns" })
    }

    func testDoHRemoteDNS() {
        let dict = SingBoxConfigBuilder.dnsServerDict(
            tag: "dns-remote", spec: "https://dns.google/dns-query", detour: "PROXY")
        XCTAssertEqual(dict["type"] as? String, "https")
        XCTAssertEqual(dict["server"] as? String, "dns.google")
        XCTAssertEqual(dict["detour"] as? String, "PROXY")
        XCTAssertNil(dict["path"]) // /dns-query 是預設路徑，不需要寫

        let local = SingBoxConfigBuilder.dnsServerDict(tag: "dns-direct", spec: "local", detour: nil)
        XCTAssertEqual(local["type"] as? String, "local")

        let dot = SingBoxConfigBuilder.dnsServerDict(tag: "t", spec: "tls://9.9.9.9", detour: nil)
        XCTAssertEqual(dot["type"] as? String, "tls")
        XCTAssertEqual(dot["server"] as? String, "9.9.9.9")
    }

    func testSubscriptionTrafficSummary() {
        var sub = Subscription(name: "s", url: "https://x")
        sub.rawUserInfo = "upload=1073741824; download=2147483648; total=107374182400; expire=1767139200"
        let summary = sub.trafficSummary
        XCTAssertNotNil(summary)
        XCTAssertTrue(summary!.contains("已用"))
        XCTAssertTrue(summary!.contains("到期"))
    }
}
