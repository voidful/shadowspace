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

    func testDefaultUTLSFingerprintApplied() {
        // TLS 節點未帶 fp → 套用預設瀏覽器指紋（抗 JA3 / 主動探測，對齊 Shadowrocket）
        var node = ProxyNode(name: "v", proto: .vless, server: "x.com", port: 443)
        node.uuid = "u"; node.tls = true
        let ob = SingBoxConfigBuilder.outbound(for: node, tag: "v", defaultFingerprint: "chrome")
        let utls = (ob["tls"] as? [String: Any])?["utls"] as? [String: Any]
        XCTAssertEqual(utls?["enabled"] as? Bool, true)
        XCTAssertEqual(utls?["fingerprint"] as? String, "chrome")
    }

    func testExplicitFingerprintOverridesDefault() {
        var node = ProxyNode(name: "t", proto: .trojan, server: "x.com", port: 443)
        node.password = "pw"; node.tls = true; node.fingerprint = "safari"
        let ob = SingBoxConfigBuilder.outbound(for: node, tag: "t", defaultFingerprint: "chrome")
        let utls = (ob["tls"] as? [String: Any])?["utls"] as? [String: Any]
        XCTAssertEqual(utls?["fingerprint"] as? String, "safari")
    }

    func testDefaultUTLSDisabledWhenEmpty() {
        var node = ProxyNode(name: "v", proto: .vless, server: "x.com", port: 443)
        node.uuid = "u"; node.tls = true
        let ob = SingBoxConfigBuilder.outbound(for: node, tag: "v", defaultFingerprint: "")
        XCTAssertNil((ob["tls"] as? [String: Any])?["utls"], "空字串 = 不套用 uTLS")
    }

    func testDefaultUTLSNotAppliedToQUIC() {
        // hysteria2（QUIC）即使 tls=true 也不該注入 uTLS（uTLS 僅適用 TLS-over-TCP）
        var node = ProxyNode(name: "h", proto: .hysteria2, server: "x.com", port: 443)
        node.password = "pw"; node.tls = true
        let ob = SingBoxConfigBuilder.outbound(for: node, tag: "h", defaultFingerprint: "chrome")
        XCTAssertNil((ob["tls"] as? [String: Any])?["utls"], "QUIC 協議不套用 uTLS")
    }

    func testBuildAppliesDefaultFingerprintEndToEnd() {
        // 端到端：預設 settings（tlsFingerprint=chrome）下，TLS 節點的 outbound 應帶 uTLS chrome
        let a = makeNode(name: "n")   // trojan + tls，未帶 fp
        let result = SingBoxConfigBuilder.build(
            nodes: [a], selectedID: a.id, settings: AppSettings(), mode: .rule)
        let outbounds = result.json["outbounds"] as? [[String: Any]] ?? []
        let node = outbounds.first { ($0["tag"] as? String) == "n" }
        let utls = (node?["tls"] as? [String: Any])?["utls"] as? [String: Any]
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

        let doh3 = SingBoxConfigBuilder.dnsServerDict(
            tag: "h3", spec: "h3://dns.google/dns-query", detour: "PROXY",
            domainResolver: "dns-bootstrap")
        XCTAssertEqual(doh3["type"] as? String, "h3")
        XCTAssertEqual(doh3["server"] as? String, "dns.google")
        XCTAssertEqual(doh3["detour"] as? String, "PROXY")
        XCTAssertEqual(doh3["domain_resolver"] as? String, "dns-bootstrap")
    }

    func testTailscaleAndMagicDNSConfig() {
        let a = makeNode(name: "n")
        var settings = AppSettings()
        settings.tailscaleEnabled = true
        settings.tailscaleMagicDNS = true
        settings.tailscaleAuthKey = "tskey-auth-test"
        settings.tailscaleHostname = "shadowspace-mac"
        settings.tailscaleExitNode = "exit.example.ts.net"

        let result = SingBoxConfigBuilder.build(
            nodes: [a], selectedID: a.id, settings: settings, mode: .rule)

        let endpoints = result.json["endpoints"] as? [[String: Any]] ?? []
        let tailscale = endpoints.first { ($0["type"] as? String) == "tailscale" }
        XCTAssertEqual(tailscale?["tag"] as? String, SingBoxConfigBuilder.tailscaleTag)
        XCTAssertEqual(tailscale?["auth_key"] as? String, "tskey-auth-test")
        XCTAssertEqual(tailscale?["hostname"] as? String, "shadowspace-mac")
        XCTAssertEqual(tailscale?["exit_node"] as? String, "exit.example.ts.net")

        let dns = result.json["dns"] as? [String: Any]
        let servers = dns?["servers"] as? [[String: Any]] ?? []
        XCTAssertTrue(servers.contains {
            ($0["type"] as? String) == "tailscale" &&
            ($0["endpoint"] as? String) == SingBoxConfigBuilder.tailscaleTag
        })

        let route = result.json["route"] as? [String: Any]
        let rules = route?["rules"] as? [[String: Any]] ?? []
        let tailscaleIndex = rules.firstIndex {
            ($0["outbound"] as? String) == SingBoxConfigBuilder.tailscaleTag
        }
        let privateIndex = rules.firstIndex { ($0["ip_is_private"] as? Bool) == true }
        XCTAssertNotNil(tailscaleIndex)
        XCTAssertNotNil(privateIndex)
        XCTAssertLessThan(tailscaleIndex!, privateIndex!, "Tailscale route 必須優先於私有 IP 直連")
    }

    func testURLTestTuningAppliedToAutoAndCustomGroups() {
        let a = makeNode(name: "a")
        let b = makeNode(name: "b", server: "5.6.7.8")
        let group = ProxyGroup(name: "最快", type: .urltest, memberNodeIDs: [a.id, b.id])
        var settings = AppSettings()
        settings.latencyTestURL = "https://example.com/ping"
        settings.latencyTestIntervalMinutes = 3
        settings.latencyTestToleranceMS = 120

        let result = SingBoxConfigBuilder.build(
            nodes: [a, b], selectedID: group.id, settings: settings, mode: .rule,
            groups: [group])
        let outbounds = result.json["outbounds"] as? [[String: Any]] ?? []
        let tests = outbounds.filter { ($0["type"] as? String) == "urltest" }
        XCTAssertEqual(tests.count, 2)
        for test in tests {
            XCTAssertEqual(test["url"] as? String, "https://example.com/ping")
            XCTAssertEqual(test["interval"] as? String, "3m")
            XCTAssertEqual(test["tolerance"] as? Int, 120)
            XCTAssertEqual(test["idle_timeout"] as? String, "30m")
        }
    }

    func testGeneratedTailscaleDoH3ConfigPassesInstalledSingBoxCheck() throws {
        guard let binary = EngineManager.findBinary() else {
            throw XCTSkip("本機未安裝 sing-box，略過核心語法檢查")
        }
        let a = makeNode(name: "n")
        var settings = AppSettings()
        settings.tailscaleEnabled = true
        settings.tailscaleMagicDNS = true
        settings.remoteDNS = "h3://dns.google/dns-query"
        settings.chinaDirect = false

        let result = SingBoxConfigBuilder.build(
            nodes: [a], selectedID: a.id, settings: settings, mode: .rule)
        let data = try SingBoxConfigBuilder.jsonData(result.json)
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("shadowspace-config-\(UUID().uuidString).json")
        try data.write(to: url, options: .atomic)
        defer { try? FileManager.default.removeItem(at: url) }

        let (status, output) = EngineManager.runProcess(binary, ["check", "-c", url.path])
        XCTAssertEqual(status, 0, output)
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
