import XCTest
@testable import ShadowSpaceKit

final class RelayTests: XCTestCase {

    func testDetourChain() {
        var transit = ProxyNode(name: "中轉", proto: .trojan, server: "a.example.com", port: 443)
        transit.password = "p"; transit.tls = true
        var landing = ProxyNode(name: "落地", proto: .shadowsocks, server: "b.example.com", port: 8388)
        landing.method = "aes-256-gcm"; landing.password = "p"
        landing.dialerNodeID = transit.id   // 落地經中轉

        let result = SingBoxConfigBuilder.build(
            nodes: [transit, landing], selectedID: landing.id, settings: AppSettings(), mode: .rule)
        let outbounds = result.json["outbounds"] as? [[String: Any]] ?? []

        let landingOut = outbounds.first { ($0["tag"] as? String) == "落地" }
        XCTAssertEqual(landingOut?["detour"] as? String, "中轉")

        let transitOut = outbounds.first { ($0["tag"] as? String) == "中轉" }
        XCTAssertNil(transitOut?["detour"])
    }

    func testNoDetourWhenUnset() {
        var node = ProxyNode(name: "單", proto: .trojan, server: "a.com", port: 443)
        node.password = "p"; node.tls = true
        let result = SingBoxConfigBuilder.build(
            nodes: [node], selectedID: node.id, settings: AppSettings(), mode: .rule)
        let out = (result.json["outbounds"] as? [[String: Any]])?.first { ($0["tag"] as? String) == "單" }
        XCTAssertNil(out?["detour"])
    }
}
