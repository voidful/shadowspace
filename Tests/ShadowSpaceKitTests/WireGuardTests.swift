import XCTest
import ShadowCore
@testable import ShadowSpaceKit

final class WireGuardTests: XCTestCase {

    let conf = """
    [Interface]
    PrivateKey = aPrivateKeyBase64==
    Address = 10.0.0.2/32, fd00::2/128
    MTU = 1420
    DNS = 1.1.1.1

    [Peer]
    PublicKey = aPublicKeyBase64==
    PresharedKey = aPSKBase64==
    Endpoint = wg.example.com:51820
    AllowedIPs = 0.0.0.0/0, ::/0
    PersistentKeepalive = 25
    """

    func testLooksLike() {
        XCTAssertTrue(WireGuardParser.looksLikeConfig(conf))
        XCTAssertFalse(WireGuardParser.looksLikeConfig("ss://abc@1.2.3.4:8388"))
    }

    func testParse() {
        let node = WireGuardParser.parse(conf)
        XCTAssertEqual(node?.proto, .wireguard)
        XCTAssertEqual(node?.server, "wg.example.com")
        XCTAssertEqual(node?.port, 51820)
        XCTAssertEqual(node?.wgPrivateKey, "aPrivateKeyBase64==")
        XCTAssertEqual(node?.wgPeerPublicKey, "aPublicKeyBase64==")
        XCTAssertEqual(node?.wgPresharedKey, "aPSKBase64==")
        XCTAssertEqual(node?.wgLocalAddress, ["10.0.0.2/32", "fd00::2/128"])
        XCTAssertEqual(node?.wgMTU, 1420)
    }

    func testImportDetectsWireGuard() {
        let (nodes, subs) = URIParser.classify(conf)
        XCTAssertEqual(nodes.count, 1)
        XCTAssertEqual(nodes.first?.proto, .wireguard)
        XCTAssertTrue(subs.isEmpty)
    }

    func testSingBoxEndpoint() {
        var node = ProxyNode(name: "wg1", proto: .wireguard, server: "wg.example.com", port: 51820)
        node.wgPrivateKey = "PRIV"; node.wgPeerPublicKey = "PUB"
        node.wgLocalAddress = ["10.0.0.2/32"]; node.wgMTU = 1420; node.wgPresharedKey = "PSK"
        let result = SingBoxConfigBuilder.build(
            nodes: [node], selectedID: node.id, settings: AppSettings(), mode: .rule)

        let endpoints = result.json["endpoints"] as? [[String: Any]]
        XCTAssertEqual(endpoints?.count, 1)
        let ep = endpoints?.first
        XCTAssertEqual(ep?["type"] as? String, "wireguard")
        XCTAssertEqual(ep?["private_key"] as? String, "PRIV")
        XCTAssertEqual(ep?["mtu"] as? Int, 1420)
        let peer = (ep?["peers"] as? [[String: Any]])?.first
        XCTAssertEqual(peer?["public_key"] as? String, "PUB")
        XCTAssertEqual(peer?["address"] as? String, "wg.example.com")
        XCTAssertEqual(peer?["pre_shared_key"] as? String, "PSK")

        // WG 不應出現在 outbounds，但 selector 要包含其 tag
        let outbounds = result.json["outbounds"] as? [[String: Any]] ?? []
        XCTAssertFalse(outbounds.contains { ($0["type"] as? String) == "wireguard" })
        let selector = outbounds.first { ($0["tag"] as? String) == "PROXY" }
        XCTAssertTrue((selector?["outbounds"] as? [String] ?? []).contains("wg1"))
    }

    func testNativeEngineRejectsWireGuard() {
        var node = ProxyNode(name: "wg", proto: .wireguard, server: "x", port: 1)
        node.wgPrivateKey = "p"; node.wgPeerPublicKey = "q"
        XCTAssertThrowsError(try NativeEngineAdapter.outbound(for: node))
    }
}
