import XCTest
@testable import ShadowSpaceKit

/// 分享連結匯出 → 解析 round-trip：確保自己產的連結自己一定讀得回來。
final class NodeShareTests: XCTestCase {

    func testSSRoundTrip() {
        var node = ProxyNode(name: "香港 SS", proto: .shadowsocks, server: "1.2.3.4", port: 8388)
        node.method = "chacha20-ietf-poly1305"
        node.password = "p@ss:word"
        let uri = NodeShare.uri(for: node)
        XCTAssertNotNil(uri)
        let parsed = URIParser.parse(uri!)
        XCTAssertEqual(parsed?.proto, .shadowsocks)
        XCTAssertEqual(parsed?.server, node.server)
        XCTAssertEqual(parsed?.port, node.port)
        XCTAssertEqual(parsed?.method, node.method)
        XCTAssertEqual(parsed?.password, node.password)
        XCTAssertEqual(parsed?.name, node.name)
    }

    func testVMessRoundTrip() {
        var node = ProxyNode(name: "JP VMess", proto: .vmess, server: "jp.example.com", port: 443)
        node.uuid = "23ad6b10-8d1a-40f7-8ad0-e3e35cd38297"
        node.alterId = 0
        node.security = "auto"
        node.tls = true
        node.sni = "cdn.example.com"
        node.network = "ws"
        node.wsPath = "/v2ray"
        node.wsHost = "cdn.example.com"
        let uri = NodeShare.uri(for: node)
        let parsed = URIParser.parse(uri!)
        XCTAssertEqual(parsed?.proto, .vmess)
        XCTAssertEqual(parsed?.uuid, node.uuid)
        XCTAssertEqual(parsed?.network, "ws")
        XCTAssertEqual(parsed?.wsPath, "/v2ray")
        XCTAssertEqual(parsed?.tls, true)
        XCTAssertEqual(parsed?.sni, "cdn.example.com")
    }

    func testVLESSRealityRoundTrip() {
        var node = ProxyNode(name: "HK Reality", proto: .vless, server: "hk.example.com", port: 443)
        node.uuid = "9a4b2c33-1111-2222-3333-444455556666"
        node.tls = true
        node.sni = "www.apple.com"
        node.fingerprint = "chrome"
        node.flow = "xtls-rprx-vision"
        node.realityPublicKey = "PUBKEY123"
        node.realityShortID = "ab12"
        let uri = NodeShare.uri(for: node)
        let parsed = URIParser.parse(uri!)
        XCTAssertEqual(parsed?.proto, .vless)
        XCTAssertEqual(parsed?.realityPublicKey, "PUBKEY123")
        XCTAssertEqual(parsed?.realityShortID, "ab12")
        XCTAssertEqual(parsed?.flow, "xtls-rprx-vision")
        XCTAssertEqual(parsed?.fingerprint, "chrome")
        XCTAssertEqual(parsed?.tls, true)
    }

    func testTrojanRoundTrip() {
        var node = ProxyNode(name: "台灣 01", proto: .trojan, server: "tw.example.com", port: 443)
        node.password = "p@ss"
        node.tls = true
        node.sni = "tw.example.com"
        node.insecure = true
        let uri = NodeShare.uri(for: node)
        let parsed = URIParser.parse(uri!)
        XCTAssertEqual(parsed?.password, "p@ss")
        XCTAssertEqual(parsed?.insecure, true)
        XCTAssertEqual(parsed?.name, "台灣 01")
    }

    func testHysteria2RoundTrip() {
        var node = ProxyNode(name: "SG Hy2", proto: .hysteria2, server: "sg.example.com", port: 443)
        node.password = "auth-key"
        node.tls = true
        node.sni = "sg.example.com"
        node.obfs = "salamander"
        node.obfsPassword = "ob123"
        let uri = NodeShare.uri(for: node)
        let parsed = URIParser.parse(uri!)
        XCTAssertEqual(parsed?.proto, .hysteria2)
        XCTAssertEqual(parsed?.password, "auth-key")
        XCTAssertEqual(parsed?.obfs, "salamander")
        XCTAssertEqual(parsed?.obfsPassword, "ob123")
    }

    func testTUICRoundTrip() {
        var node = ProxyNode(name: "US TUIC", proto: .tuic, server: "us.example.com", port: 443)
        node.uuid = "uuid-here"
        node.password = "pass-here"
        node.tls = true
        node.congestionControl = "bbr"
        node.alpn = ["h3"]
        let uri = NodeShare.uri(for: node)
        let parsed = URIParser.parse(uri!)
        XCTAssertEqual(parsed?.uuid, "uuid-here")
        XCTAssertEqual(parsed?.password, "pass-here")
        XCTAssertEqual(parsed?.congestionControl, "bbr")
        XCTAssertEqual(parsed?.alpn, ["h3"])
    }

    func testQRGeneration() {
        XCTAssertNotNil(NodeShare.qrImage(for: "ss://dGVzdDp0ZXN0@1.2.3.4:8388#test"))
    }
}
