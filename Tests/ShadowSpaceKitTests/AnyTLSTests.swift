import XCTest
@testable import ShadowSpaceKit

final class AnyTLSTests: XCTestCase {

    func testParseAnyTLSURI() throws {
        let node = try XCTUnwrap(URIParser.parseAnyTLS(
            "anytls://mypassword@anytls.example.com:8443?sni=example.com&insecure=1#AnyTLS-Node"))
        XCTAssertEqual(node.proto, .anytls)
        XCTAssertEqual(node.name, "AnyTLS-Node")
        XCTAssertEqual(node.server, "anytls.example.com")
        XCTAssertEqual(node.port, 8443)
        XCTAssertEqual(node.password, "mypassword")
        XCTAssertTrue(node.tls)
        XCTAssertEqual(node.sni, "example.com")
        XCTAssertTrue(node.insecure)
    }

    func testParseAnyTLSViaGenericEntry() {
        // 經由 URIParser.parse 分派
        let node = URIParser.parse("anytls://pw@h.com:443#x")
        XCTAssertEqual(node?.proto, .anytls)
    }

    func testClashAnyTLS() throws {
        let yaml = """
        proxies:
          - name: AnyTLS-A
            type: anytls
            server: a.example.com
            port: 443
            password: secret
            sni: a.example.com
            skip-cert-verify: true
        """
        let node = try XCTUnwrap(ClashYAMLParser.parse(yaml).first)
        XCTAssertEqual(node.proto, .anytls)
        XCTAssertEqual(node.password, "secret")
        XCTAssertTrue(node.tls)
        XCTAssertTrue(node.insecure)
    }

    func testShareLinkRoundTrip() throws {
        let original = try XCTUnwrap(URIParser.parseAnyTLS(
            "anytls://pw123@srv.example.com:8443?sni=srv.example.com#Node"))
        let link = try XCTUnwrap(NodeShare.uri(for: original))
        XCTAssertTrue(link.hasPrefix("anytls://"))
        let parsed = try XCTUnwrap(URIParser.parse(link))
        XCTAssertEqual(parsed.proto, .anytls)
        XCTAssertEqual(parsed.password, "pw123")
        XCTAssertEqual(parsed.server, "srv.example.com")
        XCTAssertEqual(parsed.sni, "srv.example.com")
    }

    /// 產出含 anytls outbound 的 sing-box 設定，欄位正確，並寫到 /tmp 供 `sing-box check`。
    func testAnyTLSConfigStructureAndDump() throws {
        let node = try XCTUnwrap(URIParser.parseAnyTLS(
            "anytls://mypassword@anytls.example.com:8443?sni=example.com&insecure=1#AnyTLS"))
        let result = SingBoxConfigBuilder.build(
            nodes: [node], selectedID: node.id, settings: AppSettings(), mode: .rule)
        let data = try SingBoxConfigBuilder.jsonData(result.json)
        let obj = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let outbounds = try XCTUnwrap(obj["outbounds"] as? [[String: Any]])
        let anytls = try XCTUnwrap(outbounds.first { $0["type"] as? String == "anytls" })
        XCTAssertEqual(anytls["password"] as? String, "mypassword")
        XCTAssertEqual(anytls["server"] as? String, "anytls.example.com")
        XCTAssertEqual(anytls["server_port"] as? Int, 8443)
        let tls = try XCTUnwrap(anytls["tls"] as? [String: Any])
        XCTAssertEqual(tls["enabled"] as? Bool, true)
        XCTAssertEqual(tls["server_name"] as? String, "example.com")
        XCTAssertEqual(tls["insecure"] as? Bool, true)
        try data.write(to: URL(fileURLWithPath: "/tmp/shadowspace-anytls-check.json"))
    }
}
