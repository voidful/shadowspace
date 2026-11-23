import XCTest
@testable import ShadowSpaceKit

final class Hy2ProfileTests: XCTestCase {
    // Self-signed test certificate; no private key is needed for a client config check.
    let pem = """
    -----BEGIN CERTIFICATE-----
    MIIBkDCCATagAwIBAgIUaJ8eR4DD1r5cXSP0wk4xl2rbVHowCgYIKoZIzj0EAwIw
    EzERMA8GA1UEAwwIaHkyLnRlc3QwHhcNMjYxMTIzMDYzMTA0WhcNMzYxMTIwMDYz
    MTA0WjATMREwDwYDVQQDDAhoeTIudGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEH
    A0IABNhHIMlpISYxXv53on2+GS056oPlWn5sbO7r6j62fvEooEgkauWivsiQkMMy
    I7zVroKHb0pHR8oq2K+zPmr/2emjaDBmMB0GA1UdDgQWBBQ5w2zduyxo8wkXb4S4
    XHwo5ndP5TAfBgNVHSMEGDAWgBQ5w2zduyxo8wkXb4S4XHwo5ndP5TAPBgNVHRMB
    Af8EBTADAQH/MBMGA1UdEQQMMAqCCGh5Mi50ZXN0MAoGCCqGSM49BAMCA0gAMEUC
    IQDeqJrnkDKI3pO6hLViEVCvjog+9rz0hhiIYudYQcPy5AIgMmqePzoevP5wKkOd
    ok2rLAIx+9xz5EWlOc2FJ+jhc6c=
    -----END CERTIFICATE-----
    """
    let pbk = Data(1...32).base64EncodedString().replacingOccurrences(of: "=", with: "")

    func profile(certificate: Any) throws -> String {
        let outbounds: [[String: Any]] = [
            ["type": "selector", "tag": "proxy", "outbounds": ["home-reality", "home-hy2"]],
            ["type": "vless", "tag": "home-reality", "server": "home.example", "server_port": 443,
             "uuid": "75c71384-77ff-467a-a654-c0509610060c", "flow": "xtls-rprx-vision",
             "tls": ["enabled": true, "server_name": "www.example.com",
                     "utls": ["enabled": true, "fingerprint": "chrome"],
                     "reality": ["enabled": true, "public_key": pbk, "short_id": "ab12"]]],
            ["type": "hysteria2", "tag": "home-hy2", "server": "home.example", "server_port": 443,
             "password": "fixture", "tls": ["enabled": true, "server_name": "hy2.test",
                                             "alpn": ["h3"], "certificate": certificate]],
            ["type": "direct", "tag": "direct"]
        ]
        let json = try JSONSerialization.data(withJSONObject: ["outbounds": outbounds,
            "route": ["rule_set": [["url": "https://example.invalid/ignored.srs"]]]])
        return String(decoding: json, as: UTF8.self)
    }

    func testProfileImportPersistAndBuild() throws {
        let lines = pem.components(separatedBy: "\n")
        let input = try profile(certificate: lines)
        let result = URIParser.classify(input)
        XCTAssertEqual(result.nodes.map(\.name), ["home-reality", "home-hy2"])
        XCTAssertTrue(result.subscriptionURLs.isEmpty)
        XCTAssertTrue(result.unparsedLines.isEmpty)
        let restored = try JSONDecoder().decode([ProxyNode].self, from: JSONEncoder().encode(result.nodes))
        let vless = restored[0], hy2 = restored[1]
        XCTAssertEqual(hy2.tlsCertificate, lines)
        XCTAssertNil(NodeShare.uri(for: hy2))
        XCTAssertFalse(NativeEngineAdapter.isSupported(hy2))
        XCTAssertTrue(NativeEngineAdapter.isSupported(vless))

        let a = SingBoxConfigBuilder.outbound(for: vless, tag: vless.name)
        let tls = try XCTUnwrap(a["tls"] as? [String: Any])
        XCTAssertEqual(a["flow"] as? String, "xtls-rprx-vision")
        XCTAssertEqual(tls["server_name"] as? String, "www.example.com")
        XCTAssertEqual((tls["reality"] as? [String: Any])?["public_key"] as? String, pbk)
        XCTAssertEqual((tls["reality"] as? [String: Any])?["short_id"] as? String, "ab12")
        XCTAssertEqual((tls["utls"] as? [String: Any])?["fingerprint"] as? String, "chrome")

        let b = SingBoxConfigBuilder.outbound(for: hy2, tag: hy2.name)
        let h = try XCTUnwrap(b["tls"] as? [String: Any])
        XCTAssertEqual(h["certificate"] as? [String], lines)
        XCTAssertEqual(h["server_name"] as? String, "hy2.test")
        XCTAssertEqual(h["alpn"] as? [String], ["h3"])
        XCTAssertNil(h["insecure"])
        XCTAssertEqual(b["password"] as? String, "fixture")
    }

    func testWholeCertificatePinCannotDegradeToInsecureURI() throws {
        let uri = "hy2://fixture@home.example:443/?insecure=1&pinSHA256=ab:cd#home-hy2"
        XCTAssertNil(URIParser.parse(uri))
        XCTAssertTrue(URIParser.requiresHysteriaCertificate(uri))
        XCTAssertTrue(SubscriptionManager.parseContent(uri, data: Data(uri.utf8)).isEmpty)
    }

    func testManualReimportRepairsLegacyTrustWithoutDuplicatingNode() throws {
        let input = try profile(certificate: pem)
        let hy2 = try XCTUnwrap(URIParser.classify(input).nodes.last)
        XCTAssertEqual(hy2.tlsCertificate, [pem])
        var old = hy2
        old.id = UUID()
        old.dialerNodeID = UUID()
        old.tlsCertificate = nil
        old.insecure = true
        let merged = ImportService.mergeNodes([hy2, hy2], into: [old])
        XCTAssertEqual(merged.added, 0)
        XCTAssertEqual(merged.upgraded, [old.id])
        XCTAssertEqual(merged.nodes.first?.dialerNodeID, old.dialerNodeID)
        XCTAssertEqual(merged.nodes.first?.tlsCertificate, [pem])
        XCTAssertEqual(merged.nodes.first?.insecure, false)
    }

    func testDualNodeConfigurationPassesSingBoxCheck() throws {
        guard let binary = EngineManager.findBinary() else { throw XCTSkip("sing-box unavailable") }
        let input = try profile(certificate: pem.components(separatedBy: "\n"))
        let nodes = SingBoxNodeParser.parse(Data(input.utf8))
        var settings = AppSettings()
        settings.chinaDirect = false
        let result = SingBoxConfigBuilder.build(nodes: nodes, selectedID: nodes.last?.id,
                                                settings: settings, mode: .global)
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".json")
        defer { try? FileManager.default.removeItem(at: url) }
        try SingBoxConfigBuilder.jsonData(result.json).write(to: url)
        let (status, output) = EngineManager.runProcess(binary, ["check", "-c", url.path])
        XCTAssertEqual(status, 0, output)
    }
}
