import XCTest
import ShadowCore
@testable import ShadowSpaceKit

final class NativeEngineAdapterTests: XCTestCase {

    func testSupportedMappings() throws {
        var ss = ProxyNode(name: "ss1", proto: .shadowsocks, server: "1.2.3.4", port: 8388)
        ss.method = "aes-256-gcm"; ss.password = "pw"
        XCTAssertEqual(try NativeEngineAdapter.outbound(for: ss).name, "ss1")

        var trojan = ProxyNode(name: "t", proto: .trojan, server: "x.com", port: 443)
        trojan.password = "pw"; trojan.tls = true
        XCTAssertEqual(try NativeEngineAdapter.outbound(for: trojan).name, "t")

        var vless = ProxyNode(name: "v", proto: .vless, server: "x.com", port: 443)
        vless.uuid = "23ad6b10-8d1a-40f7-8ad0-e3e35cd38297"; vless.tls = true
        XCTAssertEqual(try NativeEngineAdapter.outbound(for: vless).name, "v")

        let socks = ProxyNode(name: "s", proto: .socks, server: "x.com", port: 1080)
        XCTAssertEqual(try NativeEngineAdapter.outbound(for: socks).name, "s")
    }

    func testUnsupportedThrows() {
        let vmess = ProxyNode(name: "m", proto: .vmess, server: "x", port: 1)
        XCTAssertThrowsError(try NativeEngineAdapter.outbound(for: vmess))
        let hy = ProxyNode(name: "h", proto: .hysteria2, server: "x", port: 1)
        XCTAssertThrowsError(try NativeEngineAdapter.outbound(for: hy))
        let tuic = ProxyNode(name: "u", proto: .tuic, server: "x", port: 1)
        XCTAssertThrowsError(try NativeEngineAdapter.outbound(for: tuic))

        var reality = ProxyNode(name: "r", proto: .vless, server: "x", port: 443)
        reality.uuid = "23ad6b10-8d1a-40f7-8ad0-e3e35cd38297"
        reality.realityPublicKey = "PBK"
        XCTAssertThrowsError(try NativeEngineAdapter.outbound(for: reality))

        // 未知 flow 仍須報錯（native 只支援 xtls-rprx-vision）
        var badFlow = ProxyNode(name: "bad", proto: .vless, server: "x", port: 443)
        badFlow.uuid = "23ad6b10-8d1a-40f7-8ad0-e3e35cd38297"
        badFlow.tls = true
        badFlow.flow = "xtls-rprx-origin"
        XCTAssertThrowsError(try NativeEngineAdapter.outbound(for: badFlow))
    }

    func testVisionRejectedRealityFlowlessSupported() throws {
        // XTLS Vision（flow）原生實作會破壞資料流、暫不支援 → 交回 sing-box（isSupported=false）
        var vision = ProxyNode(name: "vis", proto: .vless, server: "x.com", port: 443)
        vision.uuid = "23ad6b10-8d1a-40f7-8ad0-e3e35cd38297"
        vision.tls = true
        vision.flow = "xtls-rprx-vision"
        XCTAssertThrowsError(try NativeEngineAdapter.outbound(for: vision))
        XCTAssertFalse(NativeEngineAdapter.isSupported(vision))

        // flow-less REALITY（有效 pbk）仍受支援
        var reality = ProxyNode(name: "r", proto: .vless, server: "x.com", port: 443)
        reality.uuid = "23ad6b10-8d1a-40f7-8ad0-e3e35cd38297"
        reality.tls = true
        reality.realityPublicKey = Data(repeating: 7, count: 32).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        reality.realityShortID = "01ab"
        XCTAssertNoThrow(try NativeEngineAdapter.outbound(for: reality))
        XCTAssertTrue(NativeEngineAdapter.isSupported(reality))
    }

    func testNativeTLSPropagatesToTransport() {
        // Trojan（TCP+TLS）：nativeTLS 與指紋應傳入 TransportConfig
        var trojan = ProxyNode(name: "t", proto: .trojan, server: "x.com", port: 443)
        trojan.password = "pw"; trojan.tls = true
        let cfg = NativeEngineAdapter.transport(for: trojan, defaultTLS: true, nativeTLS: true, fingerprint: "chrome")
        XCTAssertTrue(cfg.nativeTLS)
        XCTAssertEqual(cfg.fingerprint, "chrome")
        XCTAssertEqual(cfg.network, .tcp)

        // 節點自帶 fp 優先於全域預設
        var withFP = trojan; withFP.fingerprint = "safari"
        XCTAssertEqual(NativeEngineAdapter.transport(for: withFP, defaultTLS: true, nativeTLS: true, fingerprint: "chrome").fingerprint, "safari")

        // 關閉時不啟用
        XCTAssertFalse(NativeEngineAdapter.transport(for: trojan, defaultTLS: true, nativeTLS: false, fingerprint: "chrome").nativeTLS)
    }

    func testDefaultNativeTLSEnabled() {
        // 依「開起來」的決定，AppSettings.nativeTLS 預設開；舊設定檔缺此鍵時也回 true
        XCTAssertTrue(AppSettings().nativeTLS)
        let legacy = "{}".data(using: .utf8)!
        let decoded = try? JSONDecoder().decode(AppSettings.self, from: legacy)
        XCTAssertEqual(decoded?.nativeTLS, true)
    }

    func testTransportWS() {
        var node = ProxyNode(name: "w", proto: .vless, server: "x", port: 443)
        node.network = "ws"; node.wsPath = "/p"; node.wsHost = "cdn.com"; node.tls = true
        let cfg = NativeEngineAdapter.transport(for: node, defaultTLS: true)
        XCTAssertEqual(cfg.network, .ws)
        XCTAssertEqual(cfg.wsPath, "/p")
        XCTAssertEqual(cfg.wsHost, "cdn.com")
        XCTAssertTrue(cfg.tls)
    }

    func testRouterFromRulesAndModes() {
        var r1 = UserRule(); r1.type = .domainSuffix; r1.value = "ads.com"; r1.policy = .reject
        var r2 = UserRule(); r2.type = .domainKeyword; r2.value = "google"; r2.policy = .proxy

        let ruleRouter = NativeEngineAdapter.makeRouter(proxy: DirectOutbound(), rules: [r1, r2], mode: .rule)
        XCTAssertEqual(ruleRouter.policy(for: Target(host: "x.ads.com", port: 443)), .reject)
        XCTAssertEqual(ruleRouter.policy(for: Target(host: "www.google.com", port: 443)), .proxy)
        XCTAssertEqual(ruleRouter.policy(for: Target(host: "other.net", port: 443)), .proxy) // final

        // 全域：忽略規則，全走 proxy
        let global = NativeEngineAdapter.makeRouter(proxy: DirectOutbound(), rules: [r1], mode: .global)
        XCTAssertEqual(global.policy(for: Target(host: "x.ads.com", port: 443)), .proxy)

        // 直連：全走 direct
        let direct = NativeEngineAdapter.makeRouter(proxy: DirectOutbound(), rules: [r1], mode: .direct)
        XCTAssertEqual(direct.policy(for: Target(host: "anything", port: 443)), .direct)
    }

    func testGeoRulesSkippedNotCrash() {
        var geo = UserRule(); geo.type = .geosite; geo.value = "netflix"; geo.policy = .proxy
        // 原生不支援 geosite，應略過而非崩潰，final = proxy
        let router = NativeEngineAdapter.makeRouter(proxy: DirectOutbound(), rules: [geo], mode: .rule)
        XCTAssertEqual(router.policy(for: Target(host: "netflix.com", port: 443)), .proxy)
    }
}
