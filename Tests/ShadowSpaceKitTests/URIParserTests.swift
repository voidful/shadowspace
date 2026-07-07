import XCTest
@testable import ShadowSpaceKit

final class URIParserTests: XCTestCase {

    // MARK: - Shadowsocks

    func testSSModern() {
        // SIP002: base64(method:password)@host:port#name
        let userinfo = Data("aes-256-gcm:test-password".utf8).base64EncodedString()
        let node = URIParser.parse("ss://\(userinfo)@1.2.3.4:8388#%E9%A6%99%E6%B8%AF%2001")
        XCTAssertNotNil(node)
        XCTAssertEqual(node?.proto, .shadowsocks)
        XCTAssertEqual(node?.server, "1.2.3.4")
        XCTAssertEqual(node?.port, 8388)
        XCTAssertEqual(node?.method, "aes-256-gcm")
        XCTAssertEqual(node?.password, "test-password")
        XCTAssertEqual(node?.name, "香港 01")
    }

    func testSSLegacy() {
        // 舊式: base64(method:password@host:port)
        let body = Data("rc4-md5:pass123@example.com:443".utf8).base64EncodedString()
        let node = URIParser.parse("ss://\(body)#legacy")
        XCTAssertEqual(node?.method, "rc4-md5")
        XCTAssertEqual(node?.password, "pass123")
        XCTAssertEqual(node?.server, "example.com")
        XCTAssertEqual(node?.port, 443)
    }

    // MARK: - VMess

    func testVMessWebSocketTLS() {
        let json = """
        {"v":"2","ps":"日本 WS","add":"jp.example.com","port":"443","id":"23ad6b10-8d1a-40f7-8ad0-e3e35cd38297","aid":0,"scy":"auto","net":"ws","host":"cdn.example.com","path":"/v2ray","tls":"tls","sni":"cdn.example.com"}
        """
        let encoded = Data(json.utf8).base64EncodedString()
        let node = URIParser.parse("vmess://\(encoded)")
        XCTAssertNotNil(node)
        XCTAssertEqual(node?.proto, .vmess)
        XCTAssertEqual(node?.name, "日本 WS")
        XCTAssertEqual(node?.port, 443) // 字串 port 也要能解析
        XCTAssertEqual(node?.uuid, "23ad6b10-8d1a-40f7-8ad0-e3e35cd38297")
        XCTAssertEqual(node?.network, "ws")
        XCTAssertEqual(node?.wsPath, "/v2ray")
        XCTAssertEqual(node?.wsHost, "cdn.example.com")
        XCTAssertEqual(node?.tls, true)
        XCTAssertEqual(node?.sni, "cdn.example.com")
    }

    func testVMessUnsupportedTransportSkipped() {
        let json = """
        {"ps":"kcp node","add":"1.1.1.1","port":443,"id":"x","net":"kcp"}
        """
        let encoded = Data(json.utf8).base64EncodedString()
        XCTAssertNil(URIParser.parse("vmess://\(encoded)"))
    }

    // MARK: - VLESS Reality

    func testVLESSReality() {
        let uri = "vless://9a4b2c33-1111-2222-3333-444455556666@hk.example.com:443?security=reality&pbk=PUBKEY123&sid=ab12&fp=chrome&type=tcp&flow=xtls-rprx-vision&sni=www.apple.com#HK%20Reality"
        let node = URIParser.parse(uri)
        XCTAssertNotNil(node)
        XCTAssertEqual(node?.proto, .vless)
        XCTAssertEqual(node?.uuid, "9a4b2c33-1111-2222-3333-444455556666")
        XCTAssertEqual(node?.tls, true)
        XCTAssertEqual(node?.realityPublicKey, "PUBKEY123")
        XCTAssertEqual(node?.realityShortID, "ab12")
        XCTAssertEqual(node?.fingerprint, "chrome")
        XCTAssertEqual(node?.flow, "xtls-rprx-vision")
        XCTAssertEqual(node?.sni, "www.apple.com")
        XCTAssertEqual(node?.name, "HK Reality")
    }

    // MARK: - Trojan

    func testTrojan() {
        let node = URIParser.parse("trojan://p%40ss@tw.example.com:443?sni=tw.example.com&allowInsecure=1#台灣")
        XCTAssertEqual(node?.proto, .trojan)
        XCTAssertEqual(node?.password, "p@ss") // percent-encoded 密碼
        XCTAssertEqual(node?.tls, true)
        XCTAssertEqual(node?.insecure, true)
        XCTAssertEqual(node?.name, "台灣") // 未編碼中文名稱也要能解析
    }

    // MARK: - Hysteria2

    func testHysteria2() {
        let node = URIParser.parse("hy2://auth-key@sg.example.com:443?sni=sg.example.com&insecure=1&obfs=salamander&obfs-password=ob123#SG")
        XCTAssertEqual(node?.proto, .hysteria2)
        XCTAssertEqual(node?.password, "auth-key")
        XCTAssertEqual(node?.obfs, "salamander")
        XCTAssertEqual(node?.obfsPassword, "ob123")
        XCTAssertEqual(node?.insecure, true)
    }

    // MARK: - TUIC

    func testTUIC() {
        let node = URIParser.parse("tuic://uuid-here:pass-here@us.example.com:443?congestion_control=bbr&alpn=h3&sni=us.example.com#US")
        XCTAssertEqual(node?.proto, .tuic)
        XCTAssertEqual(node?.uuid, "uuid-here")
        XCTAssertEqual(node?.password, "pass-here")
        XCTAssertEqual(node?.congestionControl, "bbr")
        XCTAssertEqual(node?.alpn, ["h3"])
    }

    // MARK: - IPv6

    func testIPv6Host() {
        let userinfo = Data("aes-128-gcm:pw".utf8).base64EncodedString()
        let node = URIParser.parse("ss://\(userinfo)@[2001:db8::1]:8388#v6")
        XCTAssertEqual(node?.server, "2001:db8::1")
        XCTAssertEqual(node?.port, 8388)
    }

    // MARK: - 批次解析

    func testClassifyMixedContent() {
        let userinfo = Data("aes-256-gcm:pw".utf8).base64EncodedString()
        let text = """
        ss://\(userinfo)@1.2.3.4:8388#node1
        https://airport.example.com/sub?token=abc
        trojan://pw@5.6.7.8:443#node2
        """
        let (nodes, subs, unparsed) = URIParser.classify(text)
        XCTAssertEqual(nodes.count, 2)
        XCTAssertEqual(subs, ["https://airport.example.com/sub?token=abc"])
        XCTAssertTrue(unparsed.isEmpty)
    }

    func testClassifyReportsUnparsedLines() {
        let text = """
        trojan://pw@5.6.7.8:443#ok
        這是一行亂貼的文字
        vmess://not-valid-base64
        """
        let (nodes, subs, unparsed) = URIParser.classify(text)
        XCTAssertEqual(nodes.count, 1)
        XCTAssertTrue(subs.isEmpty)
        XCTAssertEqual(unparsed.count, 2)   // 亂貼文字 + 壞掉的 vmess
    }

    func testBase64WrappedSubscription() {
        let userinfo = Data("chacha20-ietf-poly1305:pw".utf8).base64EncodedString()
        let plain = """
        ss://\(userinfo)@1.2.3.4:8388#a
        trojan://pw@5.6.7.8:443#b
        """
        // 模擬訂閱回應：整段 base64（無 padding 也要能解）
        let wrapped = Data(plain.utf8).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
        let nodes = URIParser.parseMultiple(wrapped)
        XCTAssertEqual(nodes.count, 2)
        XCTAssertEqual(nodes[0].name, "a")
        XCTAssertEqual(nodes[1].proto, .trojan)
    }

    // MARK: - insecure 別名統一

    func testHysteria2AcceptsAllowInsecureAlias() {
        // 過去 hy2 只認 insecure，收不到 allowInsecure/allow_insecure——已統一。
        XCTAssertEqual(URIParser.parse("hysteria2://pw@a.com:443?allowInsecure=1#h")?.insecure, true)
        XCTAssertEqual(URIParser.parse("hysteria2://pw@a.com:443?allow_insecure=1#h")?.insecure, true)
        XCTAssertEqual(URIParser.parse("hysteria2://pw@a.com:443?insecure=1#h")?.insecure, true)
        XCTAssertEqual(URIParser.parse("hysteria2://pw@a.com:443#h")?.insecure, false)
    }

    func testVLESSAcceptsAllInsecureAliases() {
        XCTAssertEqual(URIParser.parse("vless://uuid@a.com:443?security=tls&allow_insecure=1#v")?.insecure, true)
        XCTAssertEqual(URIParser.parse("vless://uuid@a.com:443?security=tls&insecure=true#v")?.insecure, true)
    }

    // MARK: - Base64 工具

    func testBase64URLSafeNoPadding() {
        // "ab?cd>ef" 編碼後含 +/，轉成 URL-safe 再解
        let original = "subject?>data"
        let std = Data(original.utf8).base64EncodedString()
        let urlSafe = std
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
        XCTAssertEqual(Base64Util.decodeString(urlSafe), original)
    }
}
