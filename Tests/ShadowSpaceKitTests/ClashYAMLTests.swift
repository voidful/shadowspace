import XCTest
@testable import ShadowSpaceKit

final class ClashYAMLTests: XCTestCase {

    // 混合 block 式與 flow 式、含巢狀 ws-opts / reality-opts / 流式 alpn 與行內註解
    private let sample = """
    port: 7890
    mode: rule
    proxies:
      - name: "🇭🇰 HK 01"
        type: ss
        server: hk.example.com
        port: 8388
        cipher: aes-256-gcm
        password: "p@ss:word"   # 含冒號的密碼
      - name: JP-VMess
        type: vmess
        server: jp.example.com
        port: 443
        uuid: 11111111-2222-3333-4444-555555555555
        alterId: 0
        cipher: auto
        tls: true
        servername: cdn.jp.com
        network: ws
        ws-opts:
          path: /vmessws
          headers:
            Host: cdn.jp.com
      - { name: TW-Trojan, type: trojan, server: tw.example.com, port: 443, password: trojanpw, sni: tw.example.com, skip-cert-verify: true, alpn: [h2, http/1.1] }
      - name: US-VLESS-Reality
        type: vless
        server: us.example.com
        port: 443
        uuid: aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
        network: tcp
        tls: true
        servername: www.microsoft.com
        flow: xtls-rprx-vision
        reality-opts:
          public-key: PUBKEY123
          short-id: "abcd"
      - name: SG-Hysteria2
        type: hysteria2
        server: sg.example.com
        port: 8443
        password: hy2pw
        sni: sg.example.com
        skip-cert-verify: true
    proxy-groups:
      - name: PROXY
        type: select
        proxies: [HK 01, JP-VMess]
    rules:
      - MATCH,PROXY
    """

    func testParsesAllSupportedProtocols() {
        let nodes = ClashYAMLParser.parse(sample)
        XCTAssertEqual(nodes.count, 5, "應解析出 5 個節點，實得 \(nodes.map(\.name))")
    }

    func testShadowsocksWithColonPassword() {
        let ss = ClashYAMLParser.parse(sample).first { $0.proto == .shadowsocks }
        XCTAssertNotNil(ss)
        XCTAssertEqual(ss?.name, "🇭🇰 HK 01")
        XCTAssertEqual(ss?.server, "hk.example.com")
        XCTAssertEqual(ss?.port, 8388)
        XCTAssertEqual(ss?.method, "aes-256-gcm")
        XCTAssertEqual(ss?.password, "p@ss:word")   // 冒號與行內註解都要正確處理
    }

    func testVMessWebSocketNested() {
        let vmess = ClashYAMLParser.parse(sample).first { $0.proto == .vmess }
        XCTAssertEqual(vmess?.uuid, "11111111-2222-3333-4444-555555555555")
        XCTAssertEqual(vmess?.tls, true)
        XCTAssertEqual(vmess?.sni, "cdn.jp.com")
        XCTAssertEqual(vmess?.network, "ws")
        XCTAssertEqual(vmess?.wsPath, "/vmessws")
        XCTAssertEqual(vmess?.wsHost, "cdn.jp.com")   // ws-opts.headers.Host
    }

    func testTrojanFlowStyleWithAlpn() {
        let trojan = ClashYAMLParser.parse(sample).first { $0.proto == .trojan }
        XCTAssertEqual(trojan?.name, "TW-Trojan")
        XCTAssertEqual(trojan?.password, "trojanpw")
        XCTAssertEqual(trojan?.sni, "tw.example.com")
        XCTAssertEqual(trojan?.insecure, true)
        XCTAssertEqual(trojan?.alpn ?? [], ["h2", "http/1.1"])
    }

    func testVLESSRealityVision() {
        let vless = ClashYAMLParser.parse(sample).first { $0.proto == .vless }
        XCTAssertEqual(vless?.uuid, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        XCTAssertEqual(vless?.flow, "xtls-rprx-vision")
        XCTAssertEqual(vless?.sni, "www.microsoft.com")
        XCTAssertEqual(vless?.realityPublicKey, "PUBKEY123")
        XCTAssertEqual(vless?.realityShortID, "abcd")
    }

    func testHysteria2() {
        let hy2 = ClashYAMLParser.parse(sample).first { $0.proto == .hysteria2 }
        XCTAssertEqual(hy2?.password, "hy2pw")
        XCTAssertEqual(hy2?.port, 8443)
        XCTAssertEqual(hy2?.insecure, true)
    }

    func testLooksLikeConfig() {
        XCTAssertTrue(ClashYAMLParser.looksLikeConfig(sample))
        XCTAssertFalse(ClashYAMLParser.looksLikeConfig("vmess://abc\nss://def"))
        XCTAssertFalse(ClashYAMLParser.looksLikeConfig("{\"outbounds\": []}"))
    }

    func testIgnoresUnsupportedProtocols() {
        let yaml = """
        proxies:
          - name: snell-node
            type: snell
            server: x.com
            port: 443
            psk: abc
          - name: good-ss
            type: ss
            server: y.com
            port: 8388
            cipher: chacha20-ietf-poly1305
            password: pw
        """
        let nodes = ClashYAMLParser.parse(yaml)
        XCTAssertEqual(nodes.count, 1)          // snell 跳過，只留 ss
        XCTAssertEqual(nodes.first?.proto, .shadowsocks)
    }
}
