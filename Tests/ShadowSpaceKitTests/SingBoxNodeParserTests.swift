import XCTest
@testable import ShadowSpaceKit

final class SingBoxNodeParserTests: XCTestCase {

    let json = """
    {
      "outbounds": [
        {"type":"selector","tag":"PROXY","outbounds":["vless-04"]},
        {"type":"direct","tag":"direct"},
        {"type":"vless","tag":"vless-04","server":"sl.t2.lol","server_port":443,
         "uuid":"ab8fb17b-40b1-4f89-899c-2a7317c9ab44",
         "tls":{"enabled":true,"server_name":"sl.t2.lol"},
         "transport":{"type":"ws","path":"/vless-cf","headers":{"Host":"sl.t2.lol"}}},
        {"type":"shadowsocks","tag":"ss1","server":"1.2.3.4","server_port":8388,
         "method":"aes-256-gcm","password":"pw"},
        {"type":"trojan","tag":"tj","server":"x.com","server_port":443,"password":"tjpw",
         "tls":{"enabled":true,"server_name":"x.com","insecure":true}}
      ],
      "endpoints": [
        {"type":"wireguard","tag":"wg","address":["10.0.0.2/32"],"private_key":"PRIV","mtu":1420,
         "peers":[{"address":"wg.example.com","port":51820,"public_key":"PUB"}]}
      ]
    }
    """

    func testLooksLikeConfig() {
        XCTAssertTrue(SingBoxNodeParser.looksLikeConfig(json))
        XCTAssertFalse(SingBoxNodeParser.looksLikeConfig("ss://abc@1.2.3.4:8388"))
        XCTAssertFalse(SingBoxNodeParser.looksLikeConfig("vless://x@y:443"))
    }

    func testParseVlessWS() {
        let vless = SingBoxNodeParser.parse(Data(json.utf8)).first { $0.proto == .vless }
        XCTAssertEqual(vless?.name, "vless-04")
        XCTAssertEqual(vless?.server, "sl.t2.lol")
        XCTAssertEqual(vless?.port, 443)
        XCTAssertEqual(vless?.uuid, "ab8fb17b-40b1-4f89-899c-2a7317c9ab44")
        XCTAssertEqual(vless?.tls, true)
        XCTAssertEqual(vless?.sni, "sl.t2.lol")
        XCTAssertEqual(vless?.network, "ws")
        XCTAssertEqual(vless?.wsPath, "/vless-cf")
        XCTAssertEqual(vless?.wsHost, "sl.t2.lol")
    }

    func testParseAllAndSkipsNonNodes() {
        let nodes = SingBoxNodeParser.parse(Data(json.utf8))
        XCTAssertEqual(nodes.count, 4)                       // vless/ss/trojan/wg；selector/direct 排除
        XCTAssertNil(nodes.first { $0.name == "PROXY" })
        XCTAssertNil(nodes.first { $0.name == "direct" })

        let ss = nodes.first { $0.proto == .shadowsocks }
        XCTAssertEqual(ss?.method, "aes-256-gcm")
        XCTAssertEqual(ss?.password, "pw")

        let tj = nodes.first { $0.proto == .trojan }
        XCTAssertEqual(tj?.password, "tjpw")
        XCTAssertEqual(tj?.insecure, true)

        let wg = nodes.first { $0.proto == .wireguard }
        XCTAssertEqual(wg?.server, "wg.example.com")
        XCTAssertEqual(wg?.port, 51820)
        XCTAssertEqual(wg?.wgPrivateKey, "PRIV")
        XCTAssertEqual(wg?.wgPeerPublicKey, "PUB")
        XCTAssertEqual(wg?.wgMTU, 1420)
    }

    func testEmptyForNonConfig() {
        XCTAssertTrue(SingBoxNodeParser.parse(Data("not json".utf8)).isEmpty)
    }
}
