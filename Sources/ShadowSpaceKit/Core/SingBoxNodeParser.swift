import Foundation

/// 反解析 sing-box 訂閱回傳的 JSON 設定，抽出節點（SingBoxConfigBuilder.outbound 的逆向）。
/// 機場面對 `sing-box` User-Agent 多半回傳完整 JSON config（outbounds + endpoints）。
enum SingBoxNodeParser {

    static func looksLikeConfig(_ text: String) -> Bool {
        let t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard t.hasPrefix("{") else { return false }
        return t.contains("\"outbounds\"") || t.contains("\"endpoints\"")
    }

    static func parse(_ data: Data) -> [ProxyNode] {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return [] }
        var nodes: [ProxyNode] = []
        for ob in (obj["outbounds"] as? [[String: Any]]) ?? [] {
            if let node = parseOutbound(ob) { nodes.append(node) }
        }
        for ep in (obj["endpoints"] as? [[String: Any]]) ?? [] {
            if let node = parseWireGuard(ep) { nodes.append(node) }
        }
        return nodes
    }

    // MARK: - 單一 outbound

    private static func parseOutbound(_ ob: [String: Any]) -> ProxyNode? {
        guard let type = ob["type"] as? String,
              let server = ob["server"] as? String,
              let port = intValue(ob, "server_port") else { return nil }
        let name = (ob["tag"] as? String) ?? "\(server):\(port)"

        let proto: NodeProtocol
        switch type {
        case "shadowsocks": proto = .shadowsocks
        case "vmess": proto = .vmess
        case "vless": proto = .vless
        case "trojan": proto = .trojan
        case "hysteria2": proto = .hysteria2
        case "tuic": proto = .tuic
        case "socks": proto = .socks
        default: return nil   // selector/urltest/direct/block/dns 等不是節點
        }
        var node = ProxyNode(name: name, proto: proto, server: server, port: port)

        switch proto {
        case .shadowsocks:
            node.method = ob["method"] as? String
            node.password = ob["password"] as? String
        case .vmess:
            node.uuid = ob["uuid"] as? String
            node.alterId = intValue(ob, "alter_id")
            node.security = ob["security"] as? String
        case .vless:
            node.uuid = ob["uuid"] as? String
            node.flow = ob["flow"] as? String
        case .trojan:
            node.password = ob["password"] as? String
        case .hysteria2:
            node.password = ob["password"] as? String
            if let obfs = ob["obfs"] as? [String: Any] {
                node.obfs = obfs["type"] as? String
                node.obfsPassword = obfs["password"] as? String
            }
        case .tuic:
            node.uuid = ob["uuid"] as? String
            node.password = ob["password"] as? String
            node.congestionControl = ob["congestion_control"] as? String
        case .socks:
            node.username = ob["username"] as? String
            node.password = ob["password"] as? String
        case .wireguard:
            break
        }

        if let tls = ob["tls"] as? [String: Any], (tls["enabled"] as? Bool) == true {
            node.tls = true
            node.sni = tls["server_name"] as? String
            node.insecure = (tls["insecure"] as? Bool) ?? false
            node.alpn = tls["alpn"] as? [String]
            if let utls = tls["utls"] as? [String: Any] {
                node.fingerprint = utls["fingerprint"] as? String
            }
            if let reality = tls["reality"] as? [String: Any], (reality["enabled"] as? Bool) == true {
                node.realityPublicKey = reality["public_key"] as? String
                node.realityShortID = reality["short_id"] as? String
            }
        }

        if let tr = ob["transport"] as? [String: Any], let ttype = tr["type"] as? String {
            switch ttype {
            case "ws":
                node.network = "ws"
                node.wsPath = tr["path"] as? String
                if let headers = tr["headers"] as? [String: Any] { node.wsHost = headers["Host"] as? String }
            case "grpc":
                node.network = "grpc"
                node.grpcServiceName = tr["service_name"] as? String
            case "http":
                node.network = "http"
                node.wsPath = tr["path"] as? String
                if let host = tr["host"] as? [String] { node.wsHost = host.first }
            default:
                break
            }
        }
        return node
    }

    private static func parseWireGuard(_ ep: [String: Any]) -> ProxyNode? {
        guard (ep["type"] as? String) == "wireguard",
              let peers = ep["peers"] as? [[String: Any]], let peer = peers.first,
              let server = peer["address"] as? String,
              let port = intValue(peer, "port") else { return nil }
        var node = ProxyNode(name: (ep["tag"] as? String) ?? "WireGuard",
                             proto: .wireguard, server: server, port: port)
        node.wgPrivateKey = ep["private_key"] as? String
        node.wgPeerPublicKey = peer["public_key"] as? String
        node.wgPresharedKey = peer["pre_shared_key"] as? String
        node.wgLocalAddress = ep["address"] as? [String]
        node.wgMTU = intValue(ep, "mtu")
        return node
    }

    private static func intValue(_ d: [String: Any], _ key: String) -> Int? {
        if let i = d[key] as? Int { return i }
        if let s = d[key] as? String { return Int(s) }
        return nil
    }
}
