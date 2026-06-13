import Foundation
import AppKit
import CoreImage

/// 把節點轉回分享連結（URIParser 的反向），以及產生 QR Code。
enum NodeShare {

    private static func encodeComponent(_ s: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-._~"))
        return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? s
    }

    private static func hostPart(_ node: ProxyNode) -> String {
        node.server.contains(":") ? "[\(node.server)]" : node.server
    }

    private static func queryString(_ items: [(String, String?)]) -> String {
        let pairs = items.compactMap { key, value -> String? in
            guard let value, !value.isEmpty else { return nil }
            return "\(key)=\(encodeComponent(value))"
        }
        return pairs.isEmpty ? "" : "?" + pairs.joined(separator: "&")
    }

    static func uri(for node: ProxyNode) -> String? {
        let name = "#" + encodeComponent(node.name)
        let host = hostPart(node)
        switch node.proto {
        case .shadowsocks:
            let userinfo = Data("\(node.method ?? "aes-256-gcm"):\(node.password ?? "")".utf8)
                .base64EncodedString()
            return "ss://\(userinfo)@\(host):\(node.port)\(name)"

        case .vmess:
            var json: [String: Any] = [
                "v": "2",
                "ps": node.name,
                "add": node.server,
                "port": "\(node.port)",
                "id": node.uuid ?? "",
                "aid": "\(node.alterId ?? 0)",
                "scy": node.security ?? "auto",
                "net": vmessNet(node.network),
                "type": "none",
                "tls": node.tls ? "tls" : "",
            ]
            if let sni = node.sni { json["sni"] = sni }
            if let fp = node.fingerprint { json["fp"] = fp }
            if let alpn = node.alpn { json["alpn"] = alpn.joined(separator: ",") }
            switch node.network {
            case "ws", "http":
                json["path"] = node.wsPath ?? "/"
                if let h = node.wsHost { json["host"] = h }
            case "grpc":
                json["path"] = node.grpcServiceName ?? ""
            default: break
            }
            guard let data = try? JSONSerialization.data(withJSONObject: json, options: [.sortedKeys]) else {
                return nil
            }
            return "vmess://" + data.base64EncodedString()

        case .vless:
            var items: [(String, String?)] = [("encryption", "none")]
            if node.realityPublicKey?.isEmpty == false {
                items.append(("security", "reality"))
                items.append(("pbk", node.realityPublicKey))
                items.append(("sid", node.realityShortID))
            } else if node.tls {
                items.append(("security", "tls"))
            } else {
                items.append(("security", "none"))
            }
            items.append(("sni", node.sni))
            items.append(("fp", node.fingerprint))
            items.append(("flow", node.flow))
            if node.insecure { items.append(("allowInsecure", "1")) }
            items.append(contentsOf: transportItems(node))
            return "vless://\(node.uuid ?? "")@\(host):\(node.port)\(queryString(items))\(name)"

        case .trojan:
            var items: [(String, String?)] = [("sni", node.sni), ("fp", node.fingerprint)]
            if node.insecure { items.append(("allowInsecure", "1")) }
            items.append(contentsOf: transportItems(node))
            return "trojan://\(encodeComponent(node.password ?? ""))@\(host):\(node.port)\(queryString(items))\(name)"

        case .hysteria2:
            var items: [(String, String?)] = [("sni", node.sni)]
            if node.insecure { items.append(("insecure", "1")) }
            items.append(("obfs", node.obfs))
            items.append(("obfs-password", node.obfsPassword))
            return "hysteria2://\(encodeComponent(node.password ?? ""))@\(host):\(node.port)\(queryString(items))\(name)"

        case .tuic:
            var items: [(String, String?)] = [
                ("sni", node.sni),
                ("congestion_control", node.congestionControl),
                ("alpn", node.alpn?.joined(separator: ",")),
            ]
            if node.insecure { items.append(("allow_insecure", "1")) }
            return "tuic://\(encodeComponent(node.uuid ?? "")):\(encodeComponent(node.password ?? ""))@\(host):\(node.port)\(queryString(items))\(name)"

        case .anytls:
            var items: [(String, String?)] = [("sni", node.sni)]
            if node.insecure { items.append(("allowInsecure", "1")) }
            if let alpn = node.alpn, !alpn.isEmpty { items.append(("alpn", alpn.joined(separator: ","))) }
            return "anytls://\(encodeComponent(node.password ?? ""))@\(host):\(node.port)\(queryString(items))\(name)"

        case .socks:
            if let user = node.username {
                let userinfo = Data("\(user):\(node.password ?? "")".utf8).base64EncodedString()
                return "socks://\(userinfo)@\(host):\(node.port)\(name)"
            }
            return "socks://\(host):\(node.port)\(name)"
        case .wireguard:
            return nil   // WireGuard 用設定檔，無分享連結
        }
    }

    private static func vmessNet(_ network: String?) -> String {
        switch network {
        case "ws": return "ws"
        case "grpc": return "grpc"
        case "http": return "h2"
        default: return "tcp"
        }
    }

    private static func transportItems(_ node: ProxyNode) -> [(String, String?)] {
        switch node.network {
        case "ws":
            return [("type", "ws"), ("path", node.wsPath), ("host", node.wsHost)]
        case "grpc":
            return [("type", "grpc"), ("serviceName", node.grpcServiceName)]
        case "http":
            return [("type", "http"), ("path", node.wsPath), ("host", node.wsHost)]
        default:
            return []
        }
    }

    // MARK: - QR Code

    static func qrImage(for string: String, side: CGFloat = 240) -> NSImage? {
        guard let filter = CIFilter(name: "CIQRCodeGenerator") else { return nil }
        filter.setValue(Data(string.utf8), forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")
        guard let output = filter.outputImage else { return nil }
        let scale = side / output.extent.width
        let scaled = output.transformed(by: CGAffineTransform(scaleX: scale, y: scale))
        let rep = NSCIImageRep(ciImage: scaled)
        let image = NSImage(size: rep.size)
        image.addRepresentation(rep)
        return image
    }
}
