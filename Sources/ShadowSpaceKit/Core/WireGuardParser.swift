import Foundation

/// 解析 WireGuard `.conf`（INI 格式）。WireGuard 沒有通用分享 URI，使用者貼的是設定檔內容：
///
///     [Interface]
///     PrivateKey = ...
///     Address = 10.0.0.2/32, fd00::2/128
///     MTU = 1420
///     [Peer]
///     PublicKey = ...
///     PresharedKey = ...        (可選)
///     Endpoint = host:port
///     AllowedIPs = 0.0.0.0/0, ::/0
enum WireGuardParser {

    static func looksLikeConfig(_ text: String) -> Bool {
        let lower = text.lowercased()
        return lower.contains("[interface]") && lower.contains("[peer]")
    }

    static func parse(_ text: String, name: String? = nil) -> ProxyNode? {
        var section = ""
        var iface: [String: String] = [:]
        var peer: [String: String] = [:]
        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line.hasPrefix("[") {
                section = line.lowercased()
                continue
            }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            if section == "[interface]" { iface[key] = value }
            else if section == "[peer]" { peer[key] = value }
        }

        guard let priv = iface["privatekey"], !priv.isEmpty,
              let pub = peer["publickey"], !pub.isEmpty,
              let endpoint = peer["endpoint"],
              let colon = endpoint.lastIndex(of: ":"),
              let port = Int(endpoint[endpoint.index(after: colon)...]) else { return nil }

        var node = ProxyNode(name: name ?? "WireGuard",
                             proto: .wireguard,
                             server: String(endpoint[..<colon]),
                             port: port)
        node.wgPrivateKey = priv
        node.wgPeerPublicKey = pub
        node.wgPresharedKey = peer["presharedkey"]
        if let addr = iface["address"] {
            node.wgLocalAddress = addr.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        if let mtu = iface["mtu"], let m = Int(mtu) { node.wgMTU = m }
        return node
    }
}
