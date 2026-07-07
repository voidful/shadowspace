import Foundation

/// 解析 Clash / Clash.Meta 訂閱 YAML 的 `proxies:` 區塊 → [ProxyNode]。
///
/// 不引入第三方 YAML 函式庫；針對 Clash proxies 的規則結構做極簡子集解析：
/// 支援區塊式（縮排）與流式（`{a: 1, b: 2}`）兩種寫法、巢狀 map（ws-opts / reality-opts…）、
/// 區塊與流式序列（alpn）。支援協議：ss / vmess / vless / trojan / socks5 / hysteria2 / tuic。
enum ClashYAMLParser {

    /// 看起來是不是 Clash 設定（含頂層 proxies:）。
    static func looksLikeConfig(_ text: String) -> Bool {
        text.range(of: #"(?m)^\s*proxies\s*:"#, options: .regularExpression) != nil
    }

    static func parse(_ text: String) -> [ProxyNode] {
        proxyMaps(text).compactMap(node(from:))
    }

    // MARK: - 取出 proxies: 底下每個 proxy 的 mapping

    private static func proxyMaps(_ text: String) -> [[String: Any]] {
        // 預處理：拆行、去 \r、去整行與行內註解、記錄縮排
        var lines: [(indent: Int, text: String)] = []
        for raw in text.replacingOccurrences(of: "\r", with: "").split(separator: "\n", omittingEmptySubsequences: false).map(String.init) {
            let indent = raw.prefix(while: { $0 == " " }).count
            let body = stripInlineComment(raw.trimmingCharacters(in: .whitespaces))
            if body.isEmpty || body.hasPrefix("#") { continue }
            lines.append((indent, body))
        }
        guard let start = lines.firstIndex(where: { $0.text.hasPrefix("proxies:") }) else { return [] }
        let proxiesIndent = lines[start].indent

        // 收集 proxies 區塊並切成一個個 item（以同縮排的 "- " 為界）
        var items: [[(indent: Int, text: String)]] = []
        var current: [(indent: Int, text: String)] = []
        var itemIndent = -1
        var i = start + 1
        while i < lines.count {
            let line = lines[i]
            if line.indent <= proxiesIndent { break }            // 離開 proxies 區塊
            if line.text.hasPrefix("- ") || line.text == "-" {
                if itemIndent == -1 { itemIndent = line.indent }
                if line.indent == itemIndent {
                    if !current.isEmpty { items.append(current); current = [] }
                    let after = String(line.text.dropFirst(line.text.hasPrefix("- ") ? 2 : 1))
                        .trimmingCharacters(in: .whitespaces)
                    if !after.isEmpty { current.append((line.indent + 2, after)) }   // "- key: v" / "- {…}"
                    i += 1
                    continue
                }
            }
            current.append(line)
            i += 1
        }
        if !current.isEmpty { items.append(current) }

        return items.map { item in
            var idx = 0
            return parseMapping(item, &idx, indent: item.first?.indent ?? 0)
        }
    }

    // MARK: - 縮排 mapping 解析（遞迴）

    private static func parseMapping(_ lines: [(indent: Int, text: String)],
                                     _ i: inout Int, indent: Int) -> [String: Any] {
        var map: [String: Any] = [:]
        while i < lines.count {
            let line = lines[i]
            if line.indent < indent { break }
            if line.indent > indent { i += 1; continue }         // 防呆：跳過更深的孤兒行
            if line.text.hasPrefix("{") {                        // 流式整筆
                for (k, v) in parseFlowMap(line.text) { map[k] = v }
                i += 1
                continue
            }
            guard let (key, value) = splitKeyColon(line.text) else { i += 1; continue }
            if !value.isEmpty {
                map[key] = scalar(value)
                i += 1
                continue
            }
            // 空值 → 巢狀 mapping 或區塊序列
            i += 1
            guard i < lines.count, lines[i].indent > indent else { map[key] = ""; continue }
            let childIndent = lines[i].indent
            if lines[i].text.hasPrefix("- ") {
                var list: [String] = []
                while i < lines.count, lines[i].indent == childIndent, lines[i].text.hasPrefix("- ") {
                    list.append(unquote(String(lines[i].text.dropFirst(2)).trimmingCharacters(in: .whitespaces)))
                    i += 1
                }
                map[key] = list
            } else {
                map[key] = parseMapping(lines, &i, indent: childIndent)
            }
        }
        return map
    }

    // MARK: - 純量 / 流式 map / 流式 list

    private static func scalar(_ raw: String) -> Any {
        if raw.hasPrefix("[") { return parseFlowList(raw) }
        if raw.hasPrefix("{") { return parseFlowMap(raw) }
        return unquote(raw)
    }

    private static func parseFlowMap(_ raw: String) -> [String: Any] {
        let s = raw.trimmingCharacters(in: .whitespaces)
        guard s.hasPrefix("{"), s.hasSuffix("}") else { return [:] }
        var map: [String: Any] = [:]
        for piece in splitTopLevel(String(s.dropFirst().dropLast()), sep: ",") {
            if let (k, v) = splitKeyColon(piece.trimmingCharacters(in: .whitespaces)) { map[k] = scalar(v) }
        }
        return map
    }

    private static func parseFlowList(_ raw: String) -> [String] {
        let s = raw.trimmingCharacters(in: .whitespaces)
        guard s.hasPrefix("["), s.hasSuffix("]") else { return [] }
        return splitTopLevel(String(s.dropFirst().dropLast()), sep: ",")
            .map { unquote($0.trimmingCharacters(in: .whitespaces)) }
            .filter { !$0.isEmpty }
    }

    /// 以分隔字元切，但略過引號內與 {}/[] 巢狀內的分隔字元。
    private static func splitTopLevel(_ s: String, sep: Character) -> [String] {
        var result: [String] = []
        var depth = 0
        var inQuote: Character?
        var current = ""
        for ch in s {
            if let q = inQuote {
                if ch == q { inQuote = nil }
                current.append(ch); continue
            }
            switch ch {
            case "\"", "'": inQuote = ch; current.append(ch)
            case "{", "[": depth += 1; current.append(ch)
            case "}", "]": depth -= 1; current.append(ch)
            case sep where depth == 0: result.append(current); current = ""
            default: current.append(ch)
            }
        }
        if !current.trimmingCharacters(in: .whitespaces).isEmpty { result.append(current) }
        return result
    }

    private static func splitKeyColon(_ text: String) -> (key: String, value: String)? {
        guard let colon = text.firstIndex(of: ":") else { return nil }
        let key = unquote(String(text[..<colon]).trimmingCharacters(in: .whitespaces))
        let value = String(text[text.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
        return key.isEmpty ? nil : (key, value)
    }

    private static func unquote(_ s: String) -> String {
        let v = s.trimmingCharacters(in: .whitespaces)
        guard v.count >= 2, let f = v.first, let l = v.last, f == l, f == "\"" || f == "'" else { return v }
        return String(v.dropFirst().dropLast())
    }

    private static func stripInlineComment(_ s: String) -> String {
        var inQuote: Character?
        var prev: Character = " "
        var result = ""
        for ch in s {
            if let q = inQuote {
                if ch == q { inQuote = nil }
                result.append(ch); prev = ch; continue
            }
            if ch == "\"" || ch == "'" { inQuote = ch; result.append(ch); prev = ch; continue }
            if ch == "#", prev == " " { break }
            result.append(ch); prev = ch
        }
        return result.trimmingCharacters(in: .whitespaces)
    }

    // MARK: - mapping → ProxyNode

    private static func node(from m: [String: Any]) -> ProxyNode? {
        guard let type = str(m, "type")?.lowercased(),
              let server = str(m, "server"),
              let port = int(m, "port"), port > 0 else { return nil }
        let name = str(m, "name") ?? "\(server):\(port)"

        switch type {
        case "ss":
            var node = ProxyNode(name: name, proto: .shadowsocks, server: server, port: port)
            node.method = str(m, "cipher") ?? "aes-256-gcm"
            node.password = str(m, "password") ?? ""
            return node

        case "trojan":
            var node = ProxyNode(name: name, proto: .trojan, server: server, port: port)
            node.password = str(m, "password") ?? ""
            node.tls = true
            node.sni = str(m, "sni") ?? str(m, "servername")
            node.insecure = bool(m, "skip-cert-verify")
            node.alpn = list(m, "alpn")
            node.fingerprint = str(m, "client-fingerprint")
            applyTransport(&node, m)
            return node

        case "vmess":
            var node = ProxyNode(name: name, proto: .vmess, server: server, port: port)
            node.uuid = str(m, "uuid")
            node.alterId = int(m, "alterId") ?? 0
            node.security = str(m, "cipher") ?? "auto"
            node.tls = bool(m, "tls")
            node.sni = str(m, "servername") ?? str(m, "sni")
            node.insecure = bool(m, "skip-cert-verify")
            node.alpn = list(m, "alpn")
            node.fingerprint = str(m, "client-fingerprint")
            applyTransport(&node, m)
            return node

        case "vless":
            var node = ProxyNode(name: name, proto: .vless, server: server, port: port)
            node.uuid = str(m, "uuid")
            node.tls = bool(m, "tls")
            node.sni = str(m, "servername") ?? str(m, "sni")
            node.insecure = bool(m, "skip-cert-verify")
            node.flow = str(m, "flow")
            node.alpn = list(m, "alpn")
            node.fingerprint = str(m, "client-fingerprint")
            if let reality = map(m, "reality-opts") {
                node.tls = true
                node.realityPublicKey = str(reality, "public-key")
                node.realityShortID = str(reality, "short-id")
            }
            applyTransport(&node, m)
            return node

        case "socks5", "socks":
            var node = ProxyNode(name: name, proto: .socks, server: server, port: port)
            node.username = str(m, "username")
            node.password = str(m, "password")
            return node

        case "anytls":
            var node = ProxyNode(name: name, proto: .anytls, server: server, port: port)
            node.password = str(m, "password") ?? ""
            node.tls = true
            node.sni = str(m, "sni") ?? str(m, "servername")
            node.insecure = bool(m, "skip-cert-verify")
            node.alpn = list(m, "alpn")
            node.fingerprint = str(m, "client-fingerprint")
            return node

        case "hysteria2", "hy2":
            var node = ProxyNode(name: name, proto: .hysteria2, server: server, port: port)
            node.password = str(m, "password") ?? str(m, "auth") ?? ""
            node.tls = true
            node.sni = str(m, "sni")
            node.insecure = bool(m, "skip-cert-verify")
            if let obfs = str(m, "obfs") {
                node.obfs = obfs
                node.obfsPassword = str(m, "obfs-password")
            }
            return node

        case "tuic":
            var node = ProxyNode(name: name, proto: .tuic, server: server, port: port)
            node.uuid = str(m, "uuid")
            node.password = str(m, "password")
            node.tls = true
            node.sni = str(m, "sni")
            node.insecure = bool(m, "skip-cert-verify")
            node.congestionControl = str(m, "congestion-controller")
            node.alpn = list(m, "alpn")
            return node

        default:
            return nil   // ssr / snell 等暫不支援，略過
        }
    }

    private static func applyTransport(_ node: inout ProxyNode, _ m: [String: Any]) {
        switch (str(m, "network") ?? "tcp").lowercased() {
        case "ws":
            node.network = "ws"
            if let ws = map(m, "ws-opts") {
                node.wsPath = str(ws, "path") ?? "/"
                if let headers = map(ws, "headers") { node.wsHost = str(headers, "Host") ?? str(headers, "host") }
            } else {
                node.wsPath = "/"
            }
        case "grpc":
            node.network = "grpc"
            if let g = map(m, "grpc-opts") { node.grpcServiceName = str(g, "grpc-service-name") }
        case "h2", "http":
            node.network = "http"
            if let h = map(m, "h2-opts") ?? map(m, "http-opts") {
                node.wsPath = str(h, "path")
                node.wsHost = (h["host"] as? [String])?.first ?? str(h, "host")
            }
        default:
            break   // tcp
        }
    }

    // MARK: - 取值小工具

    private static func str(_ m: [String: Any], _ k: String) -> String? {
        guard let s = m[k] as? String, !s.isEmpty else { return nil }
        return s
    }
    private static func int(_ m: [String: Any], _ k: String) -> Int? {
        guard let s = m[k] as? String else { return nil }
        return Int(s.prefix(while: \.isNumber))
    }
    private static func bool(_ m: [String: Any], _ k: String) -> Bool {
        guard let s = m[k] as? String else { return false }
        return ["true", "1", "yes"].contains(s.lowercased())
    }
    private static func map(_ m: [String: Any], _ k: String) -> [String: Any]? {
        m[k] as? [String: Any]
    }
    private static func list(_ m: [String: Any], _ k: String) -> [String]? {
        guard let a = m[k] as? [String], !a.isEmpty else { return nil }
        return a
    }
}
