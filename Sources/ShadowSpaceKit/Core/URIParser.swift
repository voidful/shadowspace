import Foundation

/// 解析 Shadowrocket 風格的分享連結：
/// ss:// vmess:// vless:// trojan:// hysteria2:// (hy2://) tuic:// socks://
/// 以及 base64 包裝的多行訂閱內容。
enum URIParser {

    // MARK: - URI 結構

    struct URIParts {
        var scheme: String
        var userinfo: String?
        var host: String = ""
        var port: Int = 0
        var path: String?
        var query: [String: String] = [:]
        var fragment: String?
    }

    /// 手動拆解 URI。分享連結常含未編碼的中文名稱或特殊字元，
    /// URLComponents 會直接解析失敗，所以自己處理。
    static func splitURI(_ raw: String) -> URIParts? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let schemeRange = s.range(of: "://") else { return nil }
        let scheme = String(s[..<schemeRange.lowerBound]).lowercased()
        var rest = String(s[schemeRange.upperBound...])
        var parts = URIParts(scheme: scheme)

        if let hash = rest.firstIndex(of: "#") {
            let frag = String(rest[rest.index(after: hash)...])
            parts.fragment = frag.removingPercentEncoding ?? frag
            rest = String(rest[..<hash])
        }
        if let qmark = rest.firstIndex(of: "?") {
            let qs = String(rest[rest.index(after: qmark)...])
            rest = String(rest[..<qmark])
            for pair in qs.split(separator: "&") {
                let kv = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                let key = String(kv[0]).removingPercentEncoding ?? String(kv[0])
                let value = kv.count > 1 ? (String(kv[1]).removingPercentEncoding ?? String(kv[1])) : ""
                parts.query[key] = value
            }
        }
        if let slash = rest.firstIndex(of: "/") {
            let p = String(rest[slash...])
            parts.path = p.removingPercentEncoding ?? p
            rest = String(rest[..<slash])
        }
        if let at = rest.lastIndex(of: "@") {
            parts.userinfo = String(rest[..<at])
            rest = String(rest[rest.index(after: at)...])
        }
        // host[:port]，支援 [IPv6]
        if rest.hasPrefix("["), let close = rest.firstIndex(of: "]") {
            parts.host = String(rest[rest.index(after: rest.startIndex)..<close])
            let after = rest[rest.index(after: close)...]
            if after.hasPrefix(":") {
                parts.port = Int(after.dropFirst().prefix(while: \.isNumber)) ?? 0
            }
        } else if let colon = rest.lastIndex(of: ":") {
            parts.host = String(rest[..<colon])
            parts.port = Int(rest[rest.index(after: colon)...].prefix(while: \.isNumber)) ?? 0
        } else {
            parts.host = rest
        }
        guard !parts.host.isEmpty else { return nil }
        return parts
    }

    // MARK: - 入口

    /// 解析單行分享連結。http(s):// 視為訂閱連結，不在此處理。
    static func parse(_ line: String) -> ProxyNode? {
        let s = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let schemeRange = s.range(of: "://") else { return nil }
        let scheme = String(s[..<schemeRange.lowerBound]).lowercased()
        switch scheme {
        case "ss": return parseSS(s)
        case "vmess": return parseVMess(s)
        case "vless": return parseVLESS(s)
        case "trojan": return parseTrojan(s)
        case "hysteria2", "hy2": return parseHysteria2(s)
        case "tuic": return parseTUIC(s)
        case "socks", "socks5": return parseSOCKS(s)
        default: return nil
        }
    }

    /// 解析多行文字（剪貼簿、訂閱內容）。
    /// 整段是 base64 時先解開；回傳節點與其中夾帶的 http(s) 訂閱連結。
    static func classify(_ text: String) -> (nodes: [ProxyNode], subscriptionURLs: [String]) {
        var content = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if !content.contains("://"),
           let decoded = Base64Util.decodeString(content),
           decoded.contains("://") {
            content = decoded
        }
        var nodes: [ProxyNode] = []
        var subs: [String] = []
        for rawLine in content.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty else { continue }
            if line.lowercased().hasPrefix("http://") || line.lowercased().hasPrefix("https://") {
                subs.append(line)
            } else if let node = parse(line) {
                nodes.append(node)
            }
        }
        return (nodes, subs)
    }

    static func parseMultiple(_ text: String) -> [ProxyNode] {
        classify(text).nodes
    }

    // MARK: - Shadowsocks

    /// SIP002: ss://base64(method:password)@host:port#name
    /// 舊式:   ss://base64(method:password@host:port)#name
    static func parseSS(_ raw: String) -> ProxyNode? {
        guard let bodyStart = raw.range(of: "://")?.upperBound else { return nil }
        var body = String(raw[bodyStart...])
        var fragName: String?
        if let hash = body.firstIndex(of: "#") {
            let frag = String(body[body.index(after: hash)...])
            fragName = frag.removingPercentEncoding ?? frag
            body = String(body[..<hash])
        }
        // 舊式：整段 base64
        if !body.contains("@"), let plain = Base64Util.decodeString(body) {
            body = plain
        }
        guard let parts = splitURI("ss://" + body),
              let rawUI = parts.userinfo, parts.port > 0 else { return nil }

        let ui = rawUI.removingPercentEncoding ?? rawUI
        func splitMethodPassword(_ s: String) -> (String, String)? {
            guard let colon = s.firstIndex(of: ":") else { return nil }
            return (String(s[..<colon]), String(s[s.index(after: colon)...]))
        }
        let pair: (String, String)
        if let decoded = Base64Util.decodeString(ui), let mp = splitMethodPassword(decoded) {
            pair = mp
        } else if let mp = splitMethodPassword(ui) {
            pair = mp
        } else {
            return nil
        }

        var node = ProxyNode(
            name: fragName ?? parts.fragment ?? "\(parts.host):\(parts.port)",
            proto: .shadowsocks, server: parts.host, port: parts.port
        )
        node.method = pair.0
        node.password = pair.1
        return node
    }

    // MARK: - VMess (v2rayN JSON 格式)

    private struct VMessJSON: Decodable {
        var ps: String?
        var add: String
        var port: FlexValue
        var id: String
        var aid: FlexValue?
        var scy: String?
        var net: String?
        var type: String?
        var host: String?
        var path: String?
        var tls: String?
        var sni: String?
        var alpn: String?
        var fp: String?
    }

    /// 兼容 Int 與 String 兩種寫法的數值欄位（機場輸出不統一）
    struct FlexValue: Decodable {
        let intValue: Int
        init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let i = try? container.decode(Int.self) {
                intValue = i
            } else if let s = try? container.decode(String.self) {
                intValue = Int(s.prefix(while: \.isNumber)) ?? 0
            } else {
                intValue = 0
            }
        }
    }

    static func parseVMess(_ raw: String) -> ProxyNode? {
        guard let bodyStart = raw.range(of: "://")?.upperBound else { return nil }
        let body = String(raw[bodyStart...])
        guard let data = Base64Util.decode(body),
              let json = try? JSONDecoder().decode(VMessJSON.self, from: data),
              json.port.intValue > 0 else { return nil }

        let net = (json.net ?? "tcp").lowercased()
        // mKCP / QUIC 傳輸 sing-box 不支援，直接略過
        if net == "kcp" || net == "quic" { return nil }

        var node = ProxyNode(
            name: json.ps ?? "\(json.add):\(json.port.intValue)",
            proto: .vmess, server: json.add, port: json.port.intValue
        )
        node.uuid = json.id
        node.alterId = json.aid?.intValue ?? 0
        node.security = (json.scy?.isEmpty == false) ? json.scy : "auto"
        node.tls = (json.tls?.lowercased() == "tls")
        node.fingerprint = json.fp?.isEmpty == false ? json.fp : nil
        if node.tls {
            node.sni = json.sni?.isEmpty == false ? json.sni : (json.host?.isEmpty == false ? json.host : nil)
            if let alpn = json.alpn, !alpn.isEmpty {
                node.alpn = alpn.split(separator: ",").map(String.init)
            }
        }
        switch net {
        case "ws":
            node.network = "ws"
            node.wsPath = json.path?.isEmpty == false ? json.path : "/"
            node.wsHost = json.host?.isEmpty == false ? json.host : nil
        case "grpc":
            node.network = "grpc"
            node.grpcServiceName = json.path?.isEmpty == false ? json.path : nil
        case "h2", "http":
            node.network = "http"
            node.wsPath = json.path?.isEmpty == false ? json.path : nil
            node.wsHost = json.host?.isEmpty == false ? json.host : nil
        default:
            break // tcp
        }
        return node
    }

    // MARK: - VLESS

    static func parseVLESS(_ raw: String) -> ProxyNode? {
        guard let parts = splitURI(raw),
              let uuid = parts.userinfo, !uuid.isEmpty, parts.port > 0 else { return nil }

        var node = ProxyNode(
            name: parts.fragment ?? "\(parts.host):\(parts.port)",
            proto: .vless, server: parts.host, port: parts.port
        )
        node.uuid = uuid.removingPercentEncoding ?? uuid

        let q = parts.query
        let security = (q["security"] ?? "none").lowercased()
        node.tls = (security == "tls" || security == "reality")
        node.sni = q["sni"] ?? q["peer"]
        node.fingerprint = q["fp"]?.isEmpty == false ? q["fp"] : nil
        node.insecure = ["1", "true"].contains((q["allowInsecure"] ?? q["insecure"] ?? "").lowercased())
        if security == "reality" {
            node.realityPublicKey = q["pbk"]
            node.realityShortID = q["sid"]
        }
        if let flow = q["flow"], !flow.isEmpty {
            node.flow = flow
        }
        applyTransport(&node, query: q)
        if let alpn = q["alpn"], !alpn.isEmpty {
            node.alpn = alpn.split(separator: ",").map(String.init)
        }
        return node
    }

    // MARK: - Trojan

    static func parseTrojan(_ raw: String) -> ProxyNode? {
        guard let parts = splitURI(raw),
              let pw = parts.userinfo, !pw.isEmpty, parts.port > 0 else { return nil }

        var node = ProxyNode(
            name: parts.fragment ?? "\(parts.host):\(parts.port)",
            proto: .trojan, server: parts.host, port: parts.port
        )
        node.password = pw.removingPercentEncoding ?? pw
        node.tls = true
        let q = parts.query
        node.sni = q["sni"] ?? q["peer"]
        node.insecure = ["1", "true"].contains((q["allowInsecure"] ?? q["insecure"] ?? "").lowercased())
        node.fingerprint = q["fp"]?.isEmpty == false ? q["fp"] : nil
        if let alpn = q["alpn"], !alpn.isEmpty {
            node.alpn = alpn.split(separator: ",").map(String.init)
        }
        applyTransport(&node, query: q)
        return node
    }

    // MARK: - Hysteria2

    static func parseHysteria2(_ raw: String) -> ProxyNode? {
        guard let parts = splitURI(raw), parts.port > 0 else { return nil }
        var node = ProxyNode(
            name: parts.fragment ?? "\(parts.host):\(parts.port)",
            proto: .hysteria2, server: parts.host, port: parts.port
        )
        let ui = parts.userinfo ?? ""
        node.password = ui.removingPercentEncoding ?? ui
        node.tls = true
        let q = parts.query
        node.sni = q["sni"]
        node.insecure = ["1", "true"].contains((q["insecure"] ?? "").lowercased())
        if let obfs = q["obfs"], !obfs.isEmpty {
            node.obfs = obfs
            node.obfsPassword = q["obfs-password"]
        }
        return node
    }

    // MARK: - TUIC

    static func parseTUIC(_ raw: String) -> ProxyNode? {
        guard let parts = splitURI(raw),
              let ui = parts.userinfo, parts.port > 0 else { return nil }
        let decoded = ui.removingPercentEncoding ?? ui
        guard let colon = decoded.firstIndex(of: ":") else { return nil }

        var node = ProxyNode(
            name: parts.fragment ?? "\(parts.host):\(parts.port)",
            proto: .tuic, server: parts.host, port: parts.port
        )
        node.uuid = String(decoded[..<colon])
        node.password = String(decoded[decoded.index(after: colon)...])
        node.tls = true
        let q = parts.query
        node.sni = q["sni"]
        node.insecure = ["1", "true"].contains((q["allow_insecure"] ?? q["insecure"] ?? "").lowercased())
        if let cc = q["congestion_control"], !cc.isEmpty {
            node.congestionControl = cc
        }
        if let alpn = q["alpn"], !alpn.isEmpty {
            node.alpn = alpn.split(separator: ",").map(String.init)
        }
        return node
    }

    // MARK: - SOCKS

    static func parseSOCKS(_ raw: String) -> ProxyNode? {
        guard let parts = splitURI(raw), parts.port > 0 else { return nil }
        var node = ProxyNode(
            name: parts.fragment ?? "\(parts.host):\(parts.port)",
            proto: .socks, server: parts.host, port: parts.port
        )
        if let ui = parts.userinfo, !ui.isEmpty {
            let plain = Base64Util.decodeString(ui) ?? (ui.removingPercentEncoding ?? ui)
            if let colon = plain.firstIndex(of: ":") {
                node.username = String(plain[..<colon])
                node.password = String(plain[plain.index(after: colon)...])
            }
        }
        return node
    }

    // MARK: - 共用：傳輸層參數 (vless / trojan)

    private static func applyTransport(_ node: inout ProxyNode, query q: [String: String]) {
        switch (q["type"] ?? "tcp").lowercased() {
        case "ws":
            node.network = "ws"
            node.wsPath = q["path"]?.isEmpty == false ? q["path"] : "/"
            node.wsHost = q["host"]?.isEmpty == false ? q["host"] : nil
        case "grpc":
            node.network = "grpc"
            node.grpcServiceName = q["serviceName"]?.isEmpty == false ? q["serviceName"] : nil
        case "http", "h2":
            node.network = "http"
            node.wsPath = q["path"]?.isEmpty == false ? q["path"] : nil
            node.wsHost = q["host"]?.isEmpty == false ? q["host"] : nil
        default:
            break
        }
    }
}
