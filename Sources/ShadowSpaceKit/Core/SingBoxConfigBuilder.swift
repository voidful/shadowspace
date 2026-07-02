import Foundation

/// 把 App 狀態轉成 sing-box 設定檔（JSON）。
/// 目標格式為 sing-box 1.12+：
/// - DNS 使用新版 typed servers
/// - 路由規則使用 rule action 與 clash_mode，模式切換走 Clash API 不需重啟
enum SingBoxConfigBuilder {

    struct BuildResult {
        var json: [String: Any]
        /// 節點 ID → 設定檔中的 outbound tag（切換節點時用）
        var tagByNodeID: [UUID: String]
        /// 群組 ID → outbound tag
        var tagByGroupID: [UUID: String] = [:]
    }

    static let selectorTag = "PROXY"
    static let autoTag = "AUTO"
    static let directTag = "DIRECT"

    private static let ruleSetBaseURL: [String: String] = [
        "geosite": "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set",
        "geoip": "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set",
    ]

    static func build(nodes: [ProxyNode],
                      selectedID: UUID?,
                      settings: AppSettings,
                      mode: ProxyMode,
                      groups: [ProxyGroup] = [],
                      rules userRules: [UserRule] = []) -> BuildResult {

        // --- 唯一化 outbound tag ---
        var tagByNodeID: [UUID: String] = [:]
        var usedTags: Set<String> = [selectorTag, autoTag, directTag]
        for node in nodes {
            var base = node.name.trimmingCharacters(in: .whitespacesAndNewlines)
            if base.isEmpty { base = "\(node.server):\(node.port)" }
            var tag = base
            var n = 2
            while usedTags.contains(tag) {
                tag = "\(base) \(n)"
                n += 1
            }
            usedTags.insert(tag)
            tagByNodeID[node.id] = tag
        }

        let nodeTags = nodes.compactMap { tagByNodeID[$0.id] }

        // --- 群組 tag（避免與節點 / 保留字衝突）---
        var tagByGroupID: [UUID: String] = [:]
        for group in groups {
            var base = group.name.trimmingCharacters(in: .whitespacesAndNewlines)
            if base.isEmpty { base = "群組" }
            var tag = base
            var n = 2
            while usedTags.contains(tag) { tag = "\(base) \(n)"; n += 1 }
            usedTags.insert(tag)
            tagByGroupID[group.id] = tag
        }
        // 只保留至少有一個有效成員的群組
        let validGroups = groups.filter { group in
            group.memberNodeIDs.contains { tagByNodeID[$0] != nil }
        }
        let groupTags = validGroups.compactMap { tagByGroupID[$0.id] }

        let defaultTag = selectedID.flatMap { tagByGroupID[$0] ?? tagByNodeID[$0] }
            ?? groupTags.first ?? nodeTags.first ?? directTag

        // --- outbounds ---
        var outbounds: [[String: Any]] = []
        var selectorMembers: [String] = groupTags     // 群組排在最前面
        if nodes.count > 1 {
            selectorMembers.append(autoTag)
        }
        selectorMembers.append(contentsOf: nodeTags)

        outbounds.append([
            "type": "selector",
            "tag": selectorTag,
            "outbounds": selectorMembers,
            "default": defaultTag,
            "interrupt_exist_connections": true,
        ])
        if nodes.count > 1 {
            outbounds.append([
                "type": "urltest",
                "tag": autoTag,
                "outbounds": nodeTags,
                "url": "http://www.gstatic.com/generate_204",
                "interval": "5m",
            ])
        }
        // 使用者自訂群組
        for group in validGroups {
            let memberTags = group.memberNodeIDs.compactMap { tagByNodeID[$0] }
            let gtag = tagByGroupID[group.id]!
            switch group.type {
            case .select:
                outbounds.append([
                    "type": "selector",
                    "tag": gtag,
                    "outbounds": memberTags,
                    "default": memberTags.first!,
                    "interrupt_exist_connections": true,
                ])
            case .urltest:
                outbounds.append([
                    "type": "urltest",
                    "tag": gtag,
                    "outbounds": memberTags,
                    "url": "http://www.gstatic.com/generate_204",
                    "interval": "5m",
                ])
            }
        }
        var endpoints: [[String: Any]] = []
        for node in nodes {
            if node.proto == .wireguard {
                endpoints.append(wireguardEndpoint(for: node, tag: tagByNodeID[node.id]!))
            } else {
                let detour = node.dialerNodeID.flatMap { tagByNodeID[$0] }
                outbounds.append(outbound(for: node, tag: tagByNodeID[node.id]!, detour: detour,
                                          defaultFingerprint: settings.tlsFingerprint))
            }
        }
        outbounds.append(["type": "direct", "tag": directTag])

        // --- 路由規則 ---
        // 順序：sniff → (TUN: DNS 劫持) → 私有 IP 直連 → 廣告阻擋（所有模式）
        //      → 模式捷徑（Global/Direct）→ 自訂規則 → 中國大陸直連 → final
        var routeRules: [[String: Any]] = [["action": "sniff"]]
        if settings.tunMode {
            routeRules.append(["protocol": "dns", "action": "hijack-dns"])
        }
        routeRules.append(["ip_is_private": true, "outbound": directTag])

        // 需要引用的 rule_set（tag → 定義）
        var ruleSets: [String: [String: Any]] = [:]
        func ensureRuleSet(_ tag: String) {
            guard ruleSets[tag] == nil else { return }
            let repo = tag.hasPrefix("geoip-") ? "geoip" : "geosite"
            ruleSets[tag] = [
                "type": "remote",
                "tag": tag,
                "format": "binary",
                "url": "\(ruleSetBaseURL[repo]!)/\(tag).srs",
                "download_detour": directTag,
                "update_interval": "3d",
            ]
        }

        if settings.adBlock {
            ensureRuleSet("geosite-category-ads-all")
            routeRules.append(["rule_set": ["geosite-category-ads-all"], "action": "reject"])
        }

        routeRules.append(["clash_mode": "Global", "outbound": selectorTag])
        routeRules.append(["clash_mode": "Direct", "outbound": directTag])

        var urlRuleSetIndex = 0
        for rule in userRules where rule.enabled && !rule.values.isEmpty {
            if rule.type == .ruleSet {
                // 使用者訂閱的遠端規則集（.srs binary 或 .json source）
                var tags: [String] = []
                for url in rule.values {
                    let tag = "ruleset-\(urlRuleSetIndex)"
                    urlRuleSetIndex += 1
                    let format = url.lowercased().hasSuffix(".srs") ? "binary" : "source"
                    ruleSets[tag] = [
                        "type": "remote", "tag": tag, "format": format,
                        "url": url, "download_detour": directTag, "update_interval": "1d",
                    ]
                    tags.append(tag)
                }
                var d: [String: Any] = ["rule_set": tags]
                switch rule.policy {
                case .reject: d["action"] = "reject"
                case .proxy: d["outbound"] = selectorTag
                case .direct: d["outbound"] = directTag
                }
                routeRules.append(d)
            } else if let dict = ruleDict(rule, ensureRuleSet: ensureRuleSet) {
                routeRules.append(dict)
            }
        }

        if settings.chinaDirect {
            ensureRuleSet("geosite-cn")
            ensureRuleSet("geoip-cn")
            routeRules.append(["rule_set": ["geosite-cn"], "outbound": directTag])
            routeRules.append(["rule_set": ["geoip-cn"], "outbound": directTag])
        }

        var route: [String: Any] = [
            "rules": routeRules,
            "final": selectorTag,
            "default_domain_resolver": "dns-direct",
        ]
        if !ruleSets.isEmpty {
            route["rule_set"] = ruleSets.keys.sorted().map { ruleSets[$0]! }
        }
        if settings.tunMode {
            route["auto_detect_interface"] = true
        }

        // --- DNS ---
        var dnsRules: [[String: Any]] = [
            ["clash_mode": "Direct", "server": "dns-direct"],
            ["clash_mode": "Global", "server": "dns-remote"],
        ]
        if settings.adBlock {
            dnsRules.append(["rule_set": "geosite-category-ads-all", "action": "reject"])
        }
        if settings.chinaDirect {
            dnsRules.append(["rule_set": "geosite-cn", "server": "dns-direct"])
        }
        let dns: [String: Any] = [
            "servers": [
                dnsServerDict(tag: "dns-direct", spec: settings.localDNS, detour: nil),
                dnsServerDict(tag: "dns-remote", spec: settings.remoteDNS, detour: selectorTag),
            ],
            "rules": dnsRules,
            "final": "dns-remote",
            "strategy": "prefer_ipv4",
        ]

        // --- inbounds ---
        let listenAddr = settings.allowLAN ? "0.0.0.0" : "127.0.0.1"
        var inbounds: [[String: Any]] = []
        if settings.tunMode {
            inbounds.append([
                "type": "tun",
                "tag": "tun-in",
                "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
                "auto_route": true,
                "strict_route": false,
                "stack": "mixed",
            ])
        }
        inbounds.append([
            "type": "mixed",
            "tag": "mixed-in",
            "listen": listenAddr,
            "listen_port": settings.mixedPort,
        ])

        var config: [String: Any] = [
            "log": ["level": "info", "timestamp": true],
            "dns": dns,
            "inbounds": inbounds,
            "outbounds": outbounds,
            "route": route,
            "experimental": [
                "clash_api": [
                    "external_controller": "127.0.0.1:\(settings.apiPort)",
                    "secret": settings.apiSecret,
                    "default_mode": mode.clashMode,
                ],
                "cache_file": ["enabled": true],
            ],
        ]
        if !endpoints.isEmpty {
            config["endpoints"] = endpoints
        }
        return BuildResult(json: config, tagByNodeID: tagByNodeID, tagByGroupID: tagByGroupID)
    }

    static func jsonData(_ config: [String: Any]) throws -> Data {
        try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys])
    }

    // MARK: - 自訂規則 → 路由規則

    private static func ruleDict(_ rule: UserRule,
                                 ensureRuleSet: (String) -> Void) -> [String: Any]? {
        var dict: [String: Any] = [:]
        let values = rule.values
        switch rule.type {
        case .domainSuffix: dict["domain_suffix"] = values
        case .domainKeyword: dict["domain_keyword"] = values
        case .domainExact: dict["domain"] = values
        case .ipCIDR: dict["ip_cidr"] = values
        case .processName: dict["process_name"] = values
        case .geoIP:
            let tags = values.map { "geoip-\($0.lowercased())" }
            tags.forEach(ensureRuleSet)
            dict["rule_set"] = tags
        case .geosite:
            let tags = values.map { "geosite-\($0.lowercased())" }
            tags.forEach(ensureRuleSet)
            dict["rule_set"] = tags
        case .ruleSet:
            return nil   // 由 build() 直接處理（需要 URL）
        }
        switch rule.policy {
        case .reject: dict["action"] = "reject"
        case .proxy: dict["outbound"] = selectorTag
        case .direct: dict["outbound"] = directTag
        }
        return dict
    }

    // MARK: - DNS server 規格

    /// spec 支援："local"（系統解析）、IP（UDP）、https://（DoH）、tls://（DoT）
    static func dnsServerDict(tag: String, spec: String, detour: String?) -> [String: Any] {
        var d: [String: Any] = ["tag": tag]
        let s = spec.trimmingCharacters(in: .whitespacesAndNewlines)
        if s == "local" || s.isEmpty {
            d["type"] = "local"
            return d
        }
        if s.hasPrefix("https://"), let url = URL(string: s) {
            d["type"] = "https"
            d["server"] = url.host ?? s
            if !url.path.isEmpty, url.path != "/dns-query" {
                d["path"] = url.path
            }
        } else if s.hasPrefix("tls://") {
            d["type"] = "tls"
            d["server"] = String(s.dropFirst("tls://".count))
        } else {
            d["type"] = "udp"
            d["server"] = s
        }
        if let detour { d["detour"] = detour }
        return d
    }

    // MARK: - 單一節點 → outbound

    /// WireGuard 在 sing-box 1.11+ 是 endpoint（非 outbound）。
    static func wireguardEndpoint(for node: ProxyNode, tag: String) -> [String: Any] {
        var peer: [String: Any] = [
            "address": node.server,
            "port": node.port,
            "public_key": node.wgPeerPublicKey ?? "",
            "allowed_ips": ["0.0.0.0/0", "::/0"],
            "persistent_keepalive_interval": 25,
        ]
        if let psk = node.wgPresharedKey, !psk.isEmpty {
            peer["pre_shared_key"] = psk
        }
        var endpoint: [String: Any] = [
            "type": "wireguard",
            "tag": tag,
            "address": node.wgLocalAddress ?? ["172.16.0.2/32"],
            "private_key": node.wgPrivateKey ?? "",
            "peers": [peer],
        ]
        if let mtu = node.wgMTU { endpoint["mtu"] = mtu }
        return endpoint
    }

    static func outbound(for node: ProxyNode, tag: String, detour: String? = nil,
                         defaultFingerprint: String? = nil) -> [String: Any] {
        var ob: [String: Any] = [
            "tag": tag,
            "server": node.server,
            "server_port": node.port,
        ]
        switch node.proto {
        case .wireguard:
            ob["type"] = "direct"   // 不會到這：WG 走 endpoint，已在 build() 過濾
        case .shadowsocks:
            ob["type"] = "shadowsocks"
            ob["method"] = node.method ?? "aes-256-gcm"
            ob["password"] = node.password ?? ""
        case .vmess:
            ob["type"] = "vmess"
            ob["uuid"] = node.uuid ?? ""
            ob["security"] = node.security ?? "auto"
            ob["alter_id"] = node.alterId ?? 0
        case .vless:
            ob["type"] = "vless"
            ob["uuid"] = node.uuid ?? ""
            if let flow = node.flow { ob["flow"] = flow }
        case .trojan:
            ob["type"] = "trojan"
            ob["password"] = node.password ?? ""
        case .hysteria2:
            ob["type"] = "hysteria2"
            ob["password"] = node.password ?? ""
            if let obfs = node.obfs {
                ob["obfs"] = ["type": obfs, "password": node.obfsPassword ?? ""]
            }
        case .tuic:
            ob["type"] = "tuic"
            ob["uuid"] = node.uuid ?? ""
            ob["password"] = node.password ?? ""
            if let cc = node.congestionControl { ob["congestion_control"] = cc }
        case .anytls:
            ob["type"] = "anytls"
            ob["password"] = node.password ?? ""
        case .socks:
            ob["type"] = "socks"
            ob["version"] = "5"
            if let user = node.username { ob["username"] = user }
            if let pw = node.password { ob["password"] = pw }
        }

        if node.tls || node.proto == .anytls {
            var tls: [String: Any] = [
                "enabled": true,
                "server_name": node.sni ?? node.wsHost ?? node.server,
            ]
            if node.insecure { tls["insecure"] = true }
            if let alpn = node.alpn, !alpn.isEmpty { tls["alpn"] = alpn }
            // uTLS 指紋：節點自帶 fp 優先；否則對 TLS-over-TCP 協議套用預設瀏覽器指紋
            // （抗 JA3 指紋分類，且 REALITY 本就需要 uTLS）。QUIC 協議（hysteria2/tuic）不套用。
            let supportsUTLS: Bool
            switch node.proto {
            case .vless, .trojan, .vmess, .anytls: supportsUTLS = true
            default: supportsUTLS = false
            }
            let fallbackFP = (supportsUTLS && !(defaultFingerprint ?? "").isEmpty) ? defaultFingerprint : nil
            if let fp = node.fingerprint ?? fallbackFP {
                tls["utls"] = ["enabled": true, "fingerprint": fp]
            }
            if let pbk = node.realityPublicKey, !pbk.isEmpty {
                var reality: [String: Any] = ["enabled": true, "public_key": pbk]
                if let sid = node.realityShortID { reality["short_id"] = sid }
                tls["reality"] = reality
            }
            ob["tls"] = tls
        }

        if let transport = transportDict(for: node) {
            ob["transport"] = transport
        }
        if let detour { ob["detour"] = detour }   // 節點鏈：經中轉節點
        return ob
    }

    private static func transportDict(for node: ProxyNode) -> [String: Any]? {
        switch node.network {
        case "ws":
            var t: [String: Any] = ["type": "ws"]
            var path = node.wsPath ?? "/"
            // 處理 path 內嵌的 early data 參數（?ed=2048）
            if let range = path.range(of: "?ed=") {
                let edStr = path[range.upperBound...].prefix(while: \.isNumber)
                if let ed = Int(edStr) {
                    t["max_early_data"] = ed
                    t["early_data_header_name"] = "Sec-WebSocket-Protocol"
                }
                path = String(path[..<range.lowerBound])
            }
            t["path"] = path
            if let host = node.wsHost {
                t["headers"] = ["Host": host]
            }
            return t
        case "grpc":
            var t: [String: Any] = ["type": "grpc"]
            if let svc = node.grpcServiceName { t["service_name"] = svc }
            return t
        case "http":
            var t: [String: Any] = ["type": "http"]
            if let path = node.wsPath { t["path"] = path }
            if let host = node.wsHost { t["host"] = [host] }
            return t
        default:
            return nil
        }
    }
}
