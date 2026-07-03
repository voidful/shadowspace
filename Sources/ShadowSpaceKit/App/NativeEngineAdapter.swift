import Foundation
import ShadowCore

/// 把 App 的資料模型（ProxyNode / UserRule）轉成 ShadowCore 原生引擎的物件。
enum NativeEngineAdapter {

    enum AdapterError: LocalizedError {
        case unsupported(String)
        var errorDescription: String? {
            switch self { case .unsupported(let m): return m }
        }
    }

    /// ProxyNode → ShadowCore.Outbound。不支援的協議/特性丟出清楚的錯誤。
    /// nativeTLS：Trojan/VLESS 的 TCP+TLS 改走自建 TLS 1.3（瀏覽器指紋）；fingerprint：指紋預設。
    static func outbound(for node: ProxyNode, fragment: Bool = false,
                         nativeTLS: Bool = false, fingerprint: String? = nil) throws -> Outbound {
        let host = node.server
        let port = UInt16(clamping: node.port)

        switch node.proto {
        case .shadowsocks:
            // SS-2022（2022-blake3-*）：BLAKE3 + base64 PSK，走專屬串流
            if let m = SS2022Method(node.method ?? "") {
                guard let outbound = SS2022Outbound(
                    name: node.name, host: host, port: port,
                    method: node.method ?? "", password: node.password ?? "") else {
                    throw AdapterError.unsupported("SS-2022 PSK 格式錯誤（需 base64，解碼後 \(m.keySize) bytes）")
                }
                return outbound
            }
            guard let outbound = ShadowsocksOutbound(
                name: node.name, host: host, port: port,
                method: node.method ?? "aes-256-gcm", password: node.password ?? "") else {
                throw AdapterError.unsupported("原生引擎不支援此 Shadowsocks 加密方式：\(node.method ?? "未知")")
            }
            return outbound

        case .trojan:
            return TrojanOutbound(name: node.name, host: host, port: port,
                                  password: node.password ?? "",
                                  transport: transport(for: node, defaultTLS: true, fragment: fragment,
                                                       nativeTLS: nativeTLS, fingerprint: fingerprint))

        case .vless:
            // flow（含 XTLS Vision）：原生實作尚未對真機驗證、會破壞資料流，暫一律不支援 → 交回 sing-box。
            if let flow = node.flow, !flow.isEmpty {
                throw AdapterError.unsupported("原生引擎暫不支援 VLESS flow「\(flow)」（含 XTLS Vision），已改用 sing-box 引擎")
            }
            // REALITY：以自建 TLS 1.3 + REALITY 認證出站
            var reality: RealityClientConfig? = nil
            if let pbk = node.realityPublicKey, !pbk.isEmpty {
                guard let rc = RealityClientConfig(publicKeyString: pbk, shortIDHex: node.realityShortID ?? "") else {
                    throw AdapterError.unsupported("REALITY 公鑰（pbk）或 short-id（sid）格式錯誤")
                }
                reality = rc
            }
            guard let outbound = VlessOutbound(
                name: node.name, host: host, port: port, uuid: node.uuid ?? "",
                transport: transport(for: node, defaultTLS: node.tls, fragment: fragment,
                                     nativeTLS: nativeTLS, fingerprint: fingerprint, reality: reality),
                flow: node.flow) else {
                throw AdapterError.unsupported("VLESS UUID 格式錯誤")
            }
            return outbound

        case .socks:
            return SocksOutbound(name: node.name, host: host, port: port,
                                 username: node.username, password: node.password)

        case .vmess:
            throw AdapterError.unsupported("原生引擎尚未支援 VMess，請改用 sing-box 引擎")
        case .hysteria2:
            throw AdapterError.unsupported("原生引擎不支援 Hysteria2（QUIC），請改用 sing-box 引擎")
        case .tuic:
            throw AdapterError.unsupported("原生引擎不支援 TUIC（QUIC），請改用 sing-box 引擎")
        case .anytls:
            throw AdapterError.unsupported("原生引擎不支援 AnyTLS，請改用 sing-box 引擎")
        case .wireguard:
            throw AdapterError.unsupported("原生引擎不支援 WireGuard（需 Packet Tunnel），請改用 sing-box 引擎")
        }
    }

    static func transport(for node: ProxyNode, defaultTLS: Bool, fragment: Bool = false,
                          nativeTLS: Bool = false, fingerprint: String? = nil,
                          reality: RealityClientConfig? = nil) -> TransportConfig {
        var config = TransportConfig()
        config.tls = node.tls || defaultTLS || reality != nil
        config.sni = node.sni
        config.insecure = node.insecure
        config.alpn = node.alpn
        config.fragment = fragment && config.tls   // 只有 TLS 連線才需要分片
        config.reality = reality
        config.nativeTLS = nativeTLS || reality != nil   // REALITY 必走自建 TLS（Apple TLS 無法做）
        config.fingerprint = node.fingerprint ?? fingerprint
        if node.network == "ws" {
            config.network = .ws
            config.wsPath = node.wsPath ?? "/"
            config.wsHost = node.wsHost
        } else {
            config.network = .tcp
        }
        return config
    }

    /// 由選定節點 + 使用者規則 + 模式組出原生路由。
    /// 注意：原生引擎無 geosite/geoip 資料，這幾類規則會被略過。
    static func makeRouter(proxy: Outbound, rules: [UserRule], mode: ProxyMode) -> Router {
        switch mode {
        case .global:
            return Router(rules: [], proxy: proxy, finalPolicy: .proxy)
        case .direct:
            return Router(rules: [], proxy: proxy, finalPolicy: .direct)
        case .rule:
            var routing: [RoutingRule] = []
            for rule in rules where rule.enabled {
                let policy = corePolicy(rule.policy)
                for value in rule.values {
                    switch rule.type {
                    case .domainSuffix: routing.append(RoutingRule(.domainSuffix(value), policy))
                    case .domainKeyword: routing.append(RoutingRule(.domainKeyword(value), policy))
                    case .domainExact: routing.append(RoutingRule(.domainExact(value), policy))
                    case .ipCIDR: routing.append(RoutingRule(.ipCIDR(value), policy))
                    case .geoIP, .geosite, .processName, .ruleSet: break   // 原生引擎暫不支援
                    }
                }
            }
            return Router(rules: routing, proxy: proxy, finalPolicy: .proxy)
        }
    }

    /// 哪些節點原生引擎跑得動（給 UI 標示用）。
    static func isSupported(_ node: ProxyNode) -> Bool {
        (try? outbound(for: node)) != nil
    }

    private static func corePolicy(_ p: RulePolicy) -> ShadowCore.RulePolicy {
        switch p {
        case .proxy: return .proxy
        case .direct: return .direct
        case .reject: return .reject
        }
    }
}
