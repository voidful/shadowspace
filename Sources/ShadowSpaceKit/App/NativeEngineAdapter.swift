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
    static func outbound(for node: ProxyNode) throws -> Outbound {
        let host = node.server
        let port = UInt16(clamping: node.port)

        switch node.proto {
        case .shadowsocks:
            guard let outbound = ShadowsocksOutbound(
                name: node.name, host: host, port: port,
                method: node.method ?? "aes-256-gcm", password: node.password ?? "") else {
                throw AdapterError.unsupported("原生引擎不支援此 Shadowsocks 加密方式：\(node.method ?? "未知")")
            }
            return outbound

        case .trojan:
            return TrojanOutbound(name: node.name, host: host, port: port,
                                  password: node.password ?? "",
                                  transport: transport(for: node, defaultTLS: true))

        case .vless:
            if node.realityPublicKey?.isEmpty == false {
                throw AdapterError.unsupported("原生引擎不支援 VLESS Reality，請改用 sing-box 引擎")
            }
            guard let outbound = VlessOutbound(
                name: node.name, host: host, port: port, uuid: node.uuid ?? "",
                transport: transport(for: node, defaultTLS: node.tls)) else {
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
        case .wireguard:
            throw AdapterError.unsupported("原生引擎不支援 WireGuard（需 Packet Tunnel），請改用 sing-box 引擎")
        }
    }

    static func transport(for node: ProxyNode, defaultTLS: Bool) -> TransportConfig {
        var config = TransportConfig()
        config.tls = node.tls || defaultTLS
        config.sni = node.sni
        config.insecure = node.insecure
        config.alpn = node.alpn
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
