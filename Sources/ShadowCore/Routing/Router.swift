import Foundation
import Network

/// 規則命中後的去向。
public enum RulePolicy: Sendable {
    case proxy
    case direct
    case reject
}

/// 單條分流規則：比對器 + 去向。由上而下，命中即止。
public struct RoutingRule: Sendable {
    public enum Matcher: Sendable {
        case domainSuffix(String)
        case domainKeyword(String)
        case domainExact(String)
        case ipCIDR(String)
    }
    public var matcher: Matcher
    public var policy: RulePolicy

    public init(_ matcher: Matcher, _ policy: RulePolicy) {
        self.matcher = matcher
        self.policy = policy
    }

    func matches(_ target: Target) -> Bool {
        switch matcher {
        case .domainSuffix(let s):
            let host = target.host.lowercased(), suf = s.lowercased()
            return host == suf || host.hasSuffix("." + suf)
        case .domainKeyword(let k):
            return target.host.lowercased().contains(k.lowercased())
        case .domainExact(let d):
            return target.host.lowercased() == d.lowercased()
        case .ipCIDR(let cidr):
            guard let ip = IPv4Address(target.host), let range = CIDRv4(cidr) else { return false }
            return range.contains(ip)
        }
    }
}

/// IPv4 CIDR 比對。
struct CIDRv4 {
    let network: UInt32
    let mask: UInt32

    init?(_ string: String) {
        let parts = string.split(separator: "/")
        guard parts.count == 2, let prefix = Int(parts[1]), (0...32).contains(prefix),
              let ip = IPv4Address(String(parts[0])) else { return nil }
        let addr = ip.rawValue.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        self.mask = prefix == 0 ? 0 : ~UInt32(0) << (32 - prefix)
        self.network = addr & mask
    }

    func contains(_ ip: IPv4Address) -> Bool {
        let addr = ip.rawValue.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        return (addr & mask) == network
    }
}

/// 被規則拒絕的出站：連線直接失敗（廣告阻擋用）。
public struct RejectOutbound: Outbound {
    public let name = "REJECT"
    public init() {}
    public func connect(to target: Target, queue: DispatchQueue) async throws -> ByteStream {
        throw ProxyError.unsupported("已被規則拒絕：\(target.host)")
    }
}

/// 分流路由：依規則決定每個目標走 proxy / direct / reject。
public final class Router: @unchecked Sendable {
    private let rules: [RoutingRule]
    private let finalPolicy: RulePolicy
    private let proxy: Outbound
    private let direct: Outbound
    private let reject: Outbound

    public init(rules: [RoutingRule], proxy: Outbound,
                direct: Outbound = DirectOutbound(),
                reject: Outbound = RejectOutbound(),
                finalPolicy: RulePolicy = .proxy) {
        self.rules = rules
        self.finalPolicy = finalPolicy
        self.proxy = proxy
        self.direct = direct
        self.reject = reject
    }

    public func select(_ target: Target) -> Outbound {
        for rule in rules where rule.matches(target) {
            return outbound(for: rule.policy)
        }
        return outbound(for: finalPolicy)
    }

    /// 純測試用：只回傳命中的去向，不需要真的 Outbound。
    public func policy(for target: Target) -> RulePolicy {
        for rule in rules where rule.matches(target) { return rule.policy }
        return finalPolicy
    }

    private func outbound(for policy: RulePolicy) -> Outbound {
        switch policy {
        case .proxy: return proxy
        case .direct: return direct
        case .reject: return reject
        }
    }
}
