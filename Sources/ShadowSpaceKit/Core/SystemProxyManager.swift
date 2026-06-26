import Foundation
import SystemConfiguration

/// 透過 networksetup 設定/還原 macOS 系統代理（HTTP / HTTPS / SOCKS）。
/// 只設在「主要網路服務」（持有預設路由那條）上，避免污染使用者其他服務（含 VPN）；
/// 關閉時把任何指向本機的代理一併清掉並清空例外清單，確保乾淨還原。
enum SystemProxyManager {

    enum ProxyError: LocalizedError {
        case commandFailed(String)
        var errorDescription: String? {
            switch self {
            case .commandFailed(let msg):
                return "設定系統代理失敗：\(msg)\n（提示：需要管理員帳號才能修改網路設定）"
            }
        }
    }

    private static let tool = URL(fileURLWithPath: "/usr/sbin/networksetup")

    /// 列出啟用中的網路服務（Wi-Fi、乙太網路…），開頭帶 * 的是停用狀態
    static func activeServices() -> [String] {
        let (status, output) = EngineManager.runProcess(tool, ["-listallnetworkservices"])
        guard status == 0 else { return [] }
        return output
            .split(whereSeparator: \.isNewline)
            .dropFirst() // 第一行是說明文字
            .map(String.init)
            .filter { !$0.hasPrefix("*") && !$0.isEmpty }
    }

    /// 列出所有網路服務（含停用），用來清除可能殘留在停用服務上的代理。
    static func allServiceNames() -> [String] {
        let (status, output) = EngineManager.runProcess(tool, ["-listallnetworkservices"])
        guard status == 0 else { return [] }
        return output
            .split(whereSeparator: \.isNewline)
            .dropFirst()
            .map { $0.hasPrefix("*") ? String($0.dropFirst()) : String($0) }
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    /// 持有預設路由的「主要服務」名稱（= 系統代理該設的地方）。抓不到回 nil。
    static func primaryServiceName() -> String? {
        guard let store = SCDynamicStoreCreate(nil, "ShadowSpace.proxy" as CFString, nil, nil),
              let global = SCDynamicStoreCopyValue(store, "State:/Network/Global/IPv4" as CFString) as? [String: Any],
              let serviceID = global["PrimaryService"] as? String,
              let setup = SCDynamicStoreCopyValue(store, "Setup:/Network/Service/\(serviceID)" as CFString) as? [String: Any],
              let name = setup["UserDefinedName"] as? String, !name.isEmpty else {
            return nil
        }
        return name
    }

    /// 讀取某服務某種代理的狀態（啟用與否、伺服器位址）。
    private static func proxyState(_ service: String, getFlag: String) -> (enabled: Bool, server: String?) {
        let (status, output) = EngineManager.runProcess(tool, [getFlag, service])
        guard status == 0 else { return (false, nil) }
        var enabled = false
        var server: String?
        for line in output.split(whereSeparator: \.isNewline).map(String.init) {
            if line.hasPrefix("Enabled:") {            // 注意：避開 "Authenticated Proxy Enabled:"
                enabled = line.contains("Yes")
            } else if line.hasPrefix("Server:") {
                server = line.dropFirst("Server:".count).trimmingCharacters(in: .whitespaces)
            }
        }
        return (enabled, server)
    }

    private static func isLoopback(_ host: String?) -> Bool {
        host == "127.0.0.1" || host == "::1" || host == "localhost"
    }

    /// 預設繞過清單 + 額外主機（代理伺服器自身），去重後回傳。
    /// 把代理伺服器主機列入繞過，避免原生引擎連往伺服器的流量又被系統代理繞回
    /// 本機代理埠（= 引擎自己）形成迴圈，導致「連線後完全沒網路」。
    static func bypassDomains(_ extraHosts: [String] = []) -> [String] {
        let base = ["127.0.0.1", "localhost", "*.local",
                    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        var seen = Set(base)
        var result = base
        for host in extraHosts.map({ $0.trimmingCharacters(in: .whitespaces) })
            where !host.isEmpty && !seen.contains(host) {
            seen.insert(host)
            result.append(host)
        }
        return result
    }

    /// 是否有服務仍掛著「啟用中的本機代理」（= 上次非正常結束殘留）。啟動校正時用。
    static func residualProxyDetected() -> Bool {
        let services = primaryServiceName().map { [$0] } ?? activeServices()
        for service in services {
            for flag in ["-getwebproxy", "-getsecurewebproxy", "-getsocksfirewallproxy"] {
                let s = proxyState(service, getFlag: flag)
                if s.enabled && isLoopback(s.server) { return true }
            }
        }
        return false
    }

    /// 關掉所有「指向本機」的代理並清空其例外清單（= 徹底移除我們設的代理，含殘留）。
    private static func clearLoopbackProxies() {
        for service in allServiceNames() {
            let ours = isLoopback(proxyState(service, getFlag: "-getwebproxy").server)
                || isLoopback(proxyState(service, getFlag: "-getsecurewebproxy").server)
                || isLoopback(proxyState(service, getFlag: "-getsocksfirewallproxy").server)
            guard ours else { continue }
            EngineManager.runProcess(tool, ["-setwebproxystate", service, "off"])
            EngineManager.runProcess(tool, ["-setsecurewebproxystate", service, "off"])
            EngineManager.runProcess(tool, ["-setsocksfirewallproxystate", service, "off"])
            EngineManager.runProcess(tool, ["-setproxybypassdomains", service, "Empty"])  // 清空例外清單
        }
    }

    /// 啟用系統代理：先清掉任何殘留的本機代理，再只設在主要服務上（抓不到主要服務時退回所有啟用中的服務）。
    /// 先清後設 → 冪等、且網路切換時重新呼叫即可把代理移到新的主要服務。
    static func enable(port: Int, bypassHosts: [String] = []) throws {
        clearLoopbackProxies()

        let targets = primaryServiceName().map { [$0] } ?? activeServices()
        guard !targets.isEmpty else {
            throw ProxyError.commandFailed("找不到可用的網路服務")
        }
        let bypass = bypassDomains(bypassHosts)
        var failures: [String] = []
        for service in targets {
            let commands: [[String]] = [
                ["-setwebproxy", service, "127.0.0.1", "\(port)"],
                ["-setsecurewebproxy", service, "127.0.0.1", "\(port)"],
                ["-setsocksfirewallproxy", service, "127.0.0.1", "\(port)"],
                ["-setproxybypassdomains", service] + bypass,
            ]
            for args in commands {
                let (status, output) = EngineManager.runProcess(tool, args)
                if status != 0 {
                    failures.append("\(service): \(output.trimmingCharacters(in: .whitespacesAndNewlines))")
                    break
                }
            }
        }
        if failures.count == targets.count {
            throw ProxyError.commandFailed(failures.first ?? "未知錯誤")
        }
    }

    /// 停用系統代理：把任何指向本機的代理一併清掉並清空例外清單，確保乾淨還原。
    static func disable() {
        clearLoopbackProxies()
    }
}
