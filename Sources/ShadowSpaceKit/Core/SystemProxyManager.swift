import Foundation

/// 透過 networksetup 設定/還原 macOS 系統代理（HTTP / HTTPS / SOCKS）。
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

    static func enable(port: Int, bypassHosts: [String] = []) throws {
        let services = activeServices()
        guard !services.isEmpty else {
            throw ProxyError.commandFailed("找不到可用的網路服務")
        }
        let bypass = bypassDomains(bypassHosts)
        var failures: [String] = []
        for service in services {
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
        if failures.count == services.count {
            throw ProxyError.commandFailed(failures.first ?? "未知錯誤")
        }
    }

    static func disable() {
        for service in activeServices() {
            for flag in ["-setwebproxystate", "-setsecurewebproxystate", "-setsocksfirewallproxystate"] {
                EngineManager.runProcess(tool, [flag, service, "off"])
            }
        }
    }
}
