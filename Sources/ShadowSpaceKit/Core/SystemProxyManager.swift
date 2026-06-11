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

    static func enable(port: Int) throws {
        let services = activeServices()
        guard !services.isEmpty else {
            throw ProxyError.commandFailed("找不到可用的網路服務")
        }
        var failures: [String] = []
        for service in services {
            let commands: [[String]] = [
                ["-setwebproxy", service, "127.0.0.1", "\(port)"],
                ["-setsecurewebproxy", service, "127.0.0.1", "\(port)"],
                ["-setsocksfirewallproxy", service, "127.0.0.1", "\(port)"],
                ["-setproxybypassdomains", service,
                 "127.0.0.1", "localhost", "*.local",
                 "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
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
