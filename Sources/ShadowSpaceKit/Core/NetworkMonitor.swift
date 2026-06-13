import Foundation
import Network

/// 監看系統網路路徑變化（給「自動連線 / On-demand」用）。
/// macOS 14 取 SSID 需定位權限且受限，這裡只判斷「有沒有可用網路」與介面類型。
final class NetworkMonitor: @unchecked Sendable {
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "shadowspace.networkmonitor")

    /// 路徑變化回呼：(是否有可用網路, 是否為 Wi-Fi)
    var onChange: ((_ satisfied: Bool, _ isWiFi: Bool) -> Void)?

    func start() {
        monitor.pathUpdateHandler = { [weak self] path in
            let satisfied = path.status == .satisfied
            let isWiFi = path.usesInterfaceType(.wifi)
            self?.onChange?(satisfied, isWiFi)
        }
        monitor.start(queue: queue)
    }

    func stop() {
        monitor.cancel()
    }
}
