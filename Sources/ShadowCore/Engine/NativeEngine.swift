import Foundation

/// 全原生代理引擎：本地混合入站 → 路由 → 出站。
/// Phase 1 先支援單一出站；之後接上 Router 做規則分流。
public final class NativeEngine: @unchecked Sendable {

    private let host: String
    private let port: UInt16
    private let outbound: Outbound
    private var server: MixedServer?

    /// 累計流量（位元組）
    public private(set) var upTotal = 0
    public private(set) var downTotal = 0
    private let statsLock = NSLock()

    public init(listenHost: String = "127.0.0.1", port: UInt16, outbound: Outbound) {
        self.host = listenHost
        self.port = port
        self.outbound = outbound
    }

    public func start() throws {
        let outbound = self.outbound
        let server = MixedServer(host: host, port: port, onBytes: { [weak self] up, down in
            guard let self else { return }
            self.statsLock.lock()
            self.upTotal += up
            self.downTotal += down
            self.statsLock.unlock()
        }, route: { _ in outbound })
        try server.start()
        self.server = server
    }

    public func stop() {
        server?.stop()
        server = nil
    }
}
