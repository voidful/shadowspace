import Foundation

/// 全原生代理引擎：本地混合入站 → 規則路由 → 出站。
public final class NativeEngine: @unchecked Sendable {

    private let host: String
    private let port: UInt16
    private let router: Router
    private var server: MixedServer?

    /// 累計流量（位元組）
    public private(set) var upTotal = 0
    public private(set) var downTotal = 0
    private let statsLock = NSLock()

    public init(listenHost: String = "127.0.0.1", port: UInt16, router: Router) {
        self.host = listenHost
        self.port = port
        self.router = router
    }

    /// 便利初始化：所有流量走單一出站（無分流）。
    public convenience init(listenHost: String = "127.0.0.1", port: UInt16, outbound: Outbound) {
        self.init(listenHost: listenHost, port: port,
                  router: Router(rules: [], proxy: outbound, finalPolicy: .proxy))
    }

    public func start() throws {
        let router = self.router
        let server = MixedServer(host: host, port: port, onBytes: { [weak self] up, down in
            guard let self else { return }
            self.statsLock.lock()
            self.upTotal += up
            self.downTotal += down
            self.statsLock.unlock()
        }, route: { router.select($0) })
        try server.start()
        self.server = server
    }

    public func stop() {
        server?.stop()
        server = nil
    }
}
