import Foundation
import SwiftUI
import AppKit
import ShadowCore

/// 狀態存檔專用序列佇列。短時間連續要求只寫入最新快照，JSON 編碼與原子寫檔
/// 都不佔用 MainActor；App 結束時可同步 flush 最後快照。
final class StatePersistenceWriter: @unchecked Sendable {
    private struct Payload: @unchecked Sendable {
        let state: PersistedState
    }

    private let url: URL
    private let queue = DispatchQueue(label: "shadowspace.state-persistence", qos: .utility)
    private let lock = NSLock()
    private var generation = 0

    init(url: URL) {
        self.url = url
    }

    func enqueue(_ state: PersistedState) {
        let token = nextGeneration()
        let payload = Payload(state: state)
        queue.asyncAfter(deadline: .now() + .milliseconds(50)) { [weak self] in
            guard let self, self.isCurrent(token) else { return }
            self.persist(payload.state)
        }
    }

    func flush(_ state: PersistedState) {
        _ = nextGeneration() // 讓尚未執行的舊快照失效
        let payload = Payload(state: state)
        queue.sync { persist(payload.state) }
    }

    private func nextGeneration() -> Int {
        lock.lock()
        generation &+= 1
        let value = generation
        lock.unlock()
        return value
    }

    private func isCurrent(_ token: Int) -> Bool {
        lock.lock()
        let current = generation == token
        lock.unlock()
        return current
    }

    private func persist(_ state: PersistedState) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        do {
            let data = try encoder.encode(state)
            try data.write(to: url, options: .atomic)
        } catch {
            NSLog("ShadowSpace: 狀態儲存失敗 %@", error.localizedDescription)
        }
    }
}

/// 匯入去重只比對既有行為使用的四個欄位，但改用 Set 將大型清單從 O(n²) 降為 O(n)。
private struct NodeDedupKey: Hashable {
    let server: String
    let port: Int
    let proto: String
    let name: String

    init(_ node: ProxyNode) {
        server = node.server
        port = node.port
        proto = node.proto.rawValue
        name = node.name
    }
}

#if !APP_STORE
/// 把設定建構的輸入與輸出包成不可變工作單，讓大型節點清單可安全在背景產生 JSON。
private struct SingBoxBuildWork: @unchecked Sendable {
    let nodes: [ProxyNode]
    let selectedID: UUID?
    let settings: AppSettings
    let mode: ProxyMode
    let groups: [ProxyGroup]
    let rules: [UserRule]
}

private struct PreparedSingBoxConfig: @unchecked Sendable {
    let data: Data
    let tagByNodeID: [UUID: String]
    let tagByGroupID: [UUID: String]
}
#endif

/// App 的中央狀態：節點、訂閱、規則、連線生命週期、流量統計。
@MainActor
final class AppState: ObservableObject {

    static let shared = AppState()

    // MARK: - 狀態

    @Published var nodes: [ProxyNode] = []
    @Published var subscriptions: [Subscription] = []
    @Published var rules: [UserRule] = []
    @Published var groups: [ProxyGroup] = []
    @Published var settings = AppSettings()
    @Published var mode: ProxyMode = .rule
    @Published var selectedNodeID: UUID?
    /// 主視窗目前分頁；提升到此處讓全域選單命令（⌘1–⌘6）可切換。
    @Published var sidebarSelection: SidebarItem = .home

    @Published var connectionState: ConnectionState = .disconnected
    /// 即時流量統計獨立成 store，避免每秒更新重繪整個 App（見 TrafficStatsStore）。
    let traffic = TrafficStatsStore()
    /// 高頻日誌與連線清單也各自隔離，避免它們發布時讓整個主視窗重繪。
    let logs = EngineLogStore()
    let connectionStats = ConnectionStatsStore()
    @Published var latencies: [UUID: Int] = [:]   // ms；測過但失敗 = -1
    @Published var isPinging = false
    @Published var engineVersion: String?         // sing-box 版本；bootstrap() 於背景查得後填入
    @Published var engineInstallStatus: String?   // 下載引擎時的進度文字
    @Published var isInstallingEngine = false

    @Published var errorMessage: String?          // 跳 alert 用
    @Published var toastMessage: String?          // 輕量回饋（匯入成功等）
    @Published var availableUpdate: UpdateInfo?   // 有新版可下載（GitHub Releases）

#if !APP_STORE
    private let engine = EngineManager()
    private var nativeEngine: NativeEngine?
    private var nativeLastUp = 0
    private var nativeLastDown = 0
#endif
    private var trafficTask: Task<Void, Never>?
    private var connectionsTask: Task<Void, Never>?
    private var autoUpdateTask: Task<Void, Never>?
    private var connectTask: Task<Void, Never>?    // 使用者手動連線的 Task，可取消
    private var persistenceTask: Task<Void, Never>?
    private var proxyReapplyTask: Task<Void, Never>?
    private lazy var persistenceWriter = StatePersistenceWriter(url: Self.stateURL)
    private var pendingRestart = false              // 連線/停止中收到的重啟請求，完成後補做
    private var applyGeneration = 0                 // saveAndApply 防抖世代計數
    private var didBootstrap = false
    private let netMonitor = NetworkMonitor()
    private var lastNetSatisfied = false
#if !APP_STORE
    private var tagByNodeID: [UUID: String] = [:]
    private var tagByGroupID: [UUID: String] = [:]
    private var systemProxyActive = false
    private let systemProxyController = SystemProxyController()

    private var api: ClashAPIClient {
        ClashAPIClient(port: settings.apiPort, secret: settings.apiSecret)
    }
#endif

    var selectedNode: ProxyNode? {
        if let id = selectedNodeID {
            return nodes.first { $0.id == id }
        }
        return nodes.first
    }

    var selectedGroup: ProxyGroup? {
        guard let id = selectedNodeID else { return nil }
        return groups.first { $0.id == id }
    }

    /// 目前選定出口的名稱（可能是節點或群組）。
    var selectedOutboundName: String {
        if let group = selectedGroup { return group.name }
        if let node = selectedNode { return node.name }
        return "—"
    }

    /// 目前接管流量的方式，以「實際啟動的引擎」為準而非設定值——
    /// 原生引擎遇不支援節點會自動回退 sing-box，此時即使 tunMode 為真也不是 TUN。
    var transportDescription: String {
#if APP_STORE
        return String(localized: "透明代理")
#else
        return (nativeEngine == nil && settings.tunMode)
            ? String(localized: "TUN 全域")
            : String(localized: "系統代理")
#endif
    }

    /// 首頁連線狀態的完整說明句。
    var transportStatusSentence: String {
#if APP_STORE
        return "透明代理已就緒，流量正透過「\(selectedOutboundName)」轉送"
#else
        if nativeEngine == nil && settings.tunMode {
            return "TUN 模式已接管全部流量，正透過「\(selectedOutboundName)」轉送"
        }
        return "系統代理已就緒，流量正透過「\(selectedOutboundName)」轉送"
#endif
    }

    /// sing-box Tailscale endpoint 在未登入時會把驗證網址寫進日誌；抽出來讓設定頁可直接開啟。
    nonisolated static func tailscaleLoginURL(in lines: [String]) -> URL? {
        for text in lines.reversed() {
            let lower = text.lowercased()
            guard lower.contains("tailscale") || lower.contains("authenticate") || lower.contains("login") else {
                continue
            }
            guard let range = text.range(of: #"https://[^\s\]\)\}\"]+"#,
                                         options: .regularExpression) else { continue }
            let value = String(text[range]).trimmingCharacters(in: CharacterSet(charactersIn: ".,"))
            if let url = URL(string: value) { return url }
        }
        return nil
    }

    /// 系統代理需繞過的主機：所有節點的伺服器位址。
    /// 避免引擎連往代理伺服器的流量又被系統代理繞回本機代理埠（= 引擎自己）形成迴圈。
    var proxyServerHosts: [String] {
        Array(Set(nodes.map { $0.server }.filter {
            !$0.trimmingCharacters(in: .whitespaces).isEmpty
        }))
    }

    /// 把選定出口解析成實際節點（群組 → 第一個成員節點）。原生 / App Store 引擎用。
    var resolvedNode: ProxyNode? {
        if let id = selectedNodeID {
            if let n = nodes.first(where: { $0.id == id }) { return n }
            if let g = groups.first(where: { $0.id == id }) {
                return g.memberNodeIDs.lazy.compactMap { mid in self.nodes.first { $0.id == mid } }.first
            }
        }
        return nodes.first
    }

    // MARK: - 初始化與持久化

    static var supportDir: URL {
#if APP_STORE
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir = base.appendingPathComponent("ShadowSpace", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
#else
        return EngineManager.supportDir
#endif
    }

    private static var stateURL: URL {
        supportDir.appendingPathComponent("state.json")
    }

    init() {
        if let data = try? Data(contentsOf: Self.stateURL),
           let persisted = try? JSONDecoder().decode(PersistedState.self, from: data) {
            nodes = persisted.nodes
            subscriptions = persisted.subscriptions
            rules = persisted.rules
            groups = persisted.groups
            settings = persisted.settings
            mode = persisted.mode
            selectedNodeID = persisted.selectedNodeID
        }
#if !APP_STORE
        engine.onLog = { [weak self] lines in
            Task { @MainActor in self?.logs.append(contentsOf: lines) }
        }
        engine.onUnexpectedExit = { [weak self] status in
            Task { @MainActor in
                guard let self, self.connectionState == .connected || self.connectionState == .connecting else { return }
                await self.handleUnexpectedExit(status: status)
            }
        }
#endif
    }

    /// 啟動副作用：殘留代理清理、引擎版本查詢、訂閱自動更新排程、網路監看。
    /// 由 AppDelegate.applicationDidFinishLaunching 呼叫——移出 init 避免卡第一幀。
    func bootstrap() {
        guard !didBootstrap else { return }
        didBootstrap = true
        Task { [weak self] in
            guard let self else { return }
#if !APP_STORE
            // 殘留清理與版本查詢牽涉子程序與檔案系統，丟背景執行緒別卡主執行緒；
            // 但必須「先清完再開網路監看」——否則 auto-connect 會與清理搶跑，
            // 剛設好的系統代理被誤判為殘留清掉（表現為連上卻不走代理）。
            let outcome = await Task.detached { () -> (version: String?, residual: Bool) in
                EngineManager.killOrphans()
                let residual = SystemProxyManager.residualProxyDetected()
                if residual { SystemProxyManager.disable() }
                return (EngineManager.version(), residual)
            }.value
            self.engineVersion = outcome.version
            if outcome.residual {
                self.appendLog("[啟動] 偵測到上次殘留的系統代理，已清除並還原網路設定")
            }
#endif
            self.startBackgroundServices()
        }
    }

    /// 開始背景服務：訂閱自動更新排程與網路監看（auto-connect）。
    /// 一定在殘留清理完成後才呼叫，避免 auto-connect 與清理搶跑。
    private func startBackgroundServices() {
        // 訂閱自動更新：啟動 3 秒後首查，之後每 30 分鐘一次。
        autoUpdateTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(3))
            while !Task.isCancelled {
                guard let self else { return }
                await self.autoRefreshIfDue()
                try? await Task.sleep(for: .seconds(1800))
            }
        }
        // On-demand：監看網路變化，必要時自動連線
        netMonitor.onChange = { [weak self] satisfied, _ in
            Task { @MainActor in self?.handleNetworkChange(satisfied: satisfied) }
        }
        netMonitor.start()
        if settings.autoCheckUpdates { checkForUpdates() }
    }

    private func snapshot() -> PersistedState {
        PersistedState(
            nodes: nodes, subscriptions: subscriptions, settings: settings,
            mode: mode, selectedNodeID: selectedNodeID, rules: rules, groups: groups)
    }

    private static func encodeState(_ state: PersistedState) -> Data? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try? encoder.encode(state)
    }

    /// settings 欄位的雙向綁定，變更後只存檔（不需重連的設定：埠、更新間隔、開關偏好…）。
    func setting<Value>(_ keyPath: WritableKeyPath<AppSettings, Value>) -> Binding<Value> {
        Binding(
            get: { self.settings[keyPath: keyPath] },
            set: { self.settings[keyPath: keyPath] = $0; self.scheduleSave() }
        )
    }

    /// settings 欄位的雙向綁定，變更後存檔並套用（連線中即時重連生效：引擎、DNS、規則開關…）。
    func appliedSetting<Value>(_ keyPath: WritableKeyPath<AppSettings, Value>) -> Binding<Value> {
        Binding(
            get: { self.settings[keyPath: keyPath] },
            set: { self.settings[keyPath: keyPath] = $0; self.saveAndApply() }
        )
    }

    /// 將不可變快照交給背景序列佇列；JSON 編碼與原子寫檔不阻塞主執行緒。
    /// 佇列會合併短時間內的連續要求，只落盤最新狀態。
    func save() {
        persistenceWriter.enqueue(snapshot())
    }

    /// 連續輸入時合併存檔，避免每個按鍵都在主執行緒編碼整份節點資料並原子寫檔。
    /// App 結束時 cleanupOnTerminate 仍會同步補寫最後狀態。
    private func scheduleSave() {
        persistenceTask?.cancel()
        persistenceTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(300))
            guard !Task.isCancelled, let self else { return }
            self.save()
            self.persistenceTask = nil
        }
    }

    /// 儲存設定，連線中則自動套用（重啟引擎）。
    /// 用 800ms 防抖＋世代計數合併連續切換（例如快速改多個設定），避免每次都重連一輪。
    /// TUN 模式重啟需要再次授權，改成提示使用者手動重連。
    func saveAndApply() {
        scheduleSave()
        guard connectionState != .disconnected else { return }
#if !APP_STORE
        if settings.tunMode {
            toastMessage = "已儲存，重新連線後生效"
            return
        }
#endif
        applyGeneration += 1
        let gen = applyGeneration
        toastMessage = "正在套用設定…"
        Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(800))
            guard let self, gen == self.applyGeneration else { return }
            self.restartIfConnected()
        }
    }

    /// 統一的「套用設定＝重連」入口。連線/停止中時記下 pendingRestart，等狀態回穩再補做，
    /// 避免在過渡狀態下重複觸發連線。
    private func restartIfConnected() {
        switch connectionState {
        case .connected:
            pendingRestart = false
            Task { [weak self] in
                guard let self else { return }
                await self.disconnect()
                await self.connect()
                if self.connectionState == .connected {
                    self.toastMessage = "設定已套用"
                }
                if self.pendingRestart { self.restartIfConnected() }
            }
        case .connecting, .stopping:
            pendingRestart = true
        case .disconnected:
            break
        }
    }

    private func appendLog(_ line: String) {
        logs.append(line)
    }

    // MARK: - 連線生命週期

    func toggleConnection() {
        switch connectionState {
        case .disconnected:
            connectTask = Task { [weak self] in await self?.connect() }
        case .connecting:
            // 連線中（尤其首次下載引擎）再按一次＝取消，別把使用者鎖在轉圈狀態。
            connectTask?.cancel()
        case .connected:
            Task { [weak self] in await self?.disconnect() }
        case .stopping:
            break
        }
    }

    /// On-demand：網路從無到有，且開了自動連線、目前斷線、有節點 → 自動連線。
    private func handleNetworkChange(satisfied: Bool) {
        defer { lastNetSatisfied = satisfied }
#if !APP_STORE
        // 主要網路服務可能變了（例如 Wi-Fi↔乙太網路）：防抖後交給背景序列控制器。
        // 控制器會比對已套用狀態；代理設定自己觸發的重複 NWPath 事件不會再執行 networksetup。
        if satisfied, connectionState == .connected, systemProxyActive, !settings.tunMode {
            proxyReapplyTask?.cancel()
            proxyReapplyTask = Task { [weak self] in
                try? await Task.sleep(for: .milliseconds(300))
                guard !Task.isCancelled, let self,
                      self.connectionState == .connected,
                      self.systemProxyActive else { return }
                do {
                    _ = try await self.systemProxyController.enableIfNeeded(
                        port: self.settings.mixedPort,
                        bypassHosts: self.proxyServerHosts)
                } catch {
                    self.appendLog("[系統代理] 網路切換後重新套用失敗：\(error.localizedDescription)")
                }
                self.proxyReapplyTask = nil
            }
        }
#endif
        guard settings.autoConnect, satisfied, !lastNetSatisfied else { return }
        guard connectionState == .disconnected, !nodes.isEmpty else { return }
        connectTask = Task { [weak self] in await self?.connect() }
    }

    func connect() async {
        guard connectionState == .disconnected else { return }
        guard !nodes.isEmpty else {
            errorMessage = "還沒有任何節點。先到「節點」分頁貼上分享連結或訂閱，馬上就能連線。"
            return
        }
        normalizeSelectedOutbound()
        connectionState = .connecting

#if APP_STORE
        await connectAppStoreTunnel()
        return
#else
        if settings.engineKind == .native {
            // 原生引擎能處理此節點才用它；否則（Hysteria2 / TUIC / VMess / 非 Vision 的 VLESS flow…）自動改用 sing-box，
            // 避免選到原生不支援的節點時連上卻無法通訊（表現為「打開就當機」）。
            if let node = resolvedNode, NativeEngineAdapter.isSupported(node) {
                await connectNative()
                return
            }
            logs.replace(with: ["[原生引擎] 此節點需要原生尚未支援的功能，已自動改用 sing-box 引擎"])
        }

        do {
            // 引擎不存在就自動下載，新手不用碰終端機
            if EngineManager.findBinary() == nil {
                isInstallingEngine = true
                defer { isInstallingEngine = false }
                _ = try await EngineInstaller.installLatest { [weak self] msg in
                    Task { @MainActor in self?.engineInstallStatus = msg }
                }
                try Task.checkCancellation()   // 下載期間使用者按取消
                engineVersion = EngineManager.version()
                engineInstallStatus = nil
            }

            let work = SingBoxBuildWork(
                nodes: nodes, selectedID: selectedNodeID,
                settings: settings, mode: mode, groups: groups, rules: rules)
            let prepared = try await Task.detached(priority: .userInitiated) {
                let result = SingBoxConfigBuilder.build(
                    nodes: work.nodes, selectedID: work.selectedID,
                    settings: work.settings, mode: work.mode,
                    groups: work.groups, rules: work.rules)
                return PreparedSingBoxConfig(
                    data: try SingBoxConfigBuilder.jsonData(result.json),
                    tagByNodeID: result.tagByNodeID,
                    tagByGroupID: result.tagByGroupID)
            }.value
            tagByNodeID = prepared.tagByNodeID
            tagByGroupID = prepared.tagByGroupID

            logs.clear()
            try Task.checkCancellation()   // 啟動引擎前（含引擎已安裝的常見路徑）給取消一個機會
            if settings.tunMode {
                try engine.startPrivileged(configData: prepared.data)
            } else {
                try engine.start(configData: prepared.data)
            }

            guard await api.waitReady() else {
                engine.stop()
                let tail = logs.tailText(limit: 5)
                throw EngineManager.EngineError.startFailed(
                    tail.isEmpty ? "API 無回應，可能是連接埠被占用" : tail)
            }
            try Task.checkCancellation()   // 引擎起來後、動系統代理前再檢查一次（catch 會 engine.stop()）
            await api.setMode(mode.clashMode)

            // TUN 模式由引擎接管路由，不需要動系統代理
            if !settings.tunMode && settings.autoSystemProxy {
                try await systemProxyController.enableIfNeeded(
                    port: settings.mixedPort, bypassHosts: proxyServerHosts)
                systemProxyActive = true
                try Task.checkCancellation()
            }

            traffic.resetSession()
            startTrafficStream()
            connectionState = .connected
            save()
        } catch {
            engine.stop()
            if systemProxyActive {
                await systemProxyController.disable()
                systemProxyActive = false
            }
            connectionState = .disconnected
            engineInstallStatus = nil
            if error is CancellationError || (error as? URLError)?.code == .cancelled {
                toastMessage = "已取消連線"
            } else {
                errorMessage = error.localizedDescription
            }
        }
#endif
    }

    // MARK: - 原生引擎（App Store 路線）

#if APP_STORE
    private func connectAppStoreTunnel() async {
        guard let node = resolvedNode else {
            connectionState = .disconnected
            errorMessage = "找不到可用節點"
            return
        }
        do {
            _ = try NativeEngineAdapter.outbound(for: node)
            let payload = try SharedConfig.makePayload(node: node, rules: rules,
                                                       mode: mode, settings: settings)
            try Task.checkCancellation()   // 啟動穿隧前給取消一個機會
            try await TunnelManager.start(payload: payload)

            traffic.resetSession()
            logs.replace(with: ["[App Store] 透明代理已啟動，出站「\(node.name)」（\(node.proto.displayName)）"])
            connectionState = .connected
            save()
        } catch {
            connectionState = .disconnected
            if error is CancellationError {
                toastMessage = "已取消連線"
            } else {
                errorMessage = error.localizedDescription
            }
        }
    }
#else

    private func connectNative() async {
        guard let node = resolvedNode else {
            connectionState = .disconnected
            errorMessage = "找不到可用節點"
            return
        }
        do {
            let outbound = try NativeEngineAdapter.outbound(
                for: node,
                tls: .init(fragment: settings.tlsFragment,
                           nativeTLS: settings.nativeTLS,
                           fingerprint: settings.tlsFingerprint))
            let router = NativeEngineAdapter.makeRouter(proxy: outbound, rules: rules, mode: mode)
            let listenHost = settings.allowLAN ? "0.0.0.0" : "127.0.0.1"
            let eng = NativeEngine(listenHost: listenHost,
                                   port: UInt16(clamping: settings.mixedPort), router: router)
            try eng.start()
            nativeEngine = eng
            try Task.checkCancellation()   // 引擎起來後、動系統代理前給取消一個機會（catch 會停掉引擎）

            if settings.autoSystemProxy {
                try await systemProxyController.enableIfNeeded(
                    port: settings.mixedPort, bypassHosts: proxyServerHosts)
                systemProxyActive = true
                try Task.checkCancellation()
            }
            nativeLastUp = 0; nativeLastDown = 0
            traffic.resetSession()
            logs.replace(with: ["[原生引擎] 啟動於 127.0.0.1:\(settings.mixedPort)，出站「\(node.name)」（\(node.proto.displayName)）"])
            startNativeTrafficPolling()
            connectionState = .connected
            save()
        } catch {
            nativeEngine?.stop(); nativeEngine = nil
            if systemProxyActive {
                await systemProxyController.disable()
                systemProxyActive = false
            }
            connectionState = .disconnected
            if error is CancellationError {
                toastMessage = "已取消連線"
            } else {
                errorMessage = error.localizedDescription
            }
        }
    }
#endif

#if !APP_STORE
    private func startNativeTrafficPolling() {
        trafficTask?.cancel()
        trafficTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 1_000_000_000)
                guard let self else { return }
                self.pollNativeTraffic()
            }
        }
    }

    private func pollNativeTraffic() {
        guard let eng = nativeEngine else { return }
        let up = eng.upTotal, down = eng.downTotal
        traffic.push(up: max(0, up - nativeLastUp), down: max(0, down - nativeLastDown),
                     totalUp: up, totalDown: down)
        nativeLastUp = up; nativeLastDown = down
    }
#endif

    func disconnect() async {
        guard connectionState == .connected else { return }
        connectionState = .stopping
#if APP_STORE
        do {
            try await TunnelManager.stop()
        } catch {
            errorMessage = error.localizedDescription
        }
#endif
        await teardownAfterStop()
    }

#if !APP_STORE
    /// 引擎意外停止：Kill switch 開啟時保留系統代理（指向已停的埠）以阻擋流量外洩。
    private func handleUnexpectedExit(status: Int32) async {
        // 必須在 teardown 之前擷取——teardown 會把 systemProxyActive 清成 false。
        let keepProxy = settings.killSwitch && systemProxyActive
        await teardownAfterStop(keepSystemProxy: keepProxy)
        errorMessage = keepProxy
            ? "引擎意外停止（代碼 \(status)）。Kill switch 已啟用：系統代理保持開啟以阻擋流量外洩。請重新連線恢復上網，或結束 App 還原網路設定。"
            : "引擎意外停止（代碼 \(status)）。可到「日誌」分頁查看原因。"
    }
#endif

    private func teardownAfterStop(keepSystemProxy: Bool = false) async {
        trafficTask?.cancel()
        trafficTask = nil
#if !APP_STORE
        proxyReapplyTask?.cancel()
        proxyReapplyTask = nil
        if systemProxyActive && !keepSystemProxy {
            await systemProxyController.disable()
            systemProxyActive = false
        }
        engine.stop()
        nativeEngine?.stop()
        nativeEngine = nil
#endif
        traffic.clearLive()
        connectionStats.clear()
        connectionState = .disconnected
    }

    /// App 結束前的同步清理：還原系統代理、停掉引擎、確保狀態落盤。
    func cleanupOnTerminate() {
#if !APP_STORE
        proxyReapplyTask?.cancel()
        proxyReapplyTask = nil
        if systemProxyActive {
            systemProxyController.disableSynchronously()
        }
        engine.stop()
        nativeEngine?.stop()
#endif
        persistenceTask?.cancel()
        persistenceTask = nil
        persistenceWriter.flush(snapshot())
    }

#if !APP_STORE
    private func startTrafficStream() {
        trafficTask?.cancel()
        let client = api
        trafficTask = Task { [weak self] in
            guard let lines = try? await client.trafficLines() else { return }
            do {
                for try await line in lines {
                    guard !Task.isCancelled else { return }
                    if let sample = ClashAPIClient.parseTrafficLine(line) {
                        await MainActor.run {
                            guard let self else { return }
                            self.traffic.push(up: sample.up, down: sample.down)
                        }
                    }
                }
            } catch {
                // 串流中斷（引擎停止）就結束，不需處理
            }
        }
    }
#endif

    // MARK: - 模式 / 節點切換

    func setMode(_ newMode: ProxyMode) {
        mode = newMode
        save()
#if APP_STORE
        restartIfConnected()
#else
        if settings.engineKind == .native {
            restartIfConnected()
            return
        }
        // sing-box 可熱切換模式，不需重連
        guard connectionState == .connected else { return }
        let client = api
        Task { await client.setMode(newMode.clashMode) }
#endif
    }

    func selectNode(_ id: UUID) {
        guard isSelectableOutbound(id) else { return }
        selectedNodeID = id
        save()
#if APP_STORE
        restartIfConnected()
#else
        if settings.engineKind == .native {
            restartIfConnected()
            return
        }
        // sing-box 可熱切換出口，不需重連
        guard connectionState == .connected else { return }
        guard let tag = tagByGroupID[id] ?? tagByNodeID[id] else { return }
        let client = api
        Task { [weak self] in
            do {
                try await client.selectNode(group: SingBoxConfigBuilder.selectorTag, tag: tag)
            } catch {
                await MainActor.run {
                    self?.toastMessage = "節點切換失敗，已記住選擇，重新連線後生效"
                }
            }
        }
#endif
    }

    // MARK: - 匯入

    /// 從剪貼簿匯入：自動判斷是節點連結還是訂閱連結
    func importFromClipboard() async {
        guard let text = NSPasteboard.general.string(forType: .string),
              !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            toastMessage = "剪貼簿是空的，先複製節點或訂閱連結"
            return
        }
        await importText(text)
    }

    /// 處理 shadowspace:// URL（從瀏覽器/其他 App 一鍵匯入）。
    func handleURL(_ url: URL) {
        switch ImportService.classifyURL(url) {
        case .notOurs:
            break
        case .unrecognized:
            toastMessage = "無法辨識的匯入連結"
        case .payload(let text):
            Task { await importText(text) }
        }
    }

    /// 從剪貼簿圖片掃 QR Code 匯入（截圖 QR 後直接匯入）。
    func importQRFromClipboard() async {
        guard let imageData = ImportService.qrImageDataFromClipboard() else {
            toastMessage = "剪貼簿沒有圖片。先截圖 QR Code（⌃⌘⇧4）再試。"
            return
        }
        let payloads = await Task.detached(priority: .userInitiated) {
            ImportService.qrPayloads(imageData: imageData)
        }.value
        guard !payloads.isEmpty else {
            toastMessage = "圖片中找不到 QR Code"
            return
        }
        await importText(payloads.joined(separator: "\n"))
    }

    /// 匯入節點/訂閱。成功回 nil；失敗回錯誤訊息。
    /// reportFailure 為真時（預設）失敗會跳全域 errorMessage；貼上 sheet 想就地顯示錯誤時傳 false。
    @discardableResult
    func importText(_ text: String, reportFailure: Bool = true) async -> String? {
        // 大型 base64 / YAML 分享內容的拆解與 JSON 解碼不應佔用 MainActor。
        let (parsed, subURLs, unparsed) = await Task.detached(priority: .userInitiated) {
            URIParser.classify(text)
        }.value
        var known = Set(nodes.map(NodeDedupKey.init))
        var addedNodes: [ProxyNode] = []
        addedNodes.reserveCapacity(parsed.count)
        for node in parsed where known.insert(NodeDedupKey(node)).inserted {
            addedNodes.append(node)
        }
        if !addedNodes.isEmpty {
            // 一次發布，避免數千個節點逐筆讓 SwiftUI 重繪。
            nodes.append(contentsOf: addedNodes)
        }
        let added = addedNodes.count
        var subAdded = 0
        var subErrors: [String] = []
        for urlString in subURLs {
            do {
                try await addSubscription(urlString)
                subAdded += 1
            } catch {
                subErrors.append(error.localizedDescription)
            }
        }
        if selectedNodeID == nil { selectedNodeID = nodes.first?.id }
        save()

        var parts: [String] = []
        if added > 0 { parts.append("匯入 \(added) 個節點") }
        if subAdded > 0 { parts.append("新增 \(subAdded) 個訂閱") }
        if parts.isEmpty {
#if APP_STORE
            let noneFound = "沒有找到可匯入的內容。支援 \(URIParser.appStoreSupportedSchemesText) 連結或訂閱網址。"
#else
            let noneFound = "沒有找到可匯入的內容。支援 \(URIParser.supportedSchemesText) 連結或訂閱網址。"
#endif
            let err = subErrors.first ?? noneFound
            if reportFailure { errorMessage = err }
            return err
        }
        var summary = "已" + parts.joined(separator: "、")
        if !unparsed.isEmpty { summary += "；另有 \(unparsed.count) 行無法辨識" }
        toastMessage = summary
        return nil
    }

    /// 手動新增或編輯節點
    func upsertNode(_ node: ProxyNode) {
        if let index = nodes.firstIndex(where: { $0.id == node.id }) {
            nodes[index] = node
            save()
            // 改到目前使用中的節點 → 需要重建設定
            if connectionState == .connected && node.id == selectedNodeID {
                saveAndApply()
            }
            toastMessage = "已更新「\(node.name)」"
        } else {
            nodes.append(node)
            if selectedNodeID == nil { selectedNodeID = node.id }
            save()
            toastMessage = "已新增「\(node.name)」"
        }
    }

    // MARK: - 訂閱

    func addSubscription(_ urlString: String) async throws {
        let trimmed = urlString.trimmingCharacters(in: .whitespacesAndNewlines)
        if subscriptions.contains(where: { $0.url == trimmed }) {
            // 已存在就當作更新
            if let existing = subscriptions.first(where: { $0.url == trimmed }) {
                await refreshSubscription(existing.id)
            }
            return
        }
        let result = try await SubscriptionManager.fetch(urlString: trimmed, userAgent: settings.subscriptionUA)
        var sub = Subscription(name: result.suggestedName ?? "訂閱", url: trimmed)
        sub.lastUpdated = Date()
        sub.rawUserInfo = result.userInfo
        subscriptions.append(sub)
        let incoming = result.nodes.map { node -> ProxyNode in
            var node = node
            node.subscriptionID = sub.id
            return node
        }
        if !incoming.isEmpty {
            nodes.append(contentsOf: incoming)
        }
        if selectedNodeID == nil { selectedNodeID = nodes.first?.id }
        save()
    }

    func refreshSubscription(_ id: UUID, quiet: Bool = false) async {
        guard let index = subscriptions.firstIndex(where: { $0.id == id }) else { return }
        do {
            let result = try await SubscriptionManager.fetch(urlString: subscriptions[index].url, userAgent: settings.subscriptionUA)
            let oldSelectedName = selectedNode?.name
            let incoming = result.nodes.map { node -> ProxyNode in
                var node = node
                node.subscriptionID = id
                return node
            }
            // 替換整個陣列只發布一次，避免更新大型訂閱時清除一次再逐節點重繪。
            nodes = nodes.filter { $0.subscriptionID != id } + incoming
            subscriptions[index].lastUpdated = Date()
            subscriptions[index].rawUserInfo = result.userInfo
            // 盡量保住原本選的節點（依名稱比對）
            if !isSelectableOutbound(selectedNodeID) {
                selectedNodeID = nodes.first { $0.name == oldSelectedName }?.id ?? nodes.first?.id
            }
            save()
            if !quiet {
                toastMessage = "「\(subscriptions[index].name)」已更新，共 \(result.nodes.count) 個節點"
            }
        } catch {
            if !quiet {
                errorMessage = error.localizedDescription
            }
        }
    }

    func refreshAllSubscriptions() async {
        for sub in subscriptions {
            await refreshSubscription(sub.id)
        }
    }

    /// 訂閱自動更新（過了設定的間隔才抓）
    func autoRefreshIfDue() async {
        let hours = settings.subAutoUpdateHours
        guard hours > 0 else { return }
        for sub in subscriptions {
            let due = sub.lastUpdated.map {
                Date().timeIntervalSince($0) > Double(hours) * 3600
            } ?? true
            if due {
                await refreshSubscription(sub.id, quiet: true)
            }
        }
    }

    func deleteSubscription(_ id: UUID) {
        subscriptions.removeAll { $0.id == id }
        nodes.removeAll { $0.subscriptionID == id }
        if !isSelectableOutbound(selectedNodeID) {
            selectedNodeID = nodes.first?.id
        }
        save()
    }

    func deleteNode(_ id: UUID) {
        nodes.removeAll { $0.id == id }
        latencies.removeValue(forKey: id)
        for i in groups.indices { groups[i].memberNodeIDs.removeAll { $0 == id } }
        if !isSelectableOutbound(selectedNodeID) {
            selectedNodeID = nodes.first?.id
        }
        save()
    }

    // MARK: - 代理群組

    func upsertGroup(_ group: ProxyGroup) {
        if let index = groups.firstIndex(where: { $0.id == group.id }) {
            groups[index] = group
        } else {
            groups.append(group)
        }
        saveAndApply()
    }

    func deleteGroup(_ id: UUID) {
        groups.removeAll { $0.id == id }
        if selectedNodeID == id { selectedNodeID = nodes.first?.id }
        saveAndApply()
    }

    // MARK: - 自訂規則

    func upsertRule(_ rule: UserRule) {
        if let index = rules.firstIndex(where: { $0.id == rule.id }) {
            rules[index] = rule
        } else {
            rules.append(rule)
        }
        saveAndApply()
    }

    func deleteRule(_ id: UUID) {
        rules.removeAll { $0.id == id }
        saveAndApply()
    }

    func moveRules(from source: IndexSet, to destination: Int) {
        rules.move(fromOffsets: source, toOffset: destination)
        saveAndApply()
    }

    func toggleRule(_ id: UUID, enabled: Bool) {
        guard let index = rules.firstIndex(where: { $0.id == id }) else { return }
        rules[index].enabled = enabled
        saveAndApply()
    }

    // MARK: - 延遲測試

    /// 未連線：TCP 握手延遲；連線中：透過引擎做真實 URL 測試
    func pingAllNodes() async {
        guard !isPinging, !nodes.isEmpty else { return }
        isPinging = true
        defer { isPinging = false }

#if APP_STORE
        let targets = nodes.map { (id: $0.id, host: $0.server, port: $0.port) }
        let results = await TCPPing.pingAll(targets, maxConcurrent: settings.latencyTestConcurrency)
        latencies.merge(results) { _, new in new }
#else
        if connectionState == .connected, nativeEngine == nil {
            let client = api
            let testURL = settings.effectiveLatencyTestURL
            let maxConcurrent = min(64, max(1, settings.latencyTestConcurrency))
            let targets = nodes.compactMap { node in
                tagByNodeID[node.id].map { (id: node.id, tag: $0) }
            }
            var results: [UUID: Int] = [:]
            results.reserveCapacity(targets.count)
            await withTaskGroup(of: (UUID, Int?).self) { group in
                var iterator = targets.makeIterator()
                var active = 0
                func addNext(_ group: inout TaskGroup<(UUID, Int?)>) {
                    guard let t = iterator.next() else { return }
                    active += 1
                    group.addTask {
                        (t.id, await client.urlDelay(tag: t.tag, url: testURL))
                    }
                }
                for _ in 0..<maxConcurrent { addNext(&group) }
                while active > 0 {
                    if let (id, ms) = await group.next() {
                        results[id] = ms ?? -1
                    }
                    active -= 1
                    addNext(&group)
                }
            }
            latencies.merge(results) { _, new in new }
        } else {
            let targets = nodes.map { (id: $0.id, host: $0.server, port: $0.port) }
            let results = await TCPPing.pingAll(targets, maxConcurrent: settings.latencyTestConcurrency)
            latencies.merge(results) { _, new in new }
        }
#endif
        toastMessage = "延遲測試完成（\(nodes.count) 個節點）"
    }

    /// 只測單一節點（節點右鍵選單用）。連線中鏡射批次測試的引擎 URL 測試路徑，
    /// 未連線走 TCP 握手——系統代理開啟時 TCPPing 會被繞行、量不到真實延遲，故連線中不可用它。
    func pingNode(_ id: UUID) async {
        guard let node = nodes.first(where: { $0.id == id }) else { return }
#if APP_STORE
        latencies[id] = await TCPPing.ping(host: node.server, port: node.port) ?? -1
#else
        if connectionState == .connected, nativeEngine == nil, let tag = tagByNodeID[id] {
            latencies[id] = await api.urlDelay(tag: tag, url: settings.effectiveLatencyTestURL) ?? -1
        } else {
            latencies[id] = await TCPPing.ping(host: node.server, port: node.port) ?? -1
        }
#endif
    }

    // MARK: - 連線檢視

    func startConnectionsPolling() {
#if APP_STORE
        connectionStats.clear()
#else
        guard connectionsTask == nil else { return }
        connectionsTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                if self.connectionState == .connected,
                   let snapshot = await self.api.connections() {
                    self.connectionStats.update(items: snapshot.items,
                                                uploadTotal: snapshot.uploadTotal,
                                                downloadTotal: snapshot.downloadTotal)
                } else if !self.connectionStats.items.isEmpty {
                    self.connectionStats.clear()
                }
                try? await Task.sleep(nanoseconds: 1_000_000_000)
            }
        }
#endif
    }

    func stopConnectionsPolling() {
        connectionsTask?.cancel()
        connectionsTask = nil
    }

    func closeConnection(_ id: String) {
#if !APP_STORE
        let client = api
        Task { await client.closeConnection(id) }
#endif
    }

    func closeAllConnections() {
#if !APP_STORE
        let client = api
        Task { await client.closeAllConnections() }
#endif
    }

    // MARK: - 進階 / 備份

    /// 產生目前設定對應的 sing-box 設定（JSON 字串，除錯用）。
    /// App Store 版不含 sing-box（SingBoxConfigBuilder 未編入該 target），回提示字串即可。
    func generatedConfigJSON() -> String {
#if APP_STORE
        return "（App Store 版使用原生代理核心，不產生 sing-box 設定）"
#else
        let result = SingBoxConfigBuilder.build(
            nodes: nodes, selectedID: selectedNodeID,
            settings: settings, mode: mode, groups: groups, rules: rules)
        if let data = try? SingBoxConfigBuilder.jsonData(result.json),
           let text = String(data: data, encoding: .utf8) {
            return text
        }
        return "（無法產生設定）"
#endif
    }

    /// 匯出節點 / 群組 / 規則 / 設定為備份資料。
    func exportBackup() -> Data? {
        Self.encodeState(snapshot())
    }

    /// 從備份資料還原（覆蓋目前所有設定）。
    @discardableResult
    func importBackup(_ data: Data) -> Bool {
        guard let p = try? JSONDecoder().decode(PersistedState.self, from: data) else {
            errorMessage = "備份檔格式不正確，無法匯入。"
            return false
        }
        nodes = p.nodes
        subscriptions = p.subscriptions
        rules = p.rules
        groups = p.groups
        settings = p.settings
        mode = p.mode
        selectedNodeID = p.selectedNodeID
        normalizeSelectedOutbound()
        save()
        toastMessage = "已匯入備份（\(p.nodes.count) 節點、\(p.groups.count) 群組）"
        return true
    }

    // MARK: - 更新檢查

    /// 檢查 GitHub Releases 是否有新版。App Store 版由商店更新，不在此檢查。
    func checkForUpdates(manual: Bool = false) {
#if !APP_STORE
        Task { [weak self] in
            let release = await UpdateChecker.latest()
            guard let self else { return }
            guard let release else {
                if manual { self.toastMessage = "無法檢查更新，請稍後再試" }
                return
            }
            let current = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0"
            if UpdateChecker.isNewer(release.version, than: current) {
                self.availableUpdate = UpdateInfo(version: release.version, url: release.htmlURL, notes: release.notes)
                if manual { self.toastMessage = "發現新版本 \(release.version)" }
            } else {
                self.availableUpdate = nil
                if manual { self.toastMessage = "已是最新版本（\(current)）" }
            }
        }
#else
        if manual { toastMessage = "App Store 版由商店自動更新" }
#endif
    }

    // MARK: - 引擎安裝

    func installOrUpdateEngine() async {
#if APP_STORE
        toastMessage = "App Store 版使用系統 NetworkExtension，不需要安裝外部核心"
#else
        guard !isInstallingEngine else { return }
        isInstallingEngine = true
        defer { isInstallingEngine = false }
        do {
            let version = try await EngineInstaller.installLatest { [weak self] msg in
                Task { @MainActor in self?.engineInstallStatus = msg }
            }
            engineVersion = version
            engineInstallStatus = nil
            toastMessage = "引擎已安裝：\(version)"
        } catch {
            engineInstallStatus = nil
            errorMessage = error.localizedDescription
        }
#endif
    }

    private func isSelectableOutbound(_ id: UUID?) -> Bool {
        guard let id else { return false }
        return nodes.contains { $0.id == id } || groups.contains { $0.id == id }
    }

    private func normalizeSelectedOutbound() {
        guard !isSelectableOutbound(selectedNodeID) else { return }
        selectedNodeID = nodes.first?.id ?? groups.first?.id
    }
}
