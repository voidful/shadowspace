import Foundation
import SwiftUI
import AppKit
import CoreImage
import ShadowCore

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

    @Published var connectionState: ConnectionState = .disconnected
    @Published var upRate = 0
    @Published var downRate = 0
    @Published var sessionUpTotal = 0
    @Published var sessionDownTotal = 0
    @Published var trafficHistory: [TrafficSample] = []
    private var trafficSeq = 0
    static let trafficWindow = 60
    @Published var latencies: [UUID: Int] = [:]   // ms；測過但失敗 = -1
    @Published var isPinging = false

    @Published var connections: [ConnectionInfo] = []
    @Published var connUploadTotal = 0
    @Published var connDownloadTotal = 0

    @Published var engineLog: [String] = []
#if APP_STORE
    @Published var engineVersion: String? = nil
#else
    @Published var engineVersion: String? = EngineManager.version()
#endif
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
    private var autoUpdateTimer: Timer?
    private let netMonitor = NetworkMonitor()
    private var lastNetSatisfied = false
#if !APP_STORE
    private var tagByNodeID: [UUID: String] = [:]
    private var tagByGroupID: [UUID: String] = [:]
    private var systemProxyActive = false

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
        engine.onLog = { [weak self] line in
            Task { @MainActor in self?.appendLog(line) }
        }
        engine.onUnexpectedExit = { [weak self] status in
            Task { @MainActor in
                guard let self, self.connectionState == .connected || self.connectionState == .connecting else { return }
                self.handleUnexpectedExit(status: status)
            }
        }
        reconcileSystemStateOnLaunch()
#endif
        // 訂閱自動更新：啟動後與每 30 分鐘檢查一次是否到期
        autoUpdateTimer = Timer.scheduledTimer(withTimeInterval: 1800, repeats: true) { _ in
            Task { @MainActor in await AppState.shared.autoRefreshIfDue() }
        }
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            await self?.autoRefreshIfDue()
        }
        // On-demand：監看網路變化，必要時自動連線
        netMonitor.onChange = { [weak self] satisfied, _ in
            Task { @MainActor in self?.handleNetworkChange(satisfied: satisfied) }
        }
        netMonitor.start()
        if settings.autoCheckUpdates { checkForUpdates() }
    }

    func save() {
        let persisted = PersistedState(
            nodes: nodes, subscriptions: subscriptions, settings: settings,
            mode: mode, selectedNodeID: selectedNodeID, rules: rules, groups: groups)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        if let data = try? encoder.encode(persisted) {
            try? data.write(to: Self.stateURL)
        }
    }

    /// 儲存設定，連線中則自動套用（重啟引擎）。
    /// TUN 模式重啟需要再次授權，改成提示使用者手動重連。
    func saveAndApply() {
        save()
        guard connectionState == .connected else { return }
#if APP_STORE
        Task {
            await disconnect()
            await connect()
        }
#else
        if settings.tunMode {
            toastMessage = "已儲存，重新連線後生效"
        } else {
            Task {
                await disconnect()
                await connect()
            }
        }
#endif
    }

    private func appendLog(_ line: String) {
        engineLog.append(line)
        if engineLog.count > 800 {
            engineLog.removeFirst(engineLog.count - 800)
        }
    }

    // MARK: - 連線生命週期

    func toggleConnection() {
        switch connectionState {
        case .disconnected:
            Task { await connect() }
        case .connected:
            Task { await disconnect() }
        default:
            break
        }
    }

    /// On-demand：網路從無到有，且開了自動連線、目前斷線、有節點 → 自動連線。
    private func handleNetworkChange(satisfied: Bool) {
        defer { lastNetSatisfied = satisfied }
#if !APP_STORE
        // 主要網路服務可能變了（例如 Wi-Fi↔乙太網路）：連線中且用系統代理時，
        // 把代理重新套到新的主要服務上（enable 會先清舊的再設新的），代理才跟得上。
        if satisfied, connectionState == .connected, systemProxyActive, !settings.tunMode {
            try? SystemProxyManager.enable(port: settings.mixedPort, bypassHosts: proxyServerHosts)
        }
#endif
        guard settings.autoConnect, satisfied, !lastNetSatisfied else { return }
        guard connectionState == .disconnected, !nodes.isEmpty else { return }
        Task { await connect() }
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
            // 原生引擎能處理此節點才用它；否則（XTLS Vision / Hysteria2 / Reality-with-flow…）自動改用 sing-box，
            // 避免選到原生不支援的節點時連上卻無法通訊（表現為「打開就當機」）。
            if let node = resolvedNode, NativeEngineAdapter.isSupported(node) {
                await connectNative()
                return
            }
            engineLog = ["[原生引擎] 此節點需要原生尚未支援的功能，已自動改用 sing-box 引擎"]
        }

        do {
            // 引擎不存在就自動下載，新手不用碰終端機
            if EngineManager.findBinary() == nil {
                isInstallingEngine = true
                defer { isInstallingEngine = false }
                _ = try await EngineInstaller.installLatest { [weak self] msg in
                    Task { @MainActor in self?.engineInstallStatus = msg }
                }
                engineVersion = EngineManager.version()
                engineInstallStatus = nil
            }

            let result = SingBoxConfigBuilder.build(
                nodes: nodes, selectedID: selectedNodeID,
                settings: settings, mode: mode, groups: groups, rules: rules)
            tagByNodeID = result.tagByNodeID
            tagByGroupID = result.tagByGroupID

            engineLog.removeAll()
            let configData = try SingBoxConfigBuilder.jsonData(result.json)
            if settings.tunMode {
                try engine.startPrivileged(configData: configData)
            } else {
                try engine.start(configData: configData)
            }

            guard await api.waitReady() else {
                engine.stop()
                let tail = engineLog.suffix(5).joined(separator: "\n")
                throw EngineManager.EngineError.startFailed(
                    tail.isEmpty ? "API 無回應，可能是連接埠被占用" : tail)
            }
            await api.setMode(mode.clashMode)

            // TUN 模式由引擎接管路由，不需要動系統代理
            if !settings.tunMode && settings.autoSystemProxy {
                try SystemProxyManager.enable(port: settings.mixedPort, bypassHosts: proxyServerHosts)
                systemProxyActive = true
            }

            sessionUpTotal = 0
            sessionDownTotal = 0
            startTrafficStream()
            connectionState = .connected
            save()
        } catch {
            engine.stop()
            if systemProxyActive {
                SystemProxyManager.disable()
                systemProxyActive = false
            }
            connectionState = .disconnected
            errorMessage = error.localizedDescription
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
            try await TunnelManager.start(payload: payload)

            sessionUpTotal = 0; sessionDownTotal = 0
            upRate = 0; downRate = 0
            engineLog = ["[App Store] 透明代理已啟動，出站「\(node.name)」（\(node.proto.displayName)）"]
            connectionState = .connected
            save()
        } catch {
            connectionState = .disconnected
            errorMessage = error.localizedDescription
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
                for: node, fragment: settings.tlsFragment,
                nativeTLS: settings.nativeTLS, fingerprint: settings.tlsFingerprint)
            let router = NativeEngineAdapter.makeRouter(proxy: outbound, rules: rules, mode: mode)
            let listenHost = settings.allowLAN ? "0.0.0.0" : "127.0.0.1"
            let eng = NativeEngine(listenHost: listenHost,
                                   port: UInt16(clamping: settings.mixedPort), router: router)
            try eng.start()
            nativeEngine = eng

            if settings.autoSystemProxy {
                try SystemProxyManager.enable(port: settings.mixedPort, bypassHosts: proxyServerHosts)
                systemProxyActive = true
            }
            nativeLastUp = 0; nativeLastDown = 0
            sessionUpTotal = 0; sessionDownTotal = 0
            upRate = 0; downRate = 0
            engineLog = ["[原生引擎] 啟動於 127.0.0.1:\(settings.mixedPort)，出站「\(node.name)」（\(node.proto.displayName)）"]
            startNativeTrafficPolling()
            connectionState = .connected
            save()
        } catch {
            nativeEngine?.stop(); nativeEngine = nil
            if systemProxyActive { SystemProxyManager.disable(); systemProxyActive = false }
            connectionState = .disconnected
            errorMessage = error.localizedDescription
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
        pushTraffic(up: max(0, up - nativeLastUp), down: max(0, down - nativeLastDown))
        nativeLastUp = up; nativeLastDown = down
        sessionUpTotal = up; sessionDownTotal = down
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
        teardownAfterStop()
    }

#if !APP_STORE
    /// 引擎意外停止：Kill switch 開啟時保留系統代理（指向已停的埠）以阻擋流量外洩。
    private func handleUnexpectedExit(status: Int32) {
        if settings.killSwitch && systemProxyActive {
            engine.stop()
            nativeEngine?.stop(); nativeEngine = nil
            trafficTask?.cancel(); trafficTask = nil
            upRate = 0; downRate = 0
            trafficHistory = []
            connections = []
            connectionState = .disconnected
            errorMessage = "引擎意外停止（代碼 \(status)）。Kill switch 已啟用：系統代理保持開啟以阻擋流量外洩。請重新連線恢復上網，或結束 App 還原網路設定。"
            return
        }
        teardownAfterStop()
        errorMessage = "引擎意外停止（代碼 \(status)）。可到「日誌」分頁查看原因。"
    }
#endif

    private func teardownAfterStop() {
        trafficTask?.cancel()
        trafficTask = nil
#if !APP_STORE
        if systemProxyActive {
            SystemProxyManager.disable()
            systemProxyActive = false
        }
        engine.stop()
        nativeEngine?.stop()
        nativeEngine = nil
#endif
        upRate = 0
        downRate = 0
        trafficHistory = []
        connections = []
        connectionState = .disconnected
    }

    /// 統一更新即時速率並寫入歷史環形緩衝（流量圖用）。
    func pushTraffic(up: Int, down: Int) {
        upRate = up
        downRate = down
        trafficSeq &+= 1
        trafficHistory.append(TrafficSample(seq: trafficSeq, up: up, down: down))
        if trafficHistory.count > Self.trafficWindow {
            trafficHistory.removeFirst(trafficHistory.count - Self.trafficWindow)
        }
    }

#if !APP_STORE
    /// 啟動校正：上次若強制結束/閃退，可能殘留「系統代理開著」與「孤兒引擎」，
    /// UI 卻顯示未連線。一律回到乾淨的「未連線」狀態，避免「開關不乾淨」。
    private func reconcileSystemStateOnLaunch() {
        guard connectionState == .disconnected else { return }
        EngineManager.killOrphans()
        if SystemProxyManager.residualProxyDetected() {
            SystemProxyManager.disable()
            appendLog("[啟動] 偵測到上次殘留的系統代理，已清除並還原網路設定")
        }
    }
#endif

    /// App 結束前的同步清理：還原系統代理、停掉引擎
    func cleanupOnTerminate() {
#if !APP_STORE
        if systemProxyActive {
            SystemProxyManager.disable()
        }
        engine.stop()
        nativeEngine?.stop()
#endif
        save()
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
                            self.pushTraffic(up: sample.up, down: sample.down)
                            self.sessionUpTotal += sample.up
                            self.sessionDownTotal += sample.down
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
        guard connectionState == .connected else { return }
#if APP_STORE
        Task { await disconnect(); await connect() }
#else
        if settings.engineKind == .native {
            Task { await disconnect(); await connect() }
            return
        }
        let client = api
        Task { await client.setMode(newMode.clashMode) }
#endif
    }

    func selectNode(_ id: UUID) {
        guard isSelectableOutbound(id) else { return }
        selectedNodeID = id
        save()
        guard connectionState == .connected else { return }
#if APP_STORE
        Task { await disconnect(); await connect() }
#else
        if settings.engineKind == .native {
            Task { await disconnect(); await connect() }
            return
        }
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
    /// shadowspace://import?url=<訂閱網址> 或 ?text=<分享連結，可多行>；
    /// 後備：shadowspace://import/<百分比編碼內容>。
    func handleURL(_ url: URL) {
        guard url.scheme?.lowercased() == "shadowspace" else { return }
        let comps = URLComponents(url: url, resolvingAgainstBaseURL: false)
        if let payload = comps?.queryItems?.first(where: { $0.name == "url" || $0.name == "text" })?.value,
           !payload.isEmpty {
            Task { await importText(payload) }
            return
        }
        let tail = ((comps?.host == "import" ? "" : (comps?.host ?? "")) + (comps?.path ?? ""))
            .trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        let decoded = (tail.removingPercentEncoding ?? tail).trimmingCharacters(in: .whitespacesAndNewlines)
        if decoded.isEmpty {
            toastMessage = "無法辨識的匯入連結"
        } else {
            Task { await importText(decoded) }
        }
    }

    /// 從剪貼簿圖片掃 QR Code 匯入（截圖 QR 後直接匯入）。
    func importQRFromClipboard() async {
        guard let image = NSPasteboard.general.readObjects(forClasses: [NSImage.self])?.first as? NSImage,
              let tiff = image.tiffRepresentation,
              let ci = CIImage(data: tiff) else {
            toastMessage = "剪貼簿沒有圖片。先截圖 QR Code（⌃⌘⇧4）再試。"
            return
        }
        let detector = CIDetector(ofType: CIDetectorTypeQRCode, context: nil,
                                  options: [CIDetectorAccuracy: CIDetectorAccuracyHigh])
        let payloads = (detector?.features(in: ci) ?? [])
            .compactMap { ($0 as? CIQRCodeFeature)?.messageString }
            .filter { !$0.isEmpty }
        guard !payloads.isEmpty else {
            toastMessage = "圖片中找不到 QR Code"
            return
        }
        await importText(payloads.joined(separator: "\n"))
    }

    func importText(_ text: String) async {
        let (parsed, subURLs) = URIParser.classify(text)
        var added = 0
        for node in parsed where !isDuplicate(node) {
            nodes.append(node)
            added += 1
        }
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
            if let err = subErrors.first {
                errorMessage = err
            } else {
                errorMessage = "沒有找到可匯入的內容。支援 ss:// vmess:// vless:// trojan:// hysteria2:// tuic:// 連結或訂閱網址。"
            }
        } else {
            toastMessage = "已" + parts.joined(separator: "、")
        }
    }

    private func isDuplicate(_ node: ProxyNode) -> Bool {
        nodes.contains {
            $0.server == node.server && $0.port == node.port &&
            $0.proto == node.proto && $0.name == node.name
        }
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
        for var node in result.nodes {
            node.subscriptionID = sub.id
            nodes.append(node)
        }
        if selectedNodeID == nil { selectedNodeID = nodes.first?.id }
        save()
    }

    func refreshSubscription(_ id: UUID, quiet: Bool = false) async {
        guard let index = subscriptions.firstIndex(where: { $0.id == id }) else { return }
        do {
            let result = try await SubscriptionManager.fetch(urlString: subscriptions[index].url, userAgent: settings.subscriptionUA)
            let oldSelectedName = selectedNode?.name
            nodes.removeAll { $0.subscriptionID == id }
            for var node in result.nodes {
                node.subscriptionID = id
                nodes.append(node)
            }
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
        await TCPPing.pingAll(targets) { [weak self] id, ms in
            guard let self else { return }
            await MainActor.run {
                self.latencies[id] = ms ?? -1
            }
        }
#else
        if connectionState == .connected {
            let client = api
            let targets = nodes.compactMap { node in
                tagByNodeID[node.id].map { (id: node.id, tag: $0) }
            }
            await withTaskGroup(of: (UUID, Int?).self) { group in
                var iterator = targets.makeIterator()
                var active = 0
                func addNext(_ group: inout TaskGroup<(UUID, Int?)>) {
                    guard let t = iterator.next() else { return }
                    active += 1
                    group.addTask { (t.id, await client.urlDelay(tag: t.tag)) }
                }
                for _ in 0..<8 { addNext(&group) }
                while active > 0 {
                    if let (id, ms) = await group.next() {
                        latencies[id] = ms ?? -1
                    }
                    active -= 1
                    addNext(&group)
                }
            }
        } else {
            let targets = nodes.map { (id: $0.id, host: $0.server, port: $0.port) }
            await TCPPing.pingAll(targets) { [weak self] id, ms in
                guard let self else { return }
                await MainActor.run {
                    self.latencies[id] = ms ?? -1
                }
            }
        }
#endif
    }

    // MARK: - 連線檢視

    func startConnectionsPolling() {
#if APP_STORE
        connections = []
        connUploadTotal = 0
        connDownloadTotal = 0
#else
        guard connectionsTask == nil else { return }
        connectionsTask = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                if self.connectionState == .connected,
                   let snapshot = await self.api.connections() {
                    self.connections = snapshot.items
                    self.connUploadTotal = snapshot.uploadTotal
                    self.connDownloadTotal = snapshot.downloadTotal
                } else if !self.connections.isEmpty {
                    self.connections = []
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
    func generatedConfigJSON() -> String {
        let result = SingBoxConfigBuilder.build(
            nodes: nodes, selectedID: selectedNodeID,
            settings: settings, mode: mode, groups: groups, rules: rules)
        if let data = try? SingBoxConfigBuilder.jsonData(result.json),
           let text = String(data: data, encoding: .utf8) {
            return text
        }
        return "（無法產生設定）"
    }

    /// 匯出節點 / 群組 / 規則 / 設定為備份資料。
    func exportBackup() -> Data? {
        let persisted = PersistedState(
            nodes: nodes, subscriptions: subscriptions, settings: settings,
            mode: mode, selectedNodeID: selectedNodeID, rules: rules, groups: groups)
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try? encoder.encode(persisted)
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
