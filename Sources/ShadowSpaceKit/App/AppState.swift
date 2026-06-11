import Foundation
import SwiftUI
import AppKit

/// App 的中央狀態：節點、訂閱、規則、連線生命週期、流量統計。
@MainActor
final class AppState: ObservableObject {

    static let shared = AppState()

    // MARK: - 狀態

    @Published var nodes: [ProxyNode] = []
    @Published var subscriptions: [Subscription] = []
    @Published var rules: [UserRule] = []
    @Published var settings = AppSettings()
    @Published var mode: ProxyMode = .rule
    @Published var selectedNodeID: UUID?

    @Published var connectionState: ConnectionState = .disconnected
    @Published var upRate = 0
    @Published var downRate = 0
    @Published var sessionUpTotal = 0
    @Published var sessionDownTotal = 0
    @Published var latencies: [UUID: Int] = [:]   // ms；測過但失敗 = -1
    @Published var isPinging = false

    @Published var connections: [ConnectionInfo] = []
    @Published var connUploadTotal = 0
    @Published var connDownloadTotal = 0

    @Published var engineLog: [String] = []
    @Published var engineVersion: String? = EngineManager.version()
    @Published var engineInstallStatus: String?   // 下載引擎時的進度文字
    @Published var isInstallingEngine = false

    @Published var errorMessage: String?          // 跳 alert 用
    @Published var toastMessage: String?          // 輕量回饋（匯入成功等）

    private let engine = EngineManager()
    private var trafficTask: Task<Void, Never>?
    private var connectionsTask: Task<Void, Never>?
    private var autoUpdateTimer: Timer?
    private var tagByNodeID: [UUID: String] = [:]
    private var systemProxyActive = false

    private var api: ClashAPIClient {
        ClashAPIClient(port: settings.apiPort, secret: settings.apiSecret)
    }

    var selectedNode: ProxyNode? {
        nodes.first { $0.id == selectedNodeID } ?? nodes.first
    }

    // MARK: - 初始化與持久化

    private static var stateURL: URL {
        EngineManager.supportDir.appendingPathComponent("state.json")
    }

    init() {
        if let data = try? Data(contentsOf: Self.stateURL),
           let persisted = try? JSONDecoder().decode(PersistedState.self, from: data) {
            nodes = persisted.nodes
            subscriptions = persisted.subscriptions
            rules = persisted.rules
            settings = persisted.settings
            mode = persisted.mode
            selectedNodeID = persisted.selectedNodeID
        }
        engine.onLog = { [weak self] line in
            Task { @MainActor in self?.appendLog(line) }
        }
        engine.onUnexpectedExit = { [weak self] status in
            Task { @MainActor in
                guard let self, self.connectionState == .connected || self.connectionState == .connecting else { return }
                self.teardownAfterStop()
                self.errorMessage = "引擎意外停止（代碼 \(status)）。可到「日誌」分頁查看原因。"
            }
        }
        // 訂閱自動更新：啟動後與每 30 分鐘檢查一次是否到期
        autoUpdateTimer = Timer.scheduledTimer(withTimeInterval: 1800, repeats: true) { _ in
            Task { @MainActor in await AppState.shared.autoRefreshIfDue() }
        }
        Task { [weak self] in
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            await self?.autoRefreshIfDue()
        }
    }

    func save() {
        let persisted = PersistedState(
            nodes: nodes, subscriptions: subscriptions, settings: settings,
            mode: mode, selectedNodeID: selectedNodeID, rules: rules)
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
        if settings.tunMode {
            toastMessage = "已儲存，重新連線後生效"
        } else {
            Task {
                await disconnect()
                await connect()
            }
        }
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

    func connect() async {
        guard connectionState == .disconnected else { return }
        guard !nodes.isEmpty else {
            errorMessage = "還沒有任何節點。先到「節點」分頁貼上分享連結或訂閱，馬上就能連線。"
            return
        }
        connectionState = .connecting
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

            if selectedNodeID == nil || !nodes.contains(where: { $0.id == selectedNodeID }) {
                selectedNodeID = nodes.first?.id
            }

            let result = SingBoxConfigBuilder.build(
                nodes: nodes, selectedID: selectedNodeID,
                settings: settings, mode: mode, rules: rules)
            tagByNodeID = result.tagByNodeID

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
                try SystemProxyManager.enable(port: settings.mixedPort)
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
    }

    func disconnect() async {
        guard connectionState == .connected else { return }
        connectionState = .stopping
        teardownAfterStop()
    }

    private func teardownAfterStop() {
        trafficTask?.cancel()
        trafficTask = nil
        if systemProxyActive {
            SystemProxyManager.disable()
            systemProxyActive = false
        }
        engine.stop()
        upRate = 0
        downRate = 0
        connections = []
        connectionState = .disconnected
    }

    /// App 結束前的同步清理：還原系統代理、停掉引擎
    func cleanupOnTerminate() {
        if systemProxyActive {
            SystemProxyManager.disable()
        }
        engine.stop()
        save()
    }

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
                            self.upRate = sample.up
                            self.downRate = sample.down
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

    // MARK: - 模式 / 節點切換

    func setMode(_ newMode: ProxyMode) {
        mode = newMode
        save()
        if connectionState == .connected {
            let client = api
            Task { await client.setMode(newMode.clashMode) }
        }
    }

    func selectNode(_ id: UUID) {
        selectedNodeID = id
        save()
        guard connectionState == .connected, let tag = tagByNodeID[id] else { return }
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
        let result = try await SubscriptionManager.fetch(urlString: trimmed)
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
            let result = try await SubscriptionManager.fetch(urlString: subscriptions[index].url)
            let oldSelectedName = selectedNode?.name
            nodes.removeAll { $0.subscriptionID == id }
            for var node in result.nodes {
                node.subscriptionID = id
                nodes.append(node)
            }
            subscriptions[index].lastUpdated = Date()
            subscriptions[index].rawUserInfo = result.userInfo
            // 盡量保住原本選的節點（依名稱比對）
            if !nodes.contains(where: { $0.id == selectedNodeID }) {
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
        if !nodes.contains(where: { $0.id == selectedNodeID }) {
            selectedNodeID = nodes.first?.id
        }
        save()
    }

    func deleteNode(_ id: UUID) {
        nodes.removeAll { $0.id == id }
        latencies.removeValue(forKey: id)
        if selectedNodeID == id {
            selectedNodeID = nodes.first?.id
        }
        save()
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
    }

    // MARK: - 連線檢視

    func startConnectionsPolling() {
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
    }

    func stopConnectionsPolling() {
        connectionsTask?.cancel()
        connectionsTask = nil
    }

    func closeConnection(_ id: String) {
        let client = api
        Task { await client.closeConnection(id) }
    }

    func closeAllConnections() {
        let client = api
        Task { await client.closeAllConnections() }
    }

    // MARK: - 引擎安裝

    func installOrUpdateEngine() async {
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
    }
}
