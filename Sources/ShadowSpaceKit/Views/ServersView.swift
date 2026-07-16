import SwiftUI

/// 節點管理：訂閱分組、延遲測試、匯入。
struct ServersView: View {
    @EnvironmentObject private var state: AppState
    @State private var showImportSheet = false
    @State private var isRefreshing = false
    @State private var editingNode: ProxyNode?
    @State private var showManualAdd = false
    @State private var qrNode: ProxyNode?
    @State private var editingGroup: ProxyGroup?
    @State private var showAddGroup = false
    @State private var search = ""
    @State private var sortByLatency = false
    @State private var deletingSubscription: Subscription?
    @State private var deletingGroup: ProxyGroup?

    var body: some View {
        Group {
            if state.nodes.isEmpty && state.subscriptions.isEmpty {
                emptyState
            } else {
                nodeList
            }
        }
        .navigationTitle("節點")
        .toolbar {
            ToolbarItemGroup {
                ImportFromClipboardButton(state: state)
                    .help("自動辨識剪貼簿中的節點連結或訂閱網址")

                Menu {
                    Button("貼上連結匯入…") { showImportSheet = true }
                    Button("掃描剪貼簿 QR") { Task { await state.importQRFromClipboard() } }
                    Button("手動新增節點…") { showManualAdd = true }
                    if !state.nodes.isEmpty {
                        Divider()
                        Button("新增群組…") { showAddGroup = true }
                    }
                } label: {
                    Label("新增", systemImage: "plus")
                }
                .help("貼上分享連結，或手動填寫節點資料")

                Button {
                    Task { await state.pingAllNodes() }
                } label: {
                    if state.isPinging {
                        ProgressView().controlSize(.small)
                    } else {
                        Label("測延遲", systemImage: "speedometer")
                    }
                }
                .disabled(state.nodes.isEmpty || state.isPinging)
                .help("對所有節點做 TCP 延遲測試")

                Menu {
                    Picker("排序", selection: $sortByLatency) {
                        Text("預設順序").tag(false)
                        Text("延遲由低到高").tag(true)
                    }
                } label: {
                    Label("排序", systemImage: "arrow.up.arrow.down")
                }
                .help("切換節點排序方式")

                if !state.subscriptions.isEmpty {
                    Button {
                        Task {
                            isRefreshing = true
                            await state.refreshAllSubscriptions()
                            isRefreshing = false
                        }
                    } label: {
                        if isRefreshing {
                            ProgressView().controlSize(.small)
                        } else {
                            Label("更新訂閱", systemImage: "arrow.clockwise")
                        }
                    }
                    .disabled(isRefreshing)
                    .help("重新抓取所有訂閱")
                }
            }
        }
        .sheet(isPresented: $showImportSheet) {
            ImportSheet()
        }
        .sheet(isPresented: $showManualAdd) {
            NodeEditorSheet(node: nil)
        }
        .sheet(item: $editingNode) { node in
            NodeEditorSheet(node: node)
        }
        .sheet(item: $qrNode) { node in
            QRCodeSheet(node: node)
        }
        .sheet(isPresented: $showAddGroup) {
            GroupEditorSheet(group: nil)
        }
        .sheet(item: $editingGroup) { group in
            GroupEditorSheet(group: group)
        }
        .searchable(text: $search, placement: .toolbar, prompt: "搜尋節點名稱或伺服器")
        .confirmationDialog(
            "確定刪除訂閱「\(deletingSubscription?.name ?? "")」？",
            isPresented: Binding(
                get: { deletingSubscription != nil },
                set: { if !$0 { deletingSubscription = nil } }),
            titleVisibility: .visible,
            presenting: deletingSubscription
        ) { sub in
            Button("刪除", role: .destructive) { state.deleteSubscription(sub.id) }
        } message: { sub in
            let count = state.nodes.filter { $0.subscriptionID == sub.id }.count
            Text("會一併移除此訂閱的 \(count) 個節點，無法復原。")
        }
        .confirmationDialog(
            "確定刪除群組「\(deletingGroup?.name ?? "")」？",
            isPresented: Binding(
                get: { deletingGroup != nil },
                set: { if !$0 { deletingGroup = nil } }),
            titleVisibility: .visible,
            presenting: deletingGroup
        ) { group in
            Button("刪除", role: .destructive) { state.deleteGroup(group.id) }
        } message: { _ in
            Text("成員節點不會被刪除，僅移除此群組設定。")
        }
    }

    // MARK: - 清單

    private var nodeList: some View {
        // 搜尋與排序只做一次，再依訂閱 ID 線性分組；避免每個訂閱都重新掃描整份節點清單。
        let groupedNodes = Dictionary(grouping: displayNodes(state.nodes), by: \ProxyNode.subscriptionID)
        return List(selection: Binding(
            get: { state.selectedNodeID },
            set: { if let id = $0 { state.selectNode(id) } }
        )) {
            if !state.groups.isEmpty {
                Section("群組") {
                    ForEach(state.groups) { group in
                        groupRow(group)
                    }
                }
            }
            ForEach(state.subscriptions) { sub in
                let subNodes = groupedNodes[Optional(sub.id)] ?? []
                if !subNodes.isEmpty {
                    Section {
                        nodeRows(subNodes)
                    } header: {
                        subscriptionHeader(sub)
                    }
                }
            }
            let manualNodes = groupedNodes[nil] ?? []
            if !manualNodes.isEmpty {
                Section("手動新增") {
                    nodeRows(manualNodes)
                }
            }
        }
    }

    /// 套用搜尋過濾與延遲排序。群組不受影響（在上方獨立區塊）。
    /// 逾時（-1）與未測（nil）排在最後。
    private func displayNodes(_ nodes: [ProxyNode]) -> [ProxyNode] {
        var result = nodes
        if !search.isEmpty {
            result = result.filter {
                $0.name.localizedCaseInsensitiveContains(search) ||
                $0.server.localizedCaseInsensitiveContains(search)
            }
        }
        if sortByLatency {
            result.sort {
                let a = state.latencies[$0.id].flatMap { $0 >= 0 ? $0 : nil } ?? Int.max
                let b = state.latencies[$1.id].flatMap { $0 >= 0 ? $0 : nil } ?? Int.max
                return a < b
            }
        }
        return result
    }

    @ViewBuilder
    private func nodeRows(_ nodes: [ProxyNode]) -> some View {
        ForEach(nodes) { node in
            HStack(spacing: 8) {
                SelectionDot(selected: node.id == state.selectedNodeID)
                ProtocolBadge(proto: node.proto)
                VStack(alignment: .leading, spacing: 1) {
                    Text(node.name).lineLimit(1)
                    Text("\(node.server):\(String(node.port))")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer()
                LatencyBadge(ms: state.latencies[node.id])
            }
            .tag(node.id)
            .contextMenu {
                Button("使用此節點") { state.selectNode(node.id) }
                Button("測試延遲") { Task { await state.pingNode(node.id) } }
                Button("編輯…") { editingNode = node }
                Divider()
                Button("複製分享連結") {
                    if let uri = NodeShare.uri(for: node) {
                        NSPasteboard.copyString(uri)
                        state.toastMessage = "已複製分享連結"
                    }
                }
                Button("顯示 QR Code…") { qrNode = node }
                Divider()
                Button("刪除", role: .destructive) {
                    state.deleteNode(node.id)
                    state.toastMessage = "已刪除「\(node.name)」"
                }
            }
        }
    }

    @ViewBuilder
    private func groupRow(_ group: ProxyGroup) -> some View {
        let selected = group.id == state.selectedNodeID
        HStack(spacing: 8) {
            SelectionDot(selected: selected)
            Image(systemName: group.type.icon)
                .foregroundStyle(.secondary)
                .frame(width: 16)
            VStack(alignment: .leading, spacing: 1) {
                Text(group.name).lineLimit(1)
                Text("\(group.type.displayName) · \(group.memberNodeIDs.count) 個節點")
                    .font(.caption2).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
        }
        .tag(group.id)
        .contextMenu {
            Button("使用此群組") { state.selectNode(group.id) }
            Button("編輯…") { editingGroup = group }
            Divider()
            Button("刪除", role: .destructive) { deletingGroup = group }
        }
    }

    private func subscriptionHeader(_ sub: Subscription) -> some View {
        HStack {
            Text(sub.name)
            if let summary = sub.trafficSummary {
                Text(summary).foregroundStyle(.secondary)
            }
            Spacer()
            Menu {
                Button("更新") {
                    Task { await state.refreshSubscription(sub.id) }
                }
                if let updated = sub.lastUpdated {
                    Text("上次更新：\(updated.formatted(date: .abbreviated, time: .shortened))")
                }
                Divider()
                Button("刪除訂閱", role: .destructive) {
                    deletingSubscription = sub
                }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
        }
    }

    // MARK: - 空狀態

    private var emptyState: some View {
        ContentUnavailableView {
            Label("還沒有節點", systemImage: "globe.asia.australia")
        } description: {
            Text("複製節點分享連結或機場訂閱網址後，點下方按鈕匯入。")
        } actions: {
            ImportFromClipboardButton(state: state)
                .buttonStyle(.borderedProminent)
            Button("手動貼上…") { showImportSheet = true }
        }
    }
}

/// 節點/群組列的「目前選中」單選圓點。
private struct SelectionDot: View {
    let selected: Bool
    var body: some View {
        Image(systemName: selected ? "largecircle.fill.circle" : "circle")
            .foregroundStyle(selected ? Color.accentColor : Color.secondary)
    }
}

// MARK: - QR Code Sheet

struct QRCodeSheet: View {
    @Environment(\.dismiss) private var dismiss
    let node: ProxyNode

    var body: some View {
        VStack(spacing: 14) {
            Text(node.name)
                .font(.headline)
                .lineLimit(1)
            if let uri = NodeShare.uri(for: node),
               let image = NodeShare.qrImage(for: uri) {
                Image(nsImage: image)
                    .interpolation(.none)
                    .resizable()
                    .frame(width: 240, height: 240)
                    .background(Color.white)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                Text("用 Shadowrocket 等 App 掃描即可匯入")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                HStack {
                    CopyButton(title: "複製連結") { NSPasteboard.copyString(uri) }
                    CopyButton(title: "複製圖片") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.writeObjects([image])
                    }
                }
            } else {
                Text("此節點無法產生分享連結")
                    .foregroundStyle(.secondary)
            }
            Button("完成") { dismiss() }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
        }
        .padding(24)
    }
}

// MARK: - 群組編輯 Sheet

struct GroupEditorSheet: View {
    @EnvironmentObject private var state: AppState
    @Environment(\.dismiss) private var dismiss
    let group: ProxyGroup?
    @State private var draft: ProxyGroup

    init(group: ProxyGroup?) {
        self.group = group
        _draft = State(initialValue: group ?? ProxyGroup())
    }

    var body: some View {
        VStack(spacing: 0) {
            Text(group == nil ? "新增群組" : "編輯群組")
                .font(.headline)
                .padding(.top, 16)

            Form {
                Section {
                    TextField("名稱", text: $draft.name, prompt: Text("例如：香港、自動測速"))
                    Picker("型別", selection: $draft.type) {
                        ForEach(ProxyGroupType.allCases, id: \.self) { type in
                            Text(type.displayName).tag(type)
                        }
                    }
                } footer: {
                    Text(draft.type == .urltest
                         ? "自動測速，永遠走成員中最快的節點。"
                         : "手動在成員節點中選擇出口。")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Section("成員節點（\(draft.memberNodeIDs.count)）") {
                    if state.nodes.isEmpty {
                        Text("還沒有節點").foregroundStyle(.secondary)
                    }
                    ForEach(state.nodes) { node in
                        Button {
                            toggle(node.id)
                        } label: {
                            HStack(spacing: 8) {
                                Image(systemName: draft.memberNodeIDs.contains(node.id)
                                      ? "checkmark.circle.fill" : "circle")
                                    .foregroundStyle(draft.memberNodeIDs.contains(node.id)
                                                     ? Color.accentColor : .secondary)
                                ProtocolBadge(proto: node.proto)
                                Text(node.name).lineLimit(1)
                                Spacer()
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            .formStyle(.grouped)

            EditorSheetFooter(
                onDelete: group == nil ? nil : { state.deleteGroup(draft.id); dismiss() },
                hint: draft.memberNodeIDs.isEmpty ? "至少勾選一個成員節點" : nil,
                saveDisabled: draft.memberNodeIDs.isEmpty,
                onCancel: { dismiss() },
                onSave: {
                    var g = draft
                    if g.name.trimmingCharacters(in: .whitespaces).isEmpty { g.name = "群組" }
                    state.upsertGroup(g)
                    dismiss()
                }
            )
            .padding(16)
        }
        .frame(width: 460, height: 540)
    }

    private func toggle(_ id: UUID) {
        if let idx = draft.memberNodeIDs.firstIndex(of: id) {
            draft.memberNodeIDs.remove(at: idx)
        } else {
            draft.memberNodeIDs.append(id)
        }
    }
}

// MARK: - 貼上匯入 Sheet

struct ImportSheet: View {
    @EnvironmentObject private var state: AppState
    @Environment(\.dismiss) private var dismiss
    @State private var text = ""
    @State private var importing = false
    @State private var errorText: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("匯入節點或訂閱")
                .font(.headline)
#if APP_STORE
            Text("支援 \(URIParser.appStoreSupportedSchemesText) 分享連結、base64 內容，或 http(s) 訂閱網址，可一次貼多行。")
                .font(.callout)
                .foregroundStyle(.secondary)
#else
            Text("支援 \(URIParser.supportedSchemesText) 分享連結、WireGuard .conf 設定檔、base64 內容，或 http(s) 訂閱網址，可一次貼多行。")
                .font(.callout)
                .foregroundStyle(.secondary)
#endif
            TextEditor(text: $text)
                .font(.body.monospaced())
                .frame(minHeight: 160)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(.quaternary))
                .onChange(of: text) { _, _ in errorText = nil }
            if let errorText {
                Label(errorText, systemImage: "exclamationmark.triangle")
                    .font(.caption)
                    .foregroundStyle(.red)
            }
            HStack {
                Spacer()
                Button("取消") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button {
                    importing = true
                    Task {
                        // reportFailure: false → 失敗就地顯示，不關閉 sheet、保留使用者輸入
                        if let err = await state.importText(text, reportFailure: false) {
                            errorText = err
                            importing = false
                        } else {
                            importing = false
                            dismiss()
                        }
                    }
                } label: {
                    if importing {
                        ProgressView().controlSize(.small)
                    } else {
                        Text("匯入")
                    }
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || importing)
            }
        }
        .padding(20)
        .frame(width: 520)
    }
}
