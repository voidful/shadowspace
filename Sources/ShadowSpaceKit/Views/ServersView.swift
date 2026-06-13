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
                Button {
                    Task { await state.importFromClipboard() }
                } label: {
                    Label("從剪貼簿匯入", systemImage: "doc.on.clipboard")
                }
                .help("自動辨識剪貼簿中的節點連結或訂閱網址")

                Menu {
                    Button("貼上連結匯入…") { showImportSheet = true }
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
    }

    // MARK: - 清單

    private var nodeList: some View {
        List(selection: Binding(
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
                Section {
                    nodeRows(state.nodes.filter { $0.subscriptionID == sub.id })
                } header: {
                    subscriptionHeader(sub)
                }
            }
            let manualNodes = state.nodes.filter { $0.subscriptionID == nil }
            if !manualNodes.isEmpty {
                Section("手動新增") {
                    nodeRows(manualNodes)
                }
            }
        }
    }

    @ViewBuilder
    private func nodeRows(_ nodes: [ProxyNode]) -> some View {
        ForEach(nodes) { node in
            HStack(spacing: 8) {
                Image(systemName: node.id == state.selectedNodeID ? "largecircle.fill.circle" : "circle")
                    .foregroundStyle(node.id == state.selectedNodeID ? Color.accentColor : .secondary)
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
                Button("編輯…") { editingNode = node }
                Divider()
                Button("複製分享連結") {
                    if let uri = NodeShare.uri(for: node) {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(uri, forType: .string)
                        state.toastMessage = "已複製分享連結"
                    }
                }
                Button("顯示 QR Code…") { qrNode = node }
                Divider()
                Button("刪除", role: .destructive) { state.deleteNode(node.id) }
            }
        }
    }

    @ViewBuilder
    private func groupRow(_ group: ProxyGroup) -> some View {
        let selected = group.id == state.selectedNodeID
        HStack(spacing: 8) {
            Image(systemName: selected ? "largecircle.fill.circle" : "circle")
                .foregroundStyle(selected ? Color.accentColor : .secondary)
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
            Button("刪除", role: .destructive) { state.deleteGroup(group.id) }
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
                    state.deleteSubscription(sub.id)
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
            Button {
                Task { await state.importFromClipboard() }
            } label: {
                Label("從剪貼簿匯入", systemImage: "doc.on.clipboard")
            }
            .buttonStyle(.borderedProminent)
            Button("手動貼上…") { showImportSheet = true }
        }
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
                    Button("複製連結") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(uri, forType: .string)
                    }
                    Button("複製圖片") {
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
    @State private var draft = ProxyGroup()

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

            HStack {
                if group != nil {
                    Button("刪除", role: .destructive) {
                        state.deleteGroup(draft.id); dismiss()
                    }
                }
                Spacer()
                Button("取消") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("儲存") {
                    var g = draft
                    if g.name.trimmingCharacters(in: .whitespaces).isEmpty { g.name = "群組" }
                    state.upsertGroup(g)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(draft.memberNodeIDs.isEmpty)
            }
            .padding(16)
        }
        .frame(width: 460, height: 540)
        .onAppear { if let group { draft = group } }
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

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("匯入節點或訂閱")
                .font(.headline)
            Text("支援 ss:// vmess:// vless:// trojan:// hysteria2:// tuic:// 分享連結、WireGuard .conf 設定檔、base64 內容，或 http(s) 訂閱網址，可一次貼多行。")
                .font(.callout)
                .foregroundStyle(.secondary)
            TextEditor(text: $text)
                .font(.body.monospaced())
                .frame(minHeight: 160)
                .overlay(RoundedRectangle(cornerRadius: 6).stroke(.quaternary))
            HStack {
                Spacer()
                Button("取消") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button {
                    importing = true
                    Task {
                        await state.importText(text)
                        importing = false
                        dismiss()
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
