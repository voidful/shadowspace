import SwiftUI

/// 活躍連線檢視：看每條連線的目標、命中規則、出口節點與流量，可強制關閉。
struct ConnectionsView: View {
    @EnvironmentObject private var state: AppState
    @EnvironmentObject private var stats: ConnectionStatsStore
    @State private var filter = ""
    @State private var sortOrder = [KeyPathComparator(\ConnectionInfo.download, order: .reverse)]

    private var filtered: [ConnectionInfo] {
        let base: [ConnectionInfo]
        if filter.isEmpty {
            base = stats.items
        } else {
            let key = filter.lowercased()
            base = stats.items.filter {
                $0.target.lowercased().contains(key) ||
                $0.rule.lowercased().contains(key) ||
                $0.chain.lowercased().contains(key)
            }
        }
        return base.sorted(using: sortOrder)
    }

    var body: some View {
        Group {
            if state.connectionState != .connected {
                ContentUnavailableView {
                    Label("尚未連線", systemImage: "network.slash")
                } description: {
                    Text("連線後，這裡會即時顯示每條連線命中的規則與出口節點。")
                }
            } else {
                VStack(spacing: 0) {
                    table
                    footer
                }
            }
        }
        .navigationTitle("連線")
        .searchable(text: $filter, placement: .toolbar, prompt: "篩選目標 / 規則 / 節點")
        .toolbar {
            ToolbarItem {
                Button {
                    state.closeAllConnections()
                } label: {
                    Label("全部關閉", systemImage: "xmark.circle")
                }
                .disabled(stats.items.isEmpty)
                .help("關閉所有活躍連線")
            }
        }
        .onAppear { state.startConnectionsPolling() }
        .onDisappear { state.stopConnectionsPolling() }
    }

    private var table: some View {
        Table(filtered, sortOrder: $sortOrder) {
            TableColumn("目標", value: \.target) { conn in
                Text(conn.target)
                    .lineLimit(1)
                    .help(conn.target)
            }
            TableColumn("規則", value: \.rule) { conn in
                Text(conn.rule)
                    .lineLimit(1)
                    .foregroundStyle(.secondary)
            }
            .width(min: 100, ideal: 150)
            TableColumn("節點", value: \.chain) { conn in
                Text(conn.chain)
                    .lineLimit(1)
            }
            .width(min: 80, ideal: 130)
            TableColumn("上傳", value: \.upload) { conn in
                Text(conn.upload.byteString)
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
            }
            .width(70)
            TableColumn("下載", value: \.download) { conn in
                Text(conn.download.byteString)
                    .monospacedDigit()
                    .foregroundStyle(.secondary)
            }
            .width(70)
            TableColumn("時間", value: \.startedAt) { conn in
                Text(conn.durationText)
                    .foregroundStyle(.secondary)
            }
            .width(80)
        }
        .contextMenu(forSelectionType: ConnectionInfo.ID.self) { ids in
            Button("關閉連線", role: .destructive) {
                for id in ids {
                    state.closeConnection(id)
                }
            }
        }
    }

    private var footer: some View {
        HStack {
            Text("共 \(filtered.count) 條連線")
            Spacer()
            Text("總計  ↑ \(stats.uploadTotal.byteString)   ↓ \(stats.downloadTotal.byteString)")
                .monospacedDigit()
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(.bar)
    }
}
