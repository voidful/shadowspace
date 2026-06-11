import SwiftUI

enum SidebarItem: String, CaseIterable, Identifiable {
    case home, servers, rules, connections, logs, settings
    var id: String { rawValue }

    var label: String {
        switch self {
        case .home: return "首頁"
        case .servers: return "節點"
        case .rules: return "規則"
        case .connections: return "連線"
        case .logs: return "日誌"
        case .settings: return "設定"
        }
    }

    var icon: String {
        switch self {
        case .home: return "house"
        case .servers: return "globe.asia.australia"
        case .rules: return "arrow.triangle.branch"
        case .connections: return "list.bullet.rectangle"
        case .logs: return "doc.text"
        case .settings: return "gearshape"
        }
    }
}

struct MainWindow: View {
    @EnvironmentObject private var state: AppState
    @State private var selection: SidebarItem = .home

    var body: some View {
        NavigationSplitView {
            List(SidebarItem.allCases, selection: $selection) { item in
                Label(item.label, systemImage: item.icon).tag(item)
            }
            .navigationSplitViewColumnWidth(min: 150, ideal: 170, max: 200)
        } detail: {
            switch selection {
            case .home: HomeView()
            case .servers: ServersView()
            case .rules: RulesView()
            case .connections: ConnectionsView()
            case .logs: LogsView()
            case .settings: SettingsView()
            }
        }
        // 錯誤彈窗
        .alert("出了點問題", isPresented: Binding(
            get: { state.errorMessage != nil },
            set: { if !$0 { state.errorMessage = nil } }
        )) {
            Button("好") { state.errorMessage = nil }
        } message: {
            Text(state.errorMessage ?? "")
        }
        // 輕量回饋
        .overlay(alignment: .bottom) {
            if let toast = state.toastMessage {
                Text(toast)
                    .font(.callout)
                    .padding(.horizontal, 14)
                    .padding(.vertical, 8)
                    .background(.regularMaterial, in: Capsule())
                    .shadow(radius: 4)
                    .padding(.bottom, 16)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
                    .task {
                        try? await Task.sleep(nanoseconds: 2_500_000_000)
                        withAnimation { state.toastMessage = nil }
                    }
            }
        }
        .animation(.easeInOut(duration: 0.2), value: state.toastMessage)
    }
}

// MARK: - 共用小元件

/// 延遲數字徽章：綠 < 150ms、橘 < 400ms、紅 ≥ 400ms / 逾時
struct LatencyBadge: View {
    let ms: Int?

    var body: some View {
        if let ms {
            Text(ms < 0 ? "逾時" : "\(ms) ms")
                .font(.caption.monospacedDigit())
                .foregroundStyle(color)
        }
    }

    private var color: Color {
        guard let ms, ms >= 0 else { return .red }
        if ms < 150 { return .green }
        if ms < 400 { return .orange }
        return .red
    }
}

/// 協議類型小標籤
struct ProtocolBadge: View {
    let proto: NodeProtocol

    var body: some View {
        Text(proto.displayName)
            .font(.caption2.weight(.medium))
            .padding(.horizontal, 5)
            .padding(.vertical, 1.5)
            .background(Color.accentColor.opacity(0.15), in: RoundedRectangle(cornerRadius: 4))
            .foregroundStyle(Color.accentColor)
    }
}
