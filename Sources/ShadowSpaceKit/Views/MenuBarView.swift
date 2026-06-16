import SwiftUI
import AppKit

struct MenuBarStatusLabel: View {
    @ObservedObject var state: AppState

    var body: some View {
        HStack(spacing: 5) {
            Image(systemName: symbol)
            if let trafficText {
                Text(trafficText)
                    .font(.system(size: 11, weight: .medium, design: .rounded))
                    .monospacedDigit()
            }
        }
        .accessibilityLabel(statusText)
    }

    private var symbol: String {
        switch state.connectionState {
        case .connected: return "paperplane.fill"
        case .connecting, .stopping: return "paperplane.circle"
        case .disconnected: return "paperplane"
        }
    }

    private var trafficText: String? {
        guard state.connectionState == .connected else { return nil }
        return "↓ \(state.downRate.menuBarRateString) ↑ \(state.upRate.menuBarRateString)"
    }

    private var statusText: String {
        guard state.connectionState == .connected else {
            return "ShadowSpace：\(state.connectionState.label)"
        }
        return "ShadowSpace：已連線，下載 \(state.downRate.rateString)，上傳 \(state.upRate.rateString)"
    }
}

/// 選單列快速操作：連線開關、模式、節點切換。
struct MenuBarView: View {
    @ObservedObject var state: AppState
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            statusPanel

            Button {
                state.toggleConnection()
            } label: {
                Label(
                    state.connectionState == .connected ? "中斷連線" : "連線",
                    systemImage: state.connectionState == .connected ? "power.circle.fill" : "power.circle"
                )
                .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(state.connectionState == .connecting || state.connectionState == .stopping)

            Divider()

            Picker("代理模式", selection: Binding(
                get: { state.mode },
                set: { state.setMode($0) }
            )) {
                ForEach(ProxyMode.allCases, id: \.self) { mode in
                    Text(mode.displayName).tag(mode)
                }
            }
            .pickerStyle(.segmented)

            if !state.nodes.isEmpty || !state.groups.isEmpty {
                Menu {
                    if !state.groups.isEmpty {
                        Section("群組") {
                            ForEach(state.groups) { group in
                                outboundButton(id: group.id, title: group.name, icon: group.type.icon)
                            }
                        }
                    }
                    if !state.nodes.isEmpty {
                        Section("節點") {
                            ForEach(state.nodes.prefix(30)) { node in
                                outboundButton(id: node.id, title: node.name, icon: node.protoIconName)
                            }
                            if state.nodes.count > 30 {
                                Divider()
                                Button("更多節點請開啟主視窗…") { showMainWindow() }
                            }
                        }
                    }
                } label: {
                    Label("出口：\(state.selectedOutboundName)", systemImage: "point.3.connected.trianglepath.dotted")
                        .lineLimit(1)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .menuStyle(.button)
            }

            Divider()

            HStack {
                Button {
                    showMainWindow()
                } label: {
                    Label("主視窗", systemImage: "macwindow")
                }
                .keyboardShortcut("o")

                Spacer()

                Button {
                    NSApp.terminate(nil)
                } label: {
                    Label("結束", systemImage: "xmark.circle")
                }
                .keyboardShortcut("q")
            }
        }
        .padding(14)
        .frame(width: 310)
    }

    @ViewBuilder
    private var statusPanel: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 8) {
                Image(systemName: statusIcon)
                    .foregroundStyle(statusColor)
                    .font(.title3)
                VStack(alignment: .leading, spacing: 2) {
                    Text(state.connectionState.label)
                        .font(.headline)
                    Text(statusDetail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
            }

            if state.connectionState == .connected {
                HStack(spacing: 12) {
                    Label(state.downRate.rateString, systemImage: "arrow.down")
                    Label(state.upRate.rateString, systemImage: "arrow.up")
                }
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
            }
        }
    }

    private var statusIcon: String {
        switch state.connectionState {
        case .connected: return "checkmark.circle.fill"
        case .connecting, .stopping: return "clock.arrow.circlepath"
        case .disconnected: return "circle"
        }
    }

    private var statusColor: Color {
        switch state.connectionState {
        case .connected: return .green
        case .connecting, .stopping: return .orange
        case .disconnected: return .secondary
        }
    }

    private var statusDetail: String {
        switch state.connectionState {
        case .connected:
#if APP_STORE
            return "透明代理 · \(state.selectedOutboundName) · \(state.mode.displayName)"
#else
            let mode = state.settings.tunMode ? "TUN 全域" : "系統代理"
            return "\(mode) · \(state.selectedOutboundName) · \(state.mode.displayName)"
#endif
        case .connecting:
            return "正在啟動代理服務"
        case .stopping:
            return "正在停止代理服務"
        case .disconnected:
            return state.nodes.isEmpty ? "尚未匯入節點" : "已準備好連線到 \(state.selectedOutboundName)"
        }
    }

    private func outboundButton(id: UUID, title: String, icon: String) -> some View {
        Button {
            state.selectNode(id)
        } label: {
            Label(title, systemImage: state.selectedNodeID == id ? "checkmark" : icon)
        }
    }

    private func showMainWindow() {
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
    }
}

private extension ProxyNode {
    var protoIconName: String {
        switch proto {
        case .shadowsocks: return "bolt.horizontal.circle"
        case .vmess: return "v.circle"
        case .vless: return "v.square"
        case .trojan: return "shield"
        case .hysteria2: return "speedometer"
        case .tuic: return "t.circle"
        case .anytls: return "lock.circle"
        case .socks: return "network"
        case .wireguard: return "point.3.connected.trianglepath.dotted"
        }
    }
}
