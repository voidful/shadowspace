import SwiftUI
import AppKit

struct MenuBarStatusLabel: View {
    @ObservedObject var state: AppState
    @ObservedObject var traffic: TrafficStatsStore

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
        return "↓ \(traffic.downRate.menuBarRateString) ↑ \(traffic.upRate.menuBarRateString)"
    }

    private var statusText: String {
        guard state.connectionState == .connected else {
            return "ShadowSpace：\(state.connectionState.label)"
        }
        return "ShadowSpace：已連線，下載 \(traffic.downRate.rateString)，上傳 \(traffic.upRate.rateString)"
    }
}

/// 選單列快速操作：連線開關、模式、節點切換。
struct MenuBarView: View {
    @ObservedObject var state: AppState
    @ObservedObject var traffic: TrafficStatsStore
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            statusPanel

            Button {
                state.toggleConnection()
            } label: {
                Label(connectButtonTitle, systemImage: connectButtonIcon)
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(state.connectionState == .stopping)

            Divider()

            ProxyModePicker(state: state)

            if !state.nodes.isEmpty || !state.groups.isEmpty {
                Menu {
                    OutboundMenuContent(state: state, nodeLimit: 30, onOverflow: showMainWindow)
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
                    Label(traffic.downRate.rateString, systemImage: "arrow.down")
                    Label(traffic.upRate.rateString, systemImage: "arrow.up")
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
            return "\(state.transportDescription) · \(state.selectedOutboundName) · \(state.mode.displayName)"
        case .connecting:
            return "正在啟動代理服務"
        case .stopping:
            return "正在停止代理服務"
        case .disconnected:
            return state.nodes.isEmpty ? "尚未匯入節點" : "已準備好連線到 \(state.selectedOutboundName)"
        }
    }

    private var connectButtonTitle: String {
        switch state.connectionState {
        case .connecting: return "取消連線"
        case .connected: return "中斷連線"
        default: return "連線"
        }
    }

    private var connectButtonIcon: String {
        state.connectionState == .connected ? "power.circle.fill" : "power.circle"
    }

    private func showMainWindow() {
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
    }
}
