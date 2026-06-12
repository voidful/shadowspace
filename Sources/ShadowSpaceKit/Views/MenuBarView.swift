import SwiftUI
import AppKit

/// 選單列快速操作：連線開關、模式、節點切換。
struct MenuBarView: View {
    @EnvironmentObject private var state: AppState
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Group {
            // VPN 狀態面板
            switch state.connectionState {
            case .connected:
#if APP_STORE
                Text("● VPN 已連線（透明代理）")
#else
                Text("● VPN 已連線\(state.settings.tunMode ? "（TUN 全域）" : "（系統代理）")")
#endif
                if let node = state.selectedNode {
                    Text("節點：\(node.name) · 模式：\(state.mode.displayName)")
                } else {
                    Text("模式：\(state.mode.displayName)")
                }
                Text("↑ \(state.upRate.rateString)   ↓ \(state.downRate.rateString)")
            case .connecting:
                Text("○ VPN 連線中…")
            case .stopping:
                Text("○ VPN 中斷中…")
            case .disconnected:
                Text("○ VPN 未連線")
            }

            Button(state.connectionState == .connected ? "中斷連線" : "連線") {
                state.toggleConnection()
            }
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
            .pickerStyle(.inline)

            if !state.nodes.isEmpty {
                Menu("節點") {
                    ForEach(state.nodes.prefix(30)) { node in
                        Button {
                            state.selectNode(node.id)
                        } label: {
                            if node.id == state.selectedNode?.id {
                                Label(node.name, systemImage: "checkmark")
                            } else {
                                Text(node.name)
                            }
                        }
                    }
                    if state.nodes.count > 30 {
                        Divider()
                        Button("更多節點請開啟主視窗…") { showMainWindow() }
                    }
                }
            }

            Divider()

            Button("開啟主視窗") { showMainWindow() }
                .keyboardShortcut("o")

            Button("結束 ShadowSpace") {
                NSApp.terminate(nil)
            }
            .keyboardShortcut("q")
        }
    }

    private func showMainWindow() {
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
    }
}
