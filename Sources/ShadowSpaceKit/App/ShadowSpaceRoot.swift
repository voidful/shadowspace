import SwiftUI
import AppKit

/// App 進入點（由 executable target 呼叫 ShadowSpaceRoot.main()）
public struct ShadowSpaceRoot: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @StateObject private var state = AppState.shared

    public init() {}

    public var body: some Scene {
        Window("ShadowSpace", id: "main") {
            MainWindow()
                .environmentObject(state)
                .environmentObject(state.traffic)
                .environmentObject(state.logs)
                .environmentObject(state.connectionStats)
                .frame(minWidth: 700, minHeight: 460)
                .onOpenURL { state.handleURL($0) }
        }
        .defaultSize(width: 780, height: 540)
        .commands {
            ProxyCommands(state: state)
        }

        MenuBarExtra {
            MenuBarView(state: state, traffic: state.traffic)
        } label: {
            MenuBarStatusLabel(state: state, traffic: state.traffic)
        }
        .menuBarExtraStyle(.window)
    }
}

/// 全域選單命令與 ⌘ 快速鍵（App 常駐選單列，命令一律先開/聚焦主視窗才有可見效果）。
struct ProxyCommands: Commands {
    @ObservedObject var state: AppState
    @Environment(\.openWindow) private var openWindow

    var body: some Commands {
        // ⌘, 設定（置於 App 選單標準「設定」位置；專案無 Settings scene）
        CommandGroup(after: .appSettings) {
            Button("設定…") { focus(.settings) }
                .keyboardShortcut(",", modifiers: .command)
        }
        // 代理選單：連線 / 測延遲 / 更新訂閱
        CommandMenu("代理") {
            Button(connectCommandTitle) {
                focus(); state.toggleConnection()
            }
            .keyboardShortcut("k", modifiers: .command)
            .disabled(state.connectionState == .stopping)

            Button("測試延遲") { focus(.servers); Task { await state.pingAllNodes() } }
                .keyboardShortcut("t", modifiers: .command)
                .disabled(state.nodes.isEmpty || state.isPinging)

            Button("更新訂閱") { focus(.servers); Task { await state.refreshAllSubscriptions() } }
                .keyboardShortcut("r", modifiers: .command)
                .disabled(state.subscriptions.isEmpty)
        }
        // ⌘1–⌘6 切換分頁（置於「檢視」選單）
        CommandGroup(after: .sidebar) {
            Divider()
            ForEach(Array(SidebarItem.allCases.enumerated()), id: \.element) { index, item in
                Button(item.label) { focus(item) }
                    .keyboardShortcut(KeyEquivalent(Character("\(index + 1)")), modifiers: .command)
            }
        }
    }

    /// ⌘K 標籤三態：連線中按下＝取消（與選單列一致，避免標籤與行為矛盾）。
    private var connectCommandTitle: String {
        switch state.connectionState {
        case .connecting: return "取消連線"
        case .connected: return "中斷連線"
        default: return "連線"
        }
    }

    /// 開/聚焦主視窗（App 關窗後常駐選單列，不開窗命令無可見效果），可選切到指定分頁。
    private func focus(_ tab: SidebarItem? = nil) {
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
        if let tab { state.sidebarSelection = tab }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.activate(ignoringOtherApps: true)
        AppState.shared.bootstrap()
    }

    // 關掉主視窗仍常駐選單列（Shadowrocket 式體驗）
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }

    // 結束時還原系統代理並停掉引擎，避免使用者「斷網」
    func applicationWillTerminate(_ notification: Notification) {
        AppState.shared.cleanupOnTerminate()
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag {
            for window in sender.windows where window.canBecomeMain {
                window.makeKeyAndOrderFront(nil)
            }
        }
        return true
    }
}
