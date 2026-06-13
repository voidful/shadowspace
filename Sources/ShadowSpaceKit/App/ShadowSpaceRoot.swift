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
                .frame(minWidth: 700, minHeight: 460)
        }
        .defaultSize(width: 780, height: 540)

        MenuBarExtra {
            MenuBarView()
                .environmentObject(state)
        } label: {
            HStack(spacing: 5) {
                Image(systemName: menuBarSymbol)
                if let trafficText = menuBarTrafficText {
                    Text(trafficText)
                        .font(.system(size: 11, weight: .medium, design: .rounded))
                        .monospacedDigit()
                }
            }
            .accessibilityLabel(menuBarStatusText)
        }
        .menuBarExtraStyle(.menu)
    }

    /// 選單列圖示隨 VPN 狀態變化：實心紙飛機＝已連線、空心＝未連線
    private var menuBarSymbol: String {
        switch state.connectionState {
        case .connected: return "paperplane.fill"
        case .connecting, .stopping: return "paperplane.circle"
        case .disconnected: return "paperplane"
        }
    }

    private var menuBarTrafficText: String? {
        guard state.connectionState == .connected else { return nil }
        return "↓ \(state.downRate.menuBarRateString) ↑ \(state.upRate.menuBarRateString)"
    }

    private var menuBarStatusText: String {
        guard state.connectionState == .connected else {
            return "ShadowSpace：\(state.connectionState.label)"
        }
        return "ShadowSpace：已連線，下載 \(state.downRate.rateString)，上傳 \(state.upRate.rateString)"
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.activate(ignoringOtherApps: true)
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
