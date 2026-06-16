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
                .onOpenURL { state.handleURL($0) }
        }
        .defaultSize(width: 780, height: 540)

        MenuBarExtra {
            MenuBarView(state: state)
        } label: {
            MenuBarStatusLabel(state: state)
        }
        .menuBarExtraStyle(.window)
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
