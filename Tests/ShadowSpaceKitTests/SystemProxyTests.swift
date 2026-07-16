import XCTest
@testable import ShadowSpaceKit

final class SystemProxyTests: XCTestCase {

    private final class OperationRecorder: @unchecked Sendable {
        private let lock = NSLock()
        private(set) var enableCount = 0
        private(set) var disableCount = 0
        private(set) var enableRanOnMainThread = false

        func recordEnable() {
            lock.lock()
            enableCount += 1
            enableRanOnMainThread = Thread.isMainThread
            lock.unlock()
        }

        func recordDisable() {
            lock.lock()
            disableCount += 1
            lock.unlock()
        }
    }

    /// 代理伺服器主機要被加進繞過清單（否則原生引擎連往伺服器會被系統代理繞回 → 迴圈 → 沒網路）。
    func testBypassDomainsIncludesProxyServerAndDedups() {
        let list = SystemProxyManager.bypassDomains(["th.t2.lol", "th.t2.lol", "  ", "localhost"])
        XCTAssertTrue(list.contains("th.t2.lol"))          // 代理伺服器主機已列入繞過
        XCTAssertTrue(list.contains("127.0.0.1"))           // 預設仍在
        XCTAssertTrue(list.contains("192.168.0.0/16"))      // 私有網段預設仍在
        XCTAssertEqual(list.filter { $0 == "th.t2.lol" }.count, 1)   // 去重
        XCTAssertEqual(list.filter { $0 == "localhost" }.count, 1)   // 與預設重複者不重覆
        XCTAssertFalse(list.contains(""))                   // 空白被濾掉
        XCTAssertFalse(list.contains("  "))
    }

    func testBypassDomainsEmptyExtraKeepsDefaults() {
        let list = SystemProxyManager.bypassDomains()
        XCTAssertTrue(list.contains("127.0.0.1"))
        XCTAssertTrue(list.contains("localhost"))
        XCTAssertFalse(list.contains("th.t2.lol"))
    }

    // MARK: - runProcess 鉤子：離線驗證殘留偵測

    override func tearDown() {
        // 還原真實鉤子，避免污染其他測試。
        SystemProxyManager.runProcess = EngineManager.runProcess
        super.tearDown()
    }

    /// 以假的 networksetup 輸出驅動殘留偵測邏輯，不真的碰系統網路設定。
    private func fakeNetworksetup(webProxyLine: String) -> (URL, [String]) -> (Int32, String) {
        { _, args in
            guard let flag = args.first else { return (0, "") }
            switch flag {
            case "-listallnetworkservices":
                return (0, "An asterisk (*) denotes...\nWi-Fi\n")
            case "-getwebproxy":
                return (0, webProxyLine)
            default:
                return (0, "Enabled: No\nServer:\nPort: 0\n")
            }
        }
    }

    func testResidualProxyDetectedWhenLoopbackWebProxyEnabled() {
        SystemProxyManager.runProcess = fakeNetworksetup(
            webProxyLine: "Enabled: Yes\nServer: 127.0.0.1\nPort: 7890\n")
        XCTAssertTrue(SystemProxyManager.residualProxyDetected())
    }

    func testNoResidualWhenProxyDisabled() {
        SystemProxyManager.runProcess = fakeNetworksetup(
            webProxyLine: "Enabled: No\nServer:\nPort: 0\n")
        XCTAssertFalse(SystemProxyManager.residualProxyDetected())
    }

    func testNoResidualWhenProxyEnabledButNotLoopback() {
        // 使用者自己設的非本機代理不算殘留（不能誤清）。
        SystemProxyManager.runProcess = fakeNetworksetup(
            webProxyLine: "Enabled: Yes\nServer: 10.0.0.9\nPort: 8080\n")
        XCTAssertFalse(SystemProxyManager.residualProxyDetected())
    }

    func testProxyControllerRunsOffMainAndSkipsIdenticalConfiguration() async throws {
        let recorder = OperationRecorder()
        let controller = SystemProxyController(
            queueLabel: "shadowspace.system-proxy.test",
            enableOperation: { _, _ in recorder.recordEnable() },
            disableOperation: { recorder.recordDisable() },
            networkIdentity: { "Wi-Fi" })

        let firstApplied = try await controller.enableIfNeeded(
            port: 7_890, bypassHosts: ["proxy.example", "proxy.example"])
        let secondApplied = try await controller.enableIfNeeded(
            port: 7_890, bypassHosts: ["proxy.example"])

        XCTAssertTrue(firstApplied)
        XCTAssertFalse(secondApplied)
        XCTAssertEqual(recorder.enableCount, 1)
        XCTAssertFalse(recorder.enableRanOnMainThread)

        await controller.disable()
        XCTAssertEqual(recorder.disableCount, 1)

        let reapplied = try await controller.enableIfNeeded(
            port: 7_890, bypassHosts: ["proxy.example"])
        XCTAssertTrue(reapplied)
        XCTAssertEqual(recorder.enableCount, 2)
    }
}
