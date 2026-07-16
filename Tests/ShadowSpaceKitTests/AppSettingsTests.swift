import XCTest
@testable import ShadowSpaceKit

final class AppSettingsTests: XCTestCase {

    func testDefaultEngineKindIsNative() {
        XCTAssertEqual(AppSettings().engineKind, .native)
    }

    func testMissingEngineKindDecodesAsNative() throws {
        let data = """
        {
          "mixedPort": 7890,
          "apiPort": 9090
        }
        """.data(using: .utf8)!

        let settings = try JSONDecoder().decode(AppSettings.self, from: data)
        XCTAssertEqual(settings.engineKind, .native)
        XCTAssertFalse(settings.tailscaleEnabled)
        XCTAssertTrue(settings.tailscaleMagicDNS)
        XCTAssertEqual(settings.latencyTestConcurrency, 16)
        XCTAssertEqual(settings.latencyTestURL, "https://www.gstatic.com/generate_204")
    }

    func testNetworkToolboxSettingsRoundTrip() throws {
        var original = AppSettings()
        original.tailscaleEnabled = true
        original.tailscaleAuthKey = "secret"
        original.tailscaleExitNode = "100.64.0.1"
        original.latencyTestIntervalMinutes = 3
        original.latencyTestToleranceMS = 100
        original.latencyTestConcurrency = 32

        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(AppSettings.self, from: data)
        XCTAssertTrue(decoded.tailscaleEnabled)
        XCTAssertEqual(decoded.tailscaleAuthKey, "secret")
        XCTAssertEqual(decoded.tailscaleExitNode, "100.64.0.1")
        XCTAssertEqual(decoded.latencyTestIntervalMinutes, 3)
        XCTAssertEqual(decoded.latencyTestToleranceMS, 100)
        XCTAssertEqual(decoded.latencyTestConcurrency, 32)
    }

    func testTailscaleLoginURLExtraction() {
        let url = AppState.tailscaleLoginURL(in: [
            "[info] tailscale: To authenticate, visit: https://login.tailscale.com/a/abc123",
        ])
        XCTAssertEqual(url?.absoluteString, "https://login.tailscale.com/a/abc123")
        XCTAssertNil(AppState.tailscaleLoginURL(in: ["[info] ordinary proxy log https://example.com"]))
    }

    func testInvalidLatencyURLFallsBackSafely() {
        var settings = AppSettings()
        settings.latencyTestURL = "not a URL"
        XCTAssertEqual(settings.effectiveLatencyTestURL, "https://www.gstatic.com/generate_204")
        settings.latencyTestURL = "https://example.com/ping"
        XCTAssertEqual(settings.effectiveLatencyTestURL, "https://example.com/ping")
    }

    func testMenuBarRateStringIsCompact() {
        XCTAssertEqual(0.menuBarRateString, "0 B/s")
        XCTAssertEqual(512.menuBarRateString, "512 B/s")
        XCTAssertEqual(1536.menuBarRateString, "1.5 KB/s")
        XCTAssertEqual((12 * 1024 * 1024).menuBarRateString, "12 MB/s")
    }
}
