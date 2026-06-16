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
    }

    func testMenuBarRateStringIsCompact() {
        XCTAssertEqual(0.menuBarRateString, "0 B/s")
        XCTAssertEqual(512.menuBarRateString, "512 B/s")
        XCTAssertEqual(1536.menuBarRateString, "1.5 KB/s")
        XCTAssertEqual((12 * 1024 * 1024).menuBarRateString, "12 MB/s")
    }
}
