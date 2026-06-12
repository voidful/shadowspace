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
}
