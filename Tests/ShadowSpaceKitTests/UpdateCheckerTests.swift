import XCTest
@testable import ShadowSpaceKit

final class UpdateCheckerTests: XCTestCase {

    func testNewerVersionsDetected() {
        XCTAssertTrue(UpdateChecker.isNewer("0.2.2", than: "0.2.1"))
        XCTAssertTrue(UpdateChecker.isNewer("0.2.10", than: "0.2.2"))   // 數值比較，非字典序
        XCTAssertTrue(UpdateChecker.isNewer("1.0.0", than: "0.9.9"))
        XCTAssertTrue(UpdateChecker.isNewer("0.3", than: "0.2.9"))
    }

    func testSameOrOlderNotNewer() {
        XCTAssertFalse(UpdateChecker.isNewer("0.2.1", than: "0.2.1"))
        XCTAssertFalse(UpdateChecker.isNewer("0.2.1", than: "0.2.2"))
        XCTAssertFalse(UpdateChecker.isNewer("0.2.0", than: "0.2"))     // 0.2.0 == 0.2
        XCTAssertFalse(UpdateChecker.isNewer("0.9.9", than: "1.0.0"))
    }
}
