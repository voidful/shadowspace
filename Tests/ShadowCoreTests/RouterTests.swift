import XCTest
@testable import ShadowCore

final class RouterTests: XCTestCase {
    private func t(_ host: String, _ port: UInt16 = 443) -> Target { Target(host: host, port: port) }

    func testDomainSuffix() {
        let r = Router(rules: [RoutingRule(.domainSuffix("example.com"), .direct)],
                       proxy: DirectOutbound(), finalPolicy: .proxy)
        XCTAssertEqual(r.policy(for: t("example.com")), .direct)
        XCTAssertEqual(r.policy(for: t("www.example.com")), .direct)
        XCTAssertEqual(r.policy(for: t("notexample.com")), .proxy)   // 不應誤匹配
        XCTAssertEqual(r.policy(for: t("example.org")), .proxy)
    }

    func testKeywordAndExact() {
        let r = Router(rules: [
            RoutingRule(.domainKeyword("google"), .proxy),
            RoutingRule(.domainExact("ads.local"), .reject),
        ], proxy: DirectOutbound(), finalPolicy: .direct)
        XCTAssertEqual(r.policy(for: t("www.google.com")), .proxy)
        XCTAssertEqual(r.policy(for: t("ads.local")), .reject)
        XCTAssertEqual(r.policy(for: t("sub.ads.local")), .direct)   // exact 不含子網域 → final
    }

    func testCIDR() {
        let r = Router(rules: [RoutingRule(.ipCIDR("10.0.0.0/8"), .direct)],
                       proxy: DirectOutbound(), finalPolicy: .proxy)
        XCTAssertEqual(r.policy(for: t("10.1.2.3")), .direct)
        XCTAssertEqual(r.policy(for: t("11.0.0.1")), .proxy)
        let r24 = Router(rules: [RoutingRule(.ipCIDR("8.8.8.0/24"), .reject)],
                         proxy: DirectOutbound(), finalPolicy: .proxy)
        XCTAssertEqual(r24.policy(for: t("8.8.8.8")), .reject)
        XCTAssertEqual(r24.policy(for: t("8.8.9.8")), .proxy)
    }

    func testFirstMatchWins() {
        let r = Router(rules: [
            RoutingRule(.domainSuffix("example.com"), .direct),
            RoutingRule(.domainKeyword("example"), .reject),
        ], proxy: DirectOutbound(), finalPolicy: .proxy)
        XCTAssertEqual(r.policy(for: t("example.com")), .direct)     // 第一條先命中
    }

    func testFinalFallback() {
        let r = Router(rules: [], proxy: DirectOutbound(), finalPolicy: .reject)
        XCTAssertEqual(r.policy(for: t("anything.com")), .reject)
    }

    func testSelectReturnsOutbound() {
        let r = Router(rules: [RoutingRule(.domainExact("block.me"), .reject)],
                       proxy: DirectOutbound(), finalPolicy: .direct)
        XCTAssertEqual(r.select(t("block.me")).name, "REJECT")
        XCTAssertEqual(r.select(t("ok.com")).name, "DIRECT")
    }
}
