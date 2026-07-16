import Combine
import XCTest
@testable import ShadowSpaceKit

@MainActor
final class LiveDataStoreTests: XCTestCase {

    func testTrafficSamplePublishesOneAtomicUpdate() {
        let store = TrafficStatsStore()
        var publications = 0
        let token = store.objectWillChange.sink { publications += 1 }

        store.push(up: 120, down: 340)

        XCTAssertEqual(publications, 1)
        XCTAssertEqual(store.upRate, 120)
        XCTAssertEqual(store.downRate, 340)
        XCTAssertEqual(store.sessionUpTotal, 120)
        XCTAssertEqual(store.sessionDownTotal, 340)
        XCTAssertEqual(store.trafficHistory.count, 1)
        withExtendedLifetime(token) {}
    }

    func testLogBatchPublishesOnceAndKeepsRingLimit() {
        let store = EngineLogStore()
        var publications = 0
        let token = store.objectWillChange.sink { publications += 1 }
        let input = (0..<1_000).map { "line \($0)" }

        store.append(contentsOf: input)

        XCTAssertEqual(publications, 1)
        XCTAssertEqual(store.lines.count, EngineLogStore.limit)
        XCTAssertEqual(store.lines.first?.text, "line 200")
        XCTAssertEqual(store.lines.last?.text, "line 999")
        withExtendedLifetime(token) {}
    }

    func testIdenticalConnectionSnapshotDoesNotRepublish() {
        let store = ConnectionStatsStore()
        var publications = 0
        let token = store.objectWillChange.sink { publications += 1 }
        let item = ConnectionInfo(id: "1", target: "example.com:443", network: "tcp",
                                  rule: "match", chain: "proxy", upload: 10,
                                  download: 20, start: nil)

        store.update(items: [item], uploadTotal: 10, downloadTotal: 20)
        store.update(items: [item], uploadTotal: 10, downloadTotal: 20)

        XCTAssertEqual(publications, 1)
        XCTAssertEqual(store.items, [item])
        withExtendedLifetime(token) {}
    }

    func testPersistenceFlushKeepsLatestSnapshot() async throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("shadowspace-state-\(UUID().uuidString).json")
        defer { try? FileManager.default.removeItem(at: url) }
        let writer = StatePersistenceWriter(url: url)

        var firstSettings = AppSettings()
        firstSettings.mixedPort = 7_890
        writer.enqueue(PersistedState(settings: firstSettings))

        var latestSettings = AppSettings()
        latestSettings.mixedPort = 9_090
        writer.flush(PersistedState(settings: latestSettings))

        // 等待第一筆延遲工作到期，確認它已失效且不會覆蓋 flush 的最後快照。
        try await Task.sleep(for: .milliseconds(100))
        let data = try Data(contentsOf: url)
        let state = try JSONDecoder().decode(PersistedState.self, from: data)
        XCTAssertEqual(state.settings.mixedPort, 9_090)
    }
}
