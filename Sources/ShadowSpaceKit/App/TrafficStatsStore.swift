import Foundation

/// 即時流量統計（每秒更新）。獨立成 ObservableObject，讓每秒的速率變化只重繪
/// 有顯示流量的畫面（首頁、選單列），不再連帶重繪節點/規則/設定等分頁。
@MainActor
final class TrafficStatsStore: ObservableObject {
    private struct Snapshot: Equatable {
        var upRate = 0
        var downRate = 0
        var sessionUpTotal = 0
        var sessionDownTotal = 0
        var trafficHistory: [TrafficSample] = []
    }

    /// 一個取樣只發布一次，避免速率、總量、圖表各自觸發 SwiftUI 重畫。
    @Published private var snapshot = Snapshot()

    var upRate: Int { snapshot.upRate }
    var downRate: Int { snapshot.downRate }
    var sessionUpTotal: Int { snapshot.sessionUpTotal }
    var sessionDownTotal: Int { snapshot.sessionDownTotal }
    var trafficHistory: [TrafficSample] { snapshot.trafficHistory }

    private var seq = 0
    static let window = 60                           // 歷史環形緩衝長度（流量圖）

    /// 更新即時速率並寫入歷史環形緩衝（流量圖用）。
    func push(up: Int, down: Int, totalUp: Int? = nil, totalDown: Int? = nil) {
        var next = snapshot
        next.upRate = up
        next.downRate = down
        next.sessionUpTotal = totalUp ?? (next.sessionUpTotal + up)
        next.sessionDownTotal = totalDown ?? (next.sessionDownTotal + down)
        seq &+= 1
        next.trafficHistory.append(TrafficSample(seq: seq, up: up, down: down))
        if next.trafficHistory.count > Self.window {
            next.trafficHistory.removeFirst(next.trafficHistory.count - Self.window)
        }
        snapshot = next
    }

    /// 連線開始：歸零本次所有統計。
    func resetSession() {
        snapshot = Snapshot()
    }

    /// 斷線：清掉即時速率與歷史，保留本次累計總量供最後檢視。
    func clearLive() {
        var next = snapshot
        next.upRate = 0
        next.downRate = 0
        next.trafficHistory = []
        snapshot = next
    }
}

/// 高頻核心日誌獨立於 AppState；只有日誌頁（以及需要登入連結的設定頁）會重繪。
@MainActor
final class EngineLogStore: ObservableObject {
    static let limit = 800

    @Published private(set) var lines: [LogLine] = []
    private var seq = 0

    func append(_ text: String) {
        append(contentsOf: [text])
    }

    /// 同一批核心輸出只發布一次，並維持固定上限。
    func append(contentsOf texts: [String]) {
        guard !texts.isEmpty else { return }
        var next = lines
        next.reserveCapacity(min(Self.limit, next.count + texts.count))
        for text in texts where !text.isEmpty {
            seq &+= 1
            next.append(LogLine(id: seq, text: text))
        }
        guard next.count != lines.count else { return }
        if next.count > Self.limit {
            next.removeFirst(next.count - Self.limit)
        }
        lines = next
    }

    func replace(with texts: [String]) {
        var next: [LogLine] = []
        next.reserveCapacity(min(Self.limit, texts.count))
        for text in texts.suffix(Self.limit) where !text.isEmpty {
            seq &+= 1
            next.append(LogLine(id: seq, text: text))
        }
        lines = next
    }

    func clear() {
        guard !lines.isEmpty else { return }
        lines = []
    }

    func tailText(limit: Int) -> String {
        lines.suffix(limit).map(\.text).joined(separator: "\n")
    }
}

/// 活躍連線每秒刷新，但不應讓首頁、節點與設定頁一起重畫。
@MainActor
final class ConnectionStatsStore: ObservableObject {
    private struct Snapshot: Equatable {
        var items: [ConnectionInfo] = []
        var uploadTotal = 0
        var downloadTotal = 0
    }

    @Published private var snapshot = Snapshot()

    var items: [ConnectionInfo] { snapshot.items }
    var uploadTotal: Int { snapshot.uploadTotal }
    var downloadTotal: Int { snapshot.downloadTotal }

    func update(items: [ConnectionInfo], uploadTotal: Int, downloadTotal: Int) {
        let next = Snapshot(items: items, uploadTotal: uploadTotal, downloadTotal: downloadTotal)
        guard next != snapshot else { return }
        snapshot = next
    }

    func clear() {
        guard !snapshot.items.isEmpty || snapshot.uploadTotal != 0 || snapshot.downloadTotal != 0 else {
            return
        }
        snapshot = Snapshot()
    }
}
