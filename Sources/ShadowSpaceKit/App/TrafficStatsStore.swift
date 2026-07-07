import Foundation

/// 即時流量統計（每秒更新）。獨立成 ObservableObject，讓每秒的速率變化只重繪
/// 有顯示流量的畫面（首頁、選單列），不再連帶重繪節點/規則/設定等分頁。
@MainActor
final class TrafficStatsStore: ObservableObject {
    @Published var upRate = 0                       // bytes/s
    @Published var downRate = 0                     // bytes/s
    @Published var sessionUpTotal = 0               // 本次連線累計上傳
    @Published var sessionDownTotal = 0             // 本次連線累計下載
    @Published var trafficHistory: [TrafficSample] = []

    private var seq = 0
    static let window = 60                           // 歷史環形緩衝長度（流量圖）

    /// 更新即時速率並寫入歷史環形緩衝（流量圖用）。
    func push(up: Int, down: Int) {
        upRate = up
        downRate = down
        seq &+= 1
        trafficHistory.append(TrafficSample(seq: seq, up: up, down: down))
        if trafficHistory.count > Self.window {
            trafficHistory.removeFirst(trafficHistory.count - Self.window)
        }
    }

    /// 連線開始：歸零本次所有統計。
    func resetSession() {
        upRate = 0
        downRate = 0
        sessionUpTotal = 0
        sessionDownTotal = 0
        trafficHistory = []
    }

    /// 斷線：清掉即時速率與歷史，保留本次累計總量供最後檢視。
    func clearLive() {
        upRate = 0
        downRate = 0
        trafficHistory = []
    }
}
