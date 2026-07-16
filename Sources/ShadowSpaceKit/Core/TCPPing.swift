import Foundation
import Network

/// TCP 握手延遲測試。不依賴引擎，隨時可測。
enum TCPPing {

    /// stateUpdateHandler 與 timeout 都可能觸發結束，用鎖保證只 resume 一次
    private final class PingState: @unchecked Sendable {
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Int?, Never>?
        var connection: NWConnection?
        let start = Date()

        init(_ continuation: CheckedContinuation<Int?, Never>) {
            self.continuation = continuation
        }

        func finish(_ ms: Int?) {
            lock.lock()
            let cont = continuation
            continuation = nil
            lock.unlock()
            guard let cont else { return }
            connection?.cancel()
            cont.resume(returning: ms)
        }
    }

    static func ping(host: String, port: Int, timeout: TimeInterval = 3) async -> Int? {
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else { return nil }
        let queue = DispatchQueue(label: "shadowspace.tcping")

        return await withCheckedContinuation { continuation in
            let state = PingState(continuation)
            let connection = NWConnection(
                host: NWEndpoint.Host(host), port: nwPort, using: .tcp)
            state.connection = connection
            connection.stateUpdateHandler = { st in
                switch st {
                case .ready:
                    state.finish(Int(Date().timeIntervalSince(state.start) * 1000))
                case .failed, .cancelled:
                    state.finish(nil)
                default:
                    break
                }
            }
            queue.asyncAfter(deadline: .now() + timeout) {
                state.finish(nil)
            }
            connection.start(queue: queue)
        }
    }

    /// 並行測試多個節點，限制同時連線數
    static func pingAll(_ targets: [(id: UUID, host: String, port: Int)],
                        maxConcurrent: Int = 16) async -> [UUID: Int] {
        await withTaskGroup(of: (UUID, Int).self, returning: [UUID: Int].self) { group in
            var iterator = targets.makeIterator()
            var active = 0
            var results: [UUID: Int] = [:]
            results.reserveCapacity(targets.count)
            func addNext(_ group: inout TaskGroup<(UUID, Int)>) {
                guard let target = iterator.next() else { return }
                active += 1
                group.addTask {
                    let ms = await ping(host: target.host, port: target.port)
                    return (target.id, ms ?? -1)
                }
            }
            for _ in 0..<min(64, max(1, maxConcurrent)) { addNext(&group) }
            while active > 0 {
                if let (id, ms) = await group.next() {
                    results[id] = ms
                }
                active -= 1
                addNext(&group)
            }
            return results
        }
    }
}
