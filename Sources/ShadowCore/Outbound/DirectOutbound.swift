import Foundation
import Network

/// 直連：不經任何代理，直接連到目標。
public struct DirectOutbound: Outbound {
    public let name = "DIRECT"
    public init() {}

    public func connect(to target: Target, queue: DispatchQueue) async throws -> ByteStream {
        let stream = NWStream(host: target.host, port: target.port, queue: queue)
        try await stream.start()
        return stream
    }

    public func openDatagramSession(to target: Target, queue: DispatchQueue) async throws -> DatagramSession {
        let session = NWDatagramSession(host: target.host, port: target.port, queue: queue)
        try await session.start()
        return session
    }

    public func openUDPRelay(queue: DispatchQueue) async throws -> UDPRelaySession {
        DirectUDPRelay(queue: queue)
    }
}

/// 直連的多工 UDP relay：每個目標一條 connected UDP，接收合併成單一佇列。
public final class DirectUDPRelay: UDPRelaySession, @unchecked Sendable {
    private let queue: DispatchQueue
    private let lock = NSLock()
    private var sessions: [String: NWDatagramSession] = [:]
    private var inbox: [(payload: Data, from: Target)] = []
    private var waiter: CheckedContinuation<(payload: Data, from: Target), Error>?
    private var closed = false

    public init(queue: DispatchQueue) { self.queue = queue }

    public func send(_ payload: Data, to target: Target) async throws {
        let key = "\(target.host):\(target.port)"
        lock.lock(); var s = sessions[key]; lock.unlock()
        if s == nil {
            let ns = NWDatagramSession(host: target.host, port: target.port, queue: queue)
            try await ns.start()
            lock.lock()
            if closed {                                  // 建立期間已關閉 → 別存進死 relay（否則洩漏）
                lock.unlock(); ns.close()
                throw ProxyError.protocolError("UDP relay 已關閉")
            }
            if let existing = sessions[key] {            // 同 key 併發首封包競態
                lock.unlock(); ns.close(); s = existing
            } else {
                sessions[key] = ns; lock.unlock(); s = ns
                startRecvLoop(ns, target)
            }
        }
        try await s?.send(payload)
    }

    public func receive() async throws -> (payload: Data, from: Target) {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<(payload: Data, from: Target), Error>) in
            lock.lock()
            if closed { lock.unlock(); cont.resume(throwing: ProxyError.protocolError("UDP relay 已關閉")); return }
            if !inbox.isEmpty {
                let item = inbox.removeFirst(); lock.unlock(); cont.resume(returning: item); return
            }
            waiter = cont; lock.unlock()
        }
    }

    private func startRecvLoop(_ session: NWDatagramSession, _ target: Target) {
        Task {
            while true {
                guard let d = try? await session.receive(), !d.isEmpty else { break }
                lock.lock()
                if let w = waiter { waiter = nil; lock.unlock(); w.resume(returning: (d, target)) }
                else { inbox.append((d, target)); lock.unlock() }
            }
        }
    }

    public func close() {
        lock.lock()
        if closed { lock.unlock(); return }
        closed = true
        let all = Array(sessions.values); sessions.removeAll()
        let w = waiter; waiter = nil
        lock.unlock()
        all.forEach { $0.close() }
        w?.resume(throwing: ProxyError.protocolError("UDP relay 已關閉"))
    }
}
