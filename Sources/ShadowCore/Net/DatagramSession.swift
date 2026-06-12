import Foundation
import Network

/// 單一目標的 UDP datagram session。send/receive 各處理一個 UDP payload。
public protocol DatagramSession: AnyObject, Sendable {
    func send(_ data: Data) async throws
    func receive() async throws -> Data
    func close()
}

/// Network.framework 的 UDP 連線包裝；用 connected UDP，目標由 NWConnection 綁定。
public final class NWDatagramSession: DatagramSession, @unchecked Sendable {
    public enum DatagramError: Error { case notReady }

    private let connection: NWConnection
    private let queue: DispatchQueue

    public init(host: String, port: UInt16, queue: DispatchQueue) {
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port) ?? .any
        )
        self.connection = NWConnection(to: endpoint, using: .udp)
        self.queue = queue
    }

    public func start() async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    self?.connection.stateUpdateHandler = nil
                    cont.resume()
                case .failed(let error), .waiting(let error):
                    self?.connection.stateUpdateHandler = nil
                    cont.resume(throwing: error)
                case .cancelled:
                    self?.connection.stateUpdateHandler = nil
                    cont.resume(throwing: DatagramError.notReady)
                default:
                    break
                }
            }
            connection.start(queue: queue)
        }
    }

    public func send(_ data: Data) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error { cont.resume(throwing: error) } else { cont.resume() }
            })
        }
    }

    public func receive() async throws -> Data {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            connection.receiveMessage { data, _, _, error in
                if let error {
                    cont.resume(throwing: error)
                } else {
                    cont.resume(returning: data ?? Data())
                }
            }
        }
    }

    public func close() {
        connection.cancel()
    }
}
