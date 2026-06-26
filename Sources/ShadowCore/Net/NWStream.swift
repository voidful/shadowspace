import Foundation
import Network

/// 把 Network.framework 的 callback 式 NWConnection 包成 async/await 的雙工位元組串流。
/// 入站（被接受的連線）與出站（撥出的連線）共用同一個抽象，中繼層才能對稱地搬位元組。
public final class NWStream: ByteStream, @unchecked Sendable {

    public enum StreamError: Error { case eof, shortRead, notReady }

    public let connection: NWConnection
    private let queue: DispatchQueue

    public init(connection: NWConnection, queue: DispatchQueue) {
        self.connection = connection
        self.queue = queue
    }

    /// 撥出一條 TCP（可選 TLS）連線。host 可為網域或 IP；網域會在連線時解析。
    public convenience init(host: String, port: UInt16, tls: Bool = false,
                            sni: String? = nil, queue: DispatchQueue) {
        let params: NWParameters
        if tls {
            let tlsOptions = NWProtocolTLS.Options()
            if let sni {
                sec_protocol_options_set_tls_server_name(tlsOptions.securityProtocolOptions, sni)
            }
            params = NWParameters(tls: tlsOptions, tcp: NWProtocolTCP.Options())
        } else {
            params = .tcp
        }
        params.disablingSystemProxy()   // 出站不遵循系統代理，避免自迴圈
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port) ?? .any)
        self.init(connection: NWConnection(to: endpoint, using: params), queue: queue)
    }

    /// 啟動連線並等到 .ready（或拋出失敗）。
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
                    cont.resume(throwing: StreamError.notReady)
                default:
                    break
                }
            }
            connection.start(queue: queue)
        }
    }

    /// 讀取 1…64KB 位元組；回傳空 Data 代表 EOF。
    public func read() async throws -> Data {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) {
                data, _, isComplete, error in
                if let error {
                    cont.resume(throwing: error)
                } else if let data, !data.isEmpty {
                    cont.resume(returning: data)
                } else if isComplete {
                    cont.resume(returning: Data())   // EOF
                } else {
                    cont.resume(returning: Data())
                }
            }
        }
    }

    /// 精確讀取 n 位元組（協議標頭用）；不足即 EOF → 拋錯。
    public func readExactly(_ n: Int) async throws -> Data {
        guard n > 0 else { return Data() }
        return try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            connection.receive(minimumIncompleteLength: n, maximumLength: n) {
                data, _, isComplete, error in
                if let error {
                    cont.resume(throwing: error)
                } else if let data, data.count == n {
                    cont.resume(returning: data)
                } else {
                    cont.resume(throwing: isComplete ? StreamError.eof : StreamError.shortRead)
                }
            }
        }
    }

    public func write(_ data: Data) async throws {
        guard !data.isEmpty else { return }
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error { cont.resume(throwing: error) } else { cont.resume() }
            })
        }
    }

    public func close() {
        connection.cancel()
    }
}
