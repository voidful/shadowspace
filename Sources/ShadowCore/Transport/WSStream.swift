import Foundation
import Network

/// WebSocket 傳輸串流：把代理載荷裝進 WS 二進位訊息（可疊在 TLS 上 = wss）。
/// 機場節點常見的 vmess-ws / vless-ws / trojan-ws 用。
public final class WSStream: ByteStream, @unchecked Sendable {
    private let connection: NWConnection
    private let queue: DispatchQueue

    public init(host: String, port: UInt16, path: String, hostHeader: String?,
                tls: Bool, sni: String?, insecure: Bool, fragment: Bool = false, queue: DispatchQueue) {
        self.queue = queue
        let wsOptions = NWProtocolWebSocket.Options()
        wsOptions.autoReplyPing = true
        if let hostHeader, !hostHeader.isEmpty {
            wsOptions.setAdditionalHeaders([("Host", hostHeader)])
        }
        let params: NWParameters = tls
            ? TLSTransport.parameters(sni: sni ?? hostHeader ?? host, insecure: insecure,
                                      alpn: nil, fragment: fragment, queue: queue)
            : .tcp
        params.disablingSystemProxy()   // 出站不遵循系統代理，避免自迴圈（tls 路徑已設，重設無妨）
        params.defaultProtocolStack.applicationProtocols.insert(wsOptions, at: 0)

        let scheme = tls ? "wss" : "ws"
        let cleanPath = path.hasPrefix("/") ? path : "/" + path
        let url = URL(string: "\(scheme)://\(host):\(port)\(cleanPath)")!
        connection = NWConnection(to: .url(url), using: params)
    }

    public func start() async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.stateUpdateHandler = { [weak self] state in
                switch state {
                case .ready:
                    self?.connection.stateUpdateHandler = nil; cont.resume()
                case .failed(let error), .waiting(let error):
                    self?.connection.stateUpdateHandler = nil; cont.resume(throwing: error)
                case .cancelled:
                    self?.connection.stateUpdateHandler = nil
                    cont.resume(throwing: NWStream.StreamError.notReady)
                default:
                    break
                }
            }
            connection.start(queue: queue)
        }
    }

    public func read() async throws -> Data {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Data, Error>) in
            connection.receiveMessage { data, context, _, error in
                if let error { cont.resume(throwing: error); return }
                if let context,
                   let meta = context.protocolMetadata(definition: NWProtocolWebSocket.definition)
                       as? NWProtocolWebSocket.Metadata,
                   meta.opcode == .close {
                    cont.resume(returning: Data())   // 對方關閉 = EOF
                    return
                }
                cont.resume(returning: data ?? Data())
            }
        }
    }

    public func write(_ data: Data) async throws {
        let meta = NWProtocolWebSocket.Metadata(opcode: .binary)
        let context = NWConnection.ContentContext(identifier: "binary", metadata: [meta])
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            connection.send(content: data, contentContext: context, isComplete: true,
                            completion: .contentProcessed { error in
                if let error { cont.resume(throwing: error) } else { cont.resume() }
            })
        }
    }

    public func close() { connection.cancel() }
}
