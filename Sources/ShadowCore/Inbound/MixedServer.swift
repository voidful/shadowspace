import Foundation
import Network

/// 本地混合入站：同一連接埠同時接受 SOCKS5 與 HTTP 代理。
/// 依首位元組分流（0x05 → SOCKS5，其餘 → HTTP）。
public final class MixedServer: @unchecked Sendable {

    public typealias Route = @Sendable (Target) -> Outbound

    private let host: String
    private let port: UInt16
    private let route: Route
    private let onBytes: (@Sendable (Int, Int) -> Void)?
    private let queue = DispatchQueue(label: "shadowcore.mixed", attributes: .concurrent)
    private var listener: NWListener?

    public init(host: String, port: UInt16,
                onBytes: (@Sendable (Int, Int) -> Void)? = nil,
                route: @escaping Route) {
        self.host = host
        self.port = port
        self.onBytes = onBytes
        self.route = route
    }

    public func start() throws {
        let params = NWParameters.tcp
        params.allowLocalEndpointReuse = true
        if host == "127.0.0.1" || host == "localhost" {
            params.requiredInterfaceType = .loopback
        }
        let listener = try NWListener(using: params,
                                      on: NWEndpoint.Port(rawValue: port) ?? .any)
        listener.newConnectionHandler = { [weak self] conn in
            guard let self else { conn.cancel(); return }
            Task { await self.handle(conn) }
        }
        listener.start(queue: queue)
        self.listener = listener
    }

    public func stop() {
        listener?.cancel()
        listener = nil
    }

    private func handle(_ conn: NWConnection) async {
        let client = NWStream(connection: conn, queue: queue)
        do {
            try await client.start()
            let first = try await client.readExactly(1)

            let target: Target
            var isConnect = true
            var initialToRemote = Data()
            if first[0] == 0x05 {
                target = try await Socks5Handler.readRequest(client)
            } else {
                let parsed = try await HttpProxyHandler.readRequest(client, prefix: first)
                target = parsed.target
                isConnect = parsed.isConnect
                initialToRemote = parsed.initialToRemote
            }

            // 撥出站
            let outbound = route(target)
            let remote: ByteStream
            do {
                remote = try await outbound.connect(to: target, queue: queue)
            } catch {
                if first[0] == 0x05 {
                    try? await Socks5Handler.reply(client, success: false)
                } else if isConnect {
                    try? await HttpProxyHandler.replyError(client)
                }
                client.close()
                return
            }

            // 回覆客戶端 / 送出初始位元組
            if first[0] == 0x05 {
                try await Socks5Handler.reply(client, success: true)
            } else if isConnect {
                try await HttpProxyHandler.replyConnectSuccess(client)
            }
            if !initialToRemote.isEmpty {
                try await remote.write(initialToRemote)
            }

            await Relay.run(client: client, remote: remote, onBytes: onBytes)
        } catch {
            client.close()
        }
    }
}
