import Foundation
import Network

/// SOCKS5 UDP ASSOCIATE relay。開一個本地 UDP listener 供客戶端送 UDP datagram（帶 SOCKS UDP 標頭），
/// 解出目標後經出站的 UDPRelaySession 轉送；回程包回 SOCKS UDP 標頭送回客戶端。
/// 關聯生命週期綁定 TCP 控制連線：control 關閉即拆除。
enum UDPAssociate {

    static func run(client: NWStream, listenHost: String,
                    route: @escaping @Sendable (Target) -> Outbound, queue: DispatchQueue) async throws {
        let params = NWParameters.udp
        params.allowLocalEndpointReuse = true
        let listener = try NWListener(using: params, on: .any)

        let bridge = UDPRelayBridge(route: route, queue: queue)
        // 所有離開路徑（含 replyUDP／取埠失敗擲回）都拆除 listener/bridge/control，避免洩漏綁定的 UDP port。
        defer { listener.cancel(); bridge.close(); client.close() }
        listener.newConnectionHandler = { [weak bridge] conn in
            guard let bridge else { conn.cancel(); return }
            Task { await bridge.handleClientFlow(conn) }
        }

        // 啟動並取得綁定埠
        let port: UInt16 = try await withCheckedThrowingContinuation { cont in
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    listener.stateUpdateHandler = nil
                    cont.resume(returning: listener.port?.rawValue ?? 0)
                case .failed(let e):
                    listener.stateUpdateHandler = nil
                    cont.resume(throwing: e)
                default: break
                }
            }
            listener.start(queue: queue)
        }

        try await Socks5Handler.replyUDP(client, host: "127.0.0.1", port: port)

        // 保持 TCP 控制連線直到關閉 → defer 拆除
        while true {
            let d = try? await client.read()
            if d == nil || d!.isEmpty { break }
        }
    }
}

/// 橋接客戶端 UDP flow 與出站 UDPRelaySession（每個 association 一個）。
final class UDPRelayBridge: @unchecked Sendable {
    private let route: @Sendable (Target) -> Outbound
    private let queue: DispatchQueue
    private let lock = NSLock()
    private var clientConn: NWConnection?
    private var session: UDPRelaySession?
    private var replyLoopStarted = false
    private var closed = false

    init(route: @escaping @Sendable (Target) -> Outbound, queue: DispatchQueue) {
        self.route = route
        self.queue = queue
    }

    func handleClientFlow(_ conn: NWConnection) async {
        // 一個 UDP 關聯只服務發起 ASSOCIATE 的單一客戶端；後續來源的 flow 立即拒絕（RFC 1928 + 防誤路由/洩漏）
        lock.lock()
        if clientConn != nil || closed { lock.unlock(); conn.cancel(); return }
        clientConn = conn
        lock.unlock()
        conn.start(queue: queue)

        while true {
            guard let datagram = await receiveDatagram(conn), !datagram.isEmpty else { break }
            // SOCKS UDP 標頭：RSV(2) ‖ FRAG(1) ‖ ATYP+ADDR+PORT ‖ DATA
            let b = [UInt8](datagram)
            guard b.count >= 4, b[2] == 0x00 else { continue }   // 不支援分片（FRAG≠0 丟棄）
            guard let (target, next) = SocksAddress.parse(b, at: 3) else { continue }
            let payload = Data(b[next...])

            // 首個封包時延遲建立出站 relay（依該目標路由）
            if currentSession() == nil {
                do {
                    let s = try await route(target).openUDPRelay(queue: queue)
                    lock.lock(); session = s; lock.unlock()
                    startReplyLoop()
                } catch {
                    break   // 出站不支援 UDP relay → 結束此關聯
                }
            }
            try? await currentSession()?.send(payload, to: target)
        }
        conn.cancel()
    }

    private func currentSession() -> UDPRelaySession? {
        lock.lock(); defer { lock.unlock() }; return session
    }

    /// 出站回程 → 包 SOCKS UDP 標頭 → 送回客戶端。
    private func startReplyLoop() {
        lock.lock()
        if replyLoopStarted { lock.unlock(); return }
        replyLoopStarted = true
        let s = session
        let conn = clientConn
        lock.unlock()
        guard let s, let conn else { return }
        Task {
            while true {
                guard let (payload, from) = try? await s.receive() else { break }
                var out = Data([0x00, 0x00, 0x00])   // RSV RSV FRAG
                out.append(SocksAddress.encode(from))
                out.append(payload)
                conn.send(content: out, completion: .contentProcessed { _ in })
            }
        }
    }

    private func receiveDatagram(_ conn: NWConnection) async -> Data? {
        await withCheckedContinuation { (cont: CheckedContinuation<Data?, Never>) in
            conn.receiveMessage { data, _, _, error in
                if error != nil { cont.resume(returning: nil) }
                else { cont.resume(returning: data ?? Data()) }
            }
        }
    }

    func close() {
        lock.lock()
        if closed { lock.unlock(); return }
        closed = true
        let s = session; let c = clientConn
        session = nil; clientConn = nil
        lock.unlock()
        s?.close(); c?.cancel()
    }
}
