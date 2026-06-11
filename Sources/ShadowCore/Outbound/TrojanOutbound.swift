import Foundation
import Network

/// Trojan 串流：TLS 之上，首次送出 Trojan 請求標頭，之後純轉送（無分塊）。
/// 標頭 = hex(SHA224(password)) ‖ CRLF ‖ CMD(0x01) ‖ SOCKS位址 ‖ CRLF
public final class TrojanStream: ByteStream, @unchecked Sendable {
    private let under: ByteStream
    private let header: Data
    private var headerSent = false

    public init(under: ByteStream, password: String, target: Target) {
        self.under = under
        self.header = Self.buildHeader(password: password, target: target)
    }

    public static func buildHeader(password: String, target: Target) -> Data {
        var h = Data()
        h.append(SHA224.hexLower(password))      // 56 bytes
        h.append(contentsOf: [0x0D, 0x0A])
        h.append(0x01)                            // CONNECT
        h.append(SocksAddress.encode(target))
        h.append(contentsOf: [0x0D, 0x0A])
        return h
    }

    /// 連線後立即送出標頭，讓「伺服器先說話」的目標（如 SMTP）也能運作。
    public func sendHeader() async throws {
        guard !headerSent else { return }
        headerSent = true
        try await under.write(header)
    }

    public func write(_ data: Data) async throws {
        try await sendHeader()
        try await under.write(data)
    }

    public func read() async throws -> Data { try await under.read() }
    public func close() { under.close() }
}

public struct TrojanOutbound: Outbound {
    public let name: String
    private let server: Target
    private let password: String
    private let transport: TransportConfig

    public init(name: String, host: String, port: UInt16, password: String,
                transport: TransportConfig = TransportConfig(tls: true)) {
        self.name = name
        self.server = Target(host: host, port: port)
        self.password = password
        var t = transport
        t.tls = true                      // Trojan 必為 TLS
        if t.sni == nil { t.sni = host }
        self.transport = t
    }

    public func connect(to target: Target, queue: DispatchQueue) async throws -> ByteStream {
        let under = try await Transport.dial(host: server.host, port: server.port,
                                             config: transport, queue: queue)
        let stream = TrojanStream(under: under, password: password, target: target)
        try await stream.sendHeader()
        return stream
    }
}
