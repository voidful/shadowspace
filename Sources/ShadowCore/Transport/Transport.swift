import Foundation
import Network

/// 傳輸層設定：底層 TCP/WS + 是否 TLS。協議（Trojan/VLESS/VMess）套在它之上。
public struct TransportConfig: Sendable {
    public enum NetworkKind: String, Sendable { case tcp, ws }

    public var network: NetworkKind = .tcp
    public var tls: Bool = false
    public var sni: String?
    public var insecure: Bool = false
    public var alpn: [String]?
    public var wsPath: String = "/"
    public var wsHost: String?

    public init(network: NetworkKind = .tcp, tls: Bool = false, sni: String? = nil,
                insecure: Bool = false, alpn: [String]? = nil,
                wsPath: String = "/", wsHost: String? = nil) {
        self.network = network
        self.tls = tls
        self.sni = sni
        self.insecure = insecure
        self.alpn = alpn
        self.wsPath = wsPath
        self.wsHost = wsHost
    }
}

public enum Transport {
    public static func dial(host: String, port: UInt16,
                            config: TransportConfig, queue: DispatchQueue) async throws -> ByteStream {
        switch config.network {
        case .tcp:
            if config.tls {
                return try await TLSTransport.dial(
                    host: host, port: port, sni: config.sni ?? host,
                    insecure: config.insecure, alpn: config.alpn, queue: queue)
            } else {
                let tcp = NWStream(host: host, port: port, queue: queue)
                try await tcp.start()
                return tcp
            }
        case .ws:
            let ws = WSStream(host: host, port: port, path: config.wsPath, hostHeader: config.wsHost,
                              tls: config.tls, sni: config.sni, insecure: config.insecure, queue: queue)
            try await ws.start()
            return ws
        }
    }
}
