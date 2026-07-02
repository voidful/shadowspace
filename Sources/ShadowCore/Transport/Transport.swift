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
    /// TLS ClientHello 分片（抗封鎖）
    public var fragment: Bool = false
    /// 用自建 TLS 1.3 客戶端（可控 ClientHello、瀏覽器指紋）取代 Apple NWProtocolTLS。
    /// 目前套用於 TCP+TLS 路徑（Trojan / VLESS-tcp-tls）；WS 路徑仍走 Apple TLS。
    public var nativeTLS: Bool = false
    /// nativeTLS 的指紋預設（chrome…）；nil = chrome。
    public var fingerprint: String?
    /// REALITY 設定；非 nil 時強制走自建 TLS 1.3（含 REALITY 認證與伺服器驗證）。
    public var reality: RealityClientConfig?

    public init(network: NetworkKind = .tcp, tls: Bool = false, sni: String? = nil,
                insecure: Bool = false, alpn: [String]? = nil,
                wsPath: String = "/", wsHost: String? = nil, fragment: Bool = false,
                nativeTLS: Bool = false, fingerprint: String? = nil,
                reality: RealityClientConfig? = nil) {
        self.network = network
        self.tls = tls
        self.sni = sni
        self.insecure = insecure
        self.alpn = alpn
        self.wsPath = wsPath
        self.wsHost = wsHost
        self.fragment = fragment
        self.nativeTLS = nativeTLS
        self.fingerprint = fingerprint
        self.reality = reality
    }
}

public enum Transport {
    public static func dial(host: String, port: UInt16,
                            config: TransportConfig, queue: DispatchQueue) async throws -> ByteStream {
        switch config.network {
        case .tcp:
            if config.tls {
                if config.nativeTLS || config.reality != nil {
                    // 自建 TLS 1.3（瀏覽器指紋，抗 JA3/指紋偵測）；REALITY 時另做認證與伺服器驗證。
                    // 不驗證一般憑證鏈（同 allowInsecure 語意；REALITY 以 authKey-HMAC 認證伺服器）。
                    return try await NativeTLS13Client.dial(
                        host: host, port: port, sni: config.sni ?? host,
                        alpn: config.alpn ?? ["h2", "http/1.1"],
                        preset: FingerprintPreset(config.fingerprint),
                        reality: config.reality, queue: queue)
                }
                return try await TLSTransport.dial(
                    host: host, port: port, sni: config.sni ?? host,
                    insecure: config.insecure, alpn: config.alpn,
                    fragment: config.fragment, queue: queue)
            } else {
                let tcp = NWStream(host: host, port: port, queue: queue)
                try await tcp.start()
                return tcp
            }
        case .ws:
            let ws = WSStream(host: host, port: port, path: config.wsPath, hostHeader: config.wsHost,
                              tls: config.tls, sni: config.sni, insecure: config.insecure,
                              fragment: config.fragment, queue: queue)
            try await ws.start()
            return ws
        }
    }
}
