import Foundation
import Network
import Security

/// 建立 TLS 連線（含 SNI、允許不安全憑證、ALPN），回傳明文之上的 TLS ByteStream。
/// Trojan / VLESS 等以 TLS 為傳輸層的協議共用。
public enum TLSTransport {

    public static func parameters(sni: String?, insecure: Bool, alpn: [String]?,
                                  queue: DispatchQueue) -> NWParameters {
        let tls = NWProtocolTLS.Options()
        let sec = tls.securityProtocolOptions
        if let sni, !sni.isEmpty {
            sec_protocol_options_set_tls_server_name(sec, sni)
        }
        if let alpn {
            for proto in alpn { sec_protocol_options_add_tls_application_protocol(sec, proto) }
        }
        if insecure {
            // 對應節點的 allowInsecure：跳過憑證鏈驗證
            sec_protocol_options_set_verify_block(sec, { _, _, complete in
                complete(true)
            }, queue)
        }
        return NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
    }

    public static func dial(host: String, port: UInt16,
                            sni: String?, insecure: Bool, alpn: [String]?,
                            queue: DispatchQueue) async throws -> NWStream {
        let params = parameters(sni: sni, insecure: insecure, alpn: alpn, queue: queue)
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port) ?? .any)
        let stream = NWStream(connection: NWConnection(to: endpoint, using: params), queue: queue)
        try await stream.start()
        return stream
    }
}
