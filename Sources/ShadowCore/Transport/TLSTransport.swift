import Foundation
import Network
import Security

/// 建立 TLS 連線（含 SNI、允許不安全憑證、ALPN），回傳明文之上的 TLS ByteStream。
/// Trojan / VLESS 等以 TLS 為傳輸層的協議共用。
public enum TLSTransport {

    public static func parameters(sni: String?, insecure: Bool, alpn: [String]?,
                                  fragment: Bool = false, queue: DispatchQueue) -> NWParameters {
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
        let tcp = NWProtocolTCP.Options()
        if fragment { tcp.noDelay = true }   // 關 Nagle，讓小段各自成為獨立區段
        let params = NWParameters(tls: tls, tcp: tcp)
        if fragment {
            // 把分片 framer 接在 TLS 之下、TCP 之上
            let framerOptions = NWProtocolFramer.Options(definition: TLSFragmentFramer.definition)
            params.defaultProtocolStack.applicationProtocols.append(framerOptions)
        }
        return params.disablingSystemProxy()   // 出站不遵循系統代理，避免自迴圈
    }

    public static func dial(host: String, port: UInt16,
                            sni: String?, insecure: Bool, alpn: [String]?,
                            fragment: Bool = false, queue: DispatchQueue) async throws -> NWStream {
        let params = parameters(sni: sni, insecure: insecure, alpn: alpn, fragment: fragment, queue: queue)
        let endpoint = NWEndpoint.hostPort(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(rawValue: port) ?? .any)
        let stream = NWStream(connection: NWConnection(to: endpoint, using: params), queue: queue)
        try await stream.start()
        return stream
    }
}
