import Foundation
import Network

/// Shadowsocks 出站：連到 SS 伺服器，回傳會自動做 AEAD 加解密的串流。
public struct ShadowsocksOutbound: Outbound {
    public let name: String
    private let server: Target
    private let method: SSMethod
    private let masterKey: Data

    public init?(name: String, host: String, port: UInt16, method: String, password: String) {
        guard let m = SSMethod(method) else { return nil }
        self.name = name
        self.server = Target(host: host, port: port)
        self.method = m
        self.masterKey = ShadowsocksCrypto.masterKey(password: password, keyLength: m.keyLength)
    }

    public func connect(to target: Target, queue: DispatchQueue) async throws -> ByteStream {
        let tcp = NWStream(host: server.host, port: server.port, queue: queue)
        try await tcp.start()
        return ShadowsocksStream(under: tcp, method: method, masterKey: masterKey, target: target)
    }
}
