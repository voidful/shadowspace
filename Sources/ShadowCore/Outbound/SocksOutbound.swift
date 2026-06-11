import Foundation
import Network

/// SOCKS5 出站：連到上游 SOCKS5 代理（支援 no-auth 與帳密），握手後純轉送。
public struct SocksOutbound: Outbound {
    public let name: String
    private let server: Target
    private let username: String?
    private let password: String?

    public init(name: String, host: String, port: UInt16,
                username: String? = nil, password: String? = nil) {
        self.name = name
        self.server = Target(host: host, port: port)
        self.username = username
        self.password = password
    }

    public func connect(to target: Target, queue: DispatchQueue) async throws -> ByteStream {
        let s = NWStream(host: server.host, port: server.port, queue: queue)
        try await s.start()

        let useAuth = (username?.isEmpty == false)
        // 方法協商
        try await s.write(Data(useAuth ? [0x05, 0x01, 0x02] : [0x05, 0x01, 0x00]))
        let methodReply = try await s.readExactly(2)
        guard methodReply[0] == 0x05 else { throw ProxyError.protocolError("SOCKS5 版本錯誤") }
        switch methodReply[1] {
        case 0x00:
            break
        case 0x02:
            let u = Array((username ?? "").utf8), p = Array((password ?? "").utf8)
            var auth = Data([0x01, UInt8(min(u.count, 255))])
            auth.append(contentsOf: u.prefix(255))
            auth.append(UInt8(min(p.count, 255)))
            auth.append(contentsOf: p.prefix(255))
            try await s.write(auth)
            let authReply = try await s.readExactly(2)
            guard authReply[1] == 0x00 else { throw ProxyError.auth("SOCKS5 帳密被拒") }
        case 0xFF:
            throw ProxyError.auth("SOCKS5 伺服器拒絕所有認證方法")
        default:
            throw ProxyError.unsupported("SOCKS5 認證方法 \(methodReply[1])")
        }

        // CONNECT 請求
        var req = Data([0x05, 0x01, 0x00])
        req.append(SocksAddress.encode(target))
        try await s.write(req)

        // 回應：VER REP RSV ATYP BND.ADDR BND.PORT
        let head = try await s.readExactly(3)
        guard head[0] == 0x05, head[1] == 0x00 else {
            throw ProxyError.protocolError("SOCKS5 CONNECT 被拒（REP=\(head[1])）")
        }
        _ = try await SocksAddress.read(from: s)   // 消耗綁定位址
        return s
    }
}
