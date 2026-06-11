import Foundation
import Network

/// VLESS 串流：TLS/TCP 之上，首次送出 VLESS 請求標頭，首次讀取時解析回應標頭，之後純轉送。
/// 注意 VLESS 的位址型別與 SOCKS 不同：1=IPv4、2=網域、3=IPv6。
public final class VlessStream: ByteStream, @unchecked Sendable {
    private let under: ByteStream
    private let header: Data
    private var headerSent = false
    private var responseParsed = false
    private var respBuf = Data()

    public init(under: ByteStream, uuid: Data, target: Target) {
        self.under = under
        self.header = Self.buildRequest(uuid: uuid, target: target)
    }

    /// version(0) ‖ uuid(16) ‖ addonLen(0) ‖ cmd(1=tcp) ‖ port(2,BE) ‖ atyp ‖ addr
    public static func buildRequest(uuid: Data, target: Target) -> Data {
        var d = Data()
        d.append(0x00)
        d.append(uuid)
        d.append(0x00)
        d.append(0x01)
        d.append(UInt8(target.port >> 8))
        d.append(UInt8(target.port & 0xff))
        if let v4 = IPv4Address(target.host) {
            d.append(0x01); d.append(v4.rawValue)
        } else if let v6 = IPv6Address(target.host) {
            d.append(0x03); d.append(v6.rawValue)
        } else {
            let host = Array(target.host.utf8)
            d.append(0x02); d.append(UInt8(min(host.count, 255)))
            d.append(contentsOf: host.prefix(255))
        }
        return d
    }

    public static func parseUUID(_ string: String) -> Data? {
        let hex = string.replacingOccurrences(of: "-", with: "")
        guard hex.count == 32 else { return nil }
        var data = Data()
        var idx = hex.startIndex
        while idx < hex.endIndex {
            let next = hex.index(idx, offsetBy: 2)
            guard let byte = UInt8(hex[idx..<next], radix: 16) else { return nil }
            data.append(byte)
            idx = next
        }
        return data
    }

    public func sendHeader() async throws {
        guard !headerSent else { return }
        headerSent = true
        try await under.write(header)
    }

    public func write(_ data: Data) async throws {
        try await sendHeader()
        try await under.write(data)
    }

    public func read() async throws -> Data {
        if !responseParsed {
            // 回應標頭：version(1) ‖ addonLen(1) ‖ addons(addonLen)
            while respBuf.count < 2 {
                let chunk = try await under.read()
                if chunk.isEmpty { return Data() }
                respBuf.append(chunk)
            }
            let addonLen = Int(respBuf[respBuf.index(respBuf.startIndex, offsetBy: 1)])
            let need = 2 + addonLen
            while respBuf.count < need {
                let chunk = try await under.read()
                if chunk.isEmpty { return Data() }
                respBuf.append(chunk)
            }
            responseParsed = true
            let payload = Data(respBuf.dropFirst(need))   // 標頭後剩餘 = 載荷
            respBuf = Data()
            if !payload.isEmpty { return payload }
        }
        return try await under.read()
    }

    public func close() { under.close() }
}

public struct VlessOutbound: Outbound {
    public let name: String
    private let server: Target
    private let uuid: Data
    private let transport: TransportConfig

    public init?(name: String, host: String, port: UInt16, uuid: String,
                 transport: TransportConfig = TransportConfig(tls: true)) {
        guard let uuidData = VlessStream.parseUUID(uuid) else { return nil }
        self.name = name
        self.server = Target(host: host, port: port)
        self.uuid = uuidData
        var t = transport
        if t.tls && t.sni == nil { t.sni = host }
        self.transport = t
    }

    public func connect(to target: Target, queue: DispatchQueue) async throws -> ByteStream {
        let under = try await Transport.dial(host: server.host, port: server.port,
                                             config: transport, queue: queue)
        let stream = VlessStream(under: under, uuid: uuid, target: target)
        try await stream.sendHeader()
        return stream
    }
}
