import Foundation
import Network

/// SOCKS5 位址編碼（ATYP + ADDR + PORT），被 SOCKS5 入站、Shadowsocks、Trojan、VMess 共用。
/// ATYP：0x01 IPv4、0x03 網域、0x04 IPv6；PORT 為 2 位元組大端序。
public enum SocksAddress {

    /// 把 Target 編成 SOCKS5 位址位元組（出站協議送目標位址用）。
    public static func encode(_ target: Target) -> Data {
        var out = Data()
        if let v4 = IPv4Address(target.host) {
            out.append(0x01)
            out.append(v4.rawValue)
        } else if let v6 = IPv6Address(target.host) {
            out.append(0x04)
            out.append(v6.rawValue)
        } else {
            let host = Array(target.host.utf8)
            out.append(0x03)
            out.append(UInt8(min(host.count, 255)))
            out.append(contentsOf: host.prefix(255))
        }
        out.append(UInt8(target.port >> 8))
        out.append(UInt8(target.port & 0xff))
        return out
    }

    /// 從串流讀取一個 SOCKS5 位址（ATYP 已知或先讀）。
    public static func read(from stream: NWStream) async throws -> Target {
        let atyp = try await stream.readExactly(1)[0]
        let host: String
        switch atyp {
        case 0x01:
            let raw = try await stream.readExactly(4)
            host = raw.map(String.init).joined(separator: ".")
        case 0x04:
            let raw = try await stream.readExactly(16)
            host = ipv6String(raw)
        case 0x03:
            let len = Int(try await stream.readExactly(1)[0])
            let raw = try await stream.readExactly(len)
            host = String(decoding: raw, as: UTF8.self)
        default:
            throw ProxyError.protocolError("未知的 SOCKS ATYP \(atyp)")
        }
        let portBytes = try await stream.readExactly(2)
        let port = (UInt16(portBytes[0]) << 8) | UInt16(portBytes[1])
        return Target(host: host, port: port)
    }

    private static func ipv6String(_ raw: Data) -> String {
        var parts: [String] = []
        var i = raw.startIndex
        while i < raw.endIndex {
            let hi = UInt16(raw[i]) << 8
            let lo = UInt16(raw[raw.index(after: i)])
            parts.append(String(hi | lo, radix: 16))
            i = raw.index(i, offsetBy: 2)
        }
        return parts.joined(separator: ":")
    }
}

public enum ProxyError: Error, CustomStringConvertible {
    case protocolError(String)
    case unsupported(String)
    case auth(String)

    public var description: String {
        switch self {
        case .protocolError(let m): return "協議錯誤：\(m)"
        case .unsupported(let m): return "不支援：\(m)"
        case .auth(let m): return "認證錯誤：\(m)"
        }
    }
}
