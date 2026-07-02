import Foundation
import Network

/// SOCKS5 入站處理（no-auth + CONNECT + UDP ASSOCIATE）。VER 位元組由 MixedServer 先讀掉。
public enum Socks5Handler {

    public enum Command { case connect, udpAssociate }

    /// 完成方法協商與請求解析，回傳命令與目標位址（尚未回覆客戶端）。
    public static func readRequest(_ client: NWStream) async throws -> (command: Command, target: Target) {
        // 方法協商：NMETHODS + METHODS
        let nmethods = Int(try await client.readExactly(1)[0])
        if nmethods > 0 { _ = try await client.readExactly(nmethods) }
        try await client.write(Data([0x05, 0x00]))   // 選 no-auth

        // 請求：VER, CMD, RSV, ATYP+ADDR+PORT
        let head = try await client.readExactly(3)
        guard head[0] == 0x05 else { throw ProxyError.protocolError("SOCKS5 版本錯誤") }
        let command: Command
        switch head[1] {
        case 0x01: command = .connect
        case 0x03: command = .udpAssociate
        default: throw ProxyError.unsupported("SOCKS5 不支援 CMD \(head[1])")
        }
        let target = try await SocksAddress.read(from: client)
        return (command, target)
    }

    /// 回覆 CONNECT 結果。REP：0x00 成功、0x05 拒絕。
    public static func reply(_ client: NWStream, success: Bool) async throws {
        let rep: UInt8 = success ? 0x00 : 0x05
        // VER REP RSV ATYP(IPv4) BND.ADDR(0.0.0.0) BND.PORT(0)
        try await client.write(Data([0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
    }

    /// 回覆 UDP ASSOCIATE：告知客戶端 UDP relay 的 BND.ADDR:BND.PORT。
    public static func replyUDP(_ client: NWStream, host: String, port: UInt16) async throws {
        var d = Data([0x05, 0x00, 0x00])
        if let v4 = IPv4Address(host) {
            d.append(0x01); d.append(v4.rawValue)
        } else {
            d.append(0x01); d.append(contentsOf: [127, 0, 0, 1])
        }
        d.append(UInt8(port >> 8)); d.append(UInt8(port & 0xff))
        try await client.write(d)
    }
}
