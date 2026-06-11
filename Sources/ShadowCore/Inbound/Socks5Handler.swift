import Foundation

/// SOCKS5 入站處理（no-auth + CONNECT）。VER 位元組由 MixedServer 先讀掉。
public enum Socks5Handler {

    /// 完成方法協商與請求解析，回傳目標位址（尚未回覆客戶端）。
    public static func readRequest(_ client: NWStream) async throws -> Target {
        // 方法協商：NMETHODS + METHODS
        let nmethods = Int(try await client.readExactly(1)[0])
        if nmethods > 0 { _ = try await client.readExactly(nmethods) }
        try await client.write(Data([0x05, 0x00]))   // 選 no-auth

        // 請求：VER, CMD, RSV, ATYP+ADDR+PORT
        let head = try await client.readExactly(3)
        guard head[0] == 0x05 else { throw ProxyError.protocolError("SOCKS5 版本錯誤") }
        guard head[1] == 0x01 else { throw ProxyError.unsupported("SOCKS5 僅支援 CONNECT") }
        return try await SocksAddress.read(from: client)
    }

    /// 回覆客戶端連線結果。REP：0x00 成功、0x05 拒絕。
    public static func reply(_ client: NWStream, success: Bool) async throws {
        let rep: UInt8 = success ? 0x00 : 0x05
        // VER REP RSV ATYP(IPv4) BND.ADDR(0.0.0.0) BND.PORT(0)
        try await client.write(Data([0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
    }
}
