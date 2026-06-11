import Foundation

/// 雙工位元組串流抽象。NWStream（明文 TCP/TLS）與加密協議串流（如 Shadowsocks）都實作它，
/// 中繼層與出站只認這個介面，加密對它們透明。
/// read() 回傳空 Data 代表 EOF。
public protocol ByteStream: AnyObject, Sendable {
    func read() async throws -> Data
    func write(_ data: Data) async throws
    func close()
}
