import Foundation

/// 雙工位元組串流抽象。NWStream（明文 TCP/TLS）與加密協議串流（如 Shadowsocks）都實作它，
/// 中繼層與出站只認這個介面，加密對它們透明。
/// read() 回傳空 Data 代表 EOF。
public protocol ByteStream: AnyObject, Sendable {
    func read() async throws -> Data
    func write(_ data: Data) async throws
    func close()

    /// XTLS Vision splice：偵測到內層 TLS、伺服器切 Direct(裸傳)後，通知底層外層 TLS
    /// 之後的 read() 直接回傳原始 TCP 位元組（先吐外層 TLS 已緩衝、未消化的 inbuf，再讀裸 TCP），
    /// 不再以外層 TLS 解密。預設 no-op（多數串流不需要）。宣告於協定以取得動態分派。
    func enterReadSplice()

    /// XTLS Vision splice（上行）：切 Direct 後，之後的 write() 直接把位元組寫到原始 TCP，
    /// 不再以外層 TLS 加密（與伺服器裸傳對稱）。預設 no-op。
    func enterWriteSplice()
}

public extension ByteStream {
    func enterReadSplice() {}
    func enterWriteSplice() {}
}
