import Foundation

/// TLS 二進位序列化小工具。所有多位元組欄位皆為 big-endian（network order）。
struct ByteWriter {
    var data = Data()
    mutating func u8(_ v: Int) { data.append(UInt8(v & 0xff)) }
    mutating func u16(_ v: Int) { data.append(UInt8((v >> 8) & 0xff)); data.append(UInt8(v & 0xff)) }
    mutating func u24(_ v: Int) { data.append(UInt8((v >> 16) & 0xff)); data.append(UInt8((v >> 8) & 0xff)); data.append(UInt8(v & 0xff)) }
    mutating func raw(_ d: Data) { data.append(d) }
    mutating func raw(_ b: [UInt8]) { data.append(contentsOf: b) }

    /// 前綴 1/2/3-byte 長度的向量。
    mutating func u8Vec(_ body: Data) { u8(body.count); raw(body) }
    mutating func u16Vec(_ body: Data) { u16(body.count); raw(body) }
    mutating func u24Vec(_ body: Data) { u24(body.count); raw(body) }
}

/// 以 `[UInt8]` 為底的解析器（避開 Data 切片非 0 起始索引的陷阱）。
struct ByteReader {
    let bytes: [UInt8]
    private(set) var pos = 0

    init(_ data: Data) { bytes = [UInt8](data) }
    init(_ b: [UInt8]) { bytes = b }

    var remaining: Int { bytes.count - pos }
    var isAtEnd: Bool { pos >= bytes.count }

    enum ReadError: Error { case underflow }

    mutating func u8() throws -> Int {
        guard remaining >= 1 else { throw ReadError.underflow }
        defer { pos += 1 }
        return Int(bytes[pos])
    }
    mutating func u16() throws -> Int {
        guard remaining >= 2 else { throw ReadError.underflow }
        defer { pos += 2 }
        return Int(bytes[pos]) << 8 | Int(bytes[pos + 1])
    }
    mutating func u24() throws -> Int {
        guard remaining >= 3 else { throw ReadError.underflow }
        defer { pos += 3 }
        return Int(bytes[pos]) << 16 | Int(bytes[pos + 1]) << 8 | Int(bytes[pos + 2])
    }
    mutating func take(_ n: Int) throws -> [UInt8] {
        guard n >= 0, remaining >= n else { throw ReadError.underflow }
        defer { pos += n }
        return Array(bytes[pos..<pos + n])
    }
    /// 讀 1/2/3-byte 長度前綴的向量內容。
    mutating func u8Vec() throws -> [UInt8] { try take(try u8()) }
    mutating func u16Vec() throws -> [UInt8] { try take(try u16()) }
    mutating func u24Vec() throws -> [UInt8] { try take(try u24()) }
}

/// GREASE（RFC 8701）值皆為 0x?a?a；JA3/JA4 計算時剝除，故不影響指紋穩定度。
enum GREASE {
    static let values: [Int] = (0...15).map { (0x0a + $0 * 0x10) * 0x100 + (0x0a + $0 * 0x10) }
    // 對應：0x0a0a, 0x1a1a, 0x2a2a … 0xfafa
}
