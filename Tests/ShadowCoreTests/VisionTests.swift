import XCTest
@testable import ShadowCore

/// XTLS Vision 離線測試。真機另需 Xray REALITY+Vision 伺服器。
final class VisionTests: XCTestCase {

    /// 記憶體 ByteStream：write 累積、read 回傳預載內容（一次全給）。
    final class MemStream: ByteStream, @unchecked Sendable {
        var toRead = Data()
        var written = Data()
        func read() async throws -> Data { let d = toRead; toRead = Data(); return d }
        func write(_ data: Data) async throws { written.append(data) }
        func close() {}
    }

    func testVisionAddonBytes() {
        let uuid = Data((0..<16).map { UInt8($0) })
        let req = VlessStream.buildRequest(uuid: uuid, target: Target(host: "1.2.3.4", port: 443), vision: true)
        let b = [UInt8](req)
        // version(1)+uuid(16) 之後應為 addonLen=0x12, 0x0A, 0x10, "xtls-rprx-vision"
        XCTAssertEqual(b[17], 0x12)
        XCTAssertEqual(b[18], 0x0A)
        XCTAssertEqual(b[19], 0x10)
        XCTAssertEqual(Data(b[20..<36]), Data("xtls-rprx-vision".utf8))
        // 非 vision 時 addonLen=0
        let plain = VlessStream.buildRequest(uuid: uuid, target: Target(host: "1.2.3.4", port: 443), vision: false)
        XCTAssertEqual([UInt8](plain)[17], 0x00)
    }

    func testPaddingUnpaddingRoundTrip() async throws {
        let uuid = Data((0..<16).map { UInt8($0 &+ 3) })
        let wUnder = MemStream()
        let writer = VisionConn(under: wUnder, uuid: uuid)
        // 非 TLS 載荷 → 走一般 Continue padding；多次寫入
        try await writer.write(Data("hello ".utf8))
        try await writer.write(Data("vision ".utf8))
        try await writer.write(Data("world".utf8))
        XCTAssertGreaterThan(wUnder.written.count, 0)
        // 首幀應以 UUID 開頭
        XCTAssertEqual(Data([UInt8](wUnder.written).prefix(16)), uuid)

        // 讀端：把 writer 送出的框架餵進去，應還原原始位元組
        let rUnder = MemStream(); rUnder.toRead = wUnder.written
        let reader = VisionConn(under: rUnder, uuid: uuid)
        var got = Data()
        while got.count < Data("hello vision world".utf8).count {
            let chunk = try await reader.read()
            if chunk.isEmpty { break }
            got.append(chunk)
        }
        XCTAssertEqual(got, Data("hello vision world".utf8))
    }

    func testInitialFrameHeaderHidingRoundTrip() async throws {
        // 首幀 = 標頭藏匿用的純 padding frame（帶 UUID）；其後為資料幀。reader 須能吃掉 nil-frame 再還原資料。
        let uuid = Data((0..<16).map { UInt8($0 &+ 9) })
        let wUnder = MemStream()
        let writer = VisionConn(under: wUnder, uuid: uuid)
        let initial = writer.makeInitialFrame()          // 消耗 UUID（模擬 VlessStream.sendHeader 合併寫出）
        XCTAssertEqual(Data([UInt8](initial).prefix(16)), uuid, "首幀應帶 UUID 前綴")
        try await writer.write(Data("payload-after-header".utf8))

        let rUnder = MemStream(); rUnder.toRead = initial + wUnder.written
        let reader = VisionConn(under: rUnder, uuid: uuid)
        var got = Data()
        while got.count < Data("payload-after-header".utf8).count {
            let chunk = try await reader.read()
            if chunk.isEmpty { break }
            got.append(chunk)
        }
        XCTAssertEqual(got, Data("payload-after-header".utf8))
    }

    func testFilterDetectsTLS13ServerHello() {
        let state = VisionState(uuid: Data(repeating: 0, count: 16))
        var sh = Data([0x16, 0x03, 0x03, 0x00, 0x4a, 0x02])   // record hdr + ServerHello, len 0x4a → remainingSH 79
        while sh.count < 43 { sh.append(0) }
        sh.append(0x00)                                        // sessionIdLen = 0 @ [43]
        sh.append(contentsOf: [0x13, 0x01])                    // cipher 0x1301 @ [44,45]
        sh.append(contentsOf: [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04])  // TLS 1.3 supported_versions
        while sh.count < 79 { sh.append(0) }

        Vision.filterTls(sh, state)
        XCTAssertTrue(state.isTLS)
        XCTAssertTrue(state.isTLS12orAbove)
        XCTAssertTrue(state.enableXtls, "偵測到 TLS 1.3（cipher 0x1301 非 CCM_8）應啟用 xtls")
        XCTAssertEqual(state.numberOfPacketToFilter, 0)
    }

    func testIsCompleteRecord() {
        // 完整 app-data record：17 03 03 00 03 <3 bytes>
        XCTAssertTrue(Vision.isCompleteRecord(Data([0x17, 0x03, 0x03, 0x00, 0x03, 0xAA, 0xBB, 0xCC])))
        // 不完整（少 1 byte）
        XCTAssertFalse(Vision.isCompleteRecord(Data([0x17, 0x03, 0x03, 0x00, 0x03, 0xAA, 0xBB])))
        // 非 app-data 開頭
        XCTAssertFalse(Vision.isCompleteRecord(Data([0x16, 0x03, 0x03, 0x00, 0x01, 0xAA])))
    }
}
