import Foundation

/// XTLS Vision（flow="xtls-rprx-vision"）客戶端。線格式以 Xray-core `proxy/proxy.go`
/// （XtlsPadding / XtlsUnpadding / XtlsFilterTls / WriteMultiBuffer / ReadMultiBuffer）為準。
///
/// Vision 疊在 VLESS 載荷之上（VLESS 標頭仍以明文送出）：它檢視「內層應用自己的 TLS 握手」
/// （TLS-in-TLS），對前幾筆做 padding，偵測到內層 TLS 1.3 後切換為裸傳（direct），以打散
/// TLS-in-TLS 的封包長度/時序特徵。
///
/// padding frame：`[UserUUID(16，僅首幀)] [command(1)] [contentLen(2,BE)] [paddingLen(2,BE)] [content] [padding]`
/// command：0=continue、1=end、2=direct。

enum Vision {
    static let commandContinue: UInt8 = 0x00
    static let commandEnd: UInt8 = 0x01
    static let commandDirect: UInt8 = 0x02

    static let debugEnabled = ProcessInfo.processInfo.environment["VISION_DEBUG"] != nil
    static func dbg(_ s: @autoclosure () -> String) {
        if debugEnabled { FileHandle.standardError.write(Data(("[Vision] " + s() + "\n").utf8)) }
    }

    static let bufSize = 8192
    static let tls13SupportedVersions: [UInt8] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]

    /// VLESS 請求標頭的 addon 位元組（flow=xtls-rprx-vision）：protobuf field1(0x0A) ‖ len(0x10) ‖ 16 ASCII。
    static let visionAddon: [UInt8] = [0x0A, 0x10] + Array("xtls-rprx-vision".utf8)  // 18 bytes

    /// XtlsPadding：把一段 content 包成 padding frame。uuid 非 nil 時前置（並清空，只首幀帶）。
    static func padding(content: Data?, command: UInt8, uuid: inout Data?, longPadding: Bool, testseed: [UInt32]) -> Data {
        let contentLen = Int32(content?.count ?? 0)
        var paddingLen: Int32
        if contentLen < Int32(testseed[0]) && longPadding {
            paddingLen = Int32.random(in: 0..<Int32(testseed[1])) + Int32(testseed[2]) - contentLen
        } else {
            paddingLen = Int32.random(in: 0..<Int32(testseed[3]))
        }
        let maxPad = Int32(bufSize) - 21 - contentLen
        if paddingLen > maxPad { paddingLen = maxPad }
        if paddingLen < 0 { paddingLen = 0 }

        var out = Data()
        if let u = uuid { out.append(u); uuid = nil }
        out.append(command)
        out.append(UInt8((contentLen >> 8) & 0xff)); out.append(UInt8(contentLen & 0xff))
        out.append(UInt8((paddingLen >> 8) & 0xff)); out.append(UInt8(paddingLen & 0xff))
        if let c = content { out.append(c) }
        if paddingLen > 0 { out.append(Data(count: Int(paddingLen))) }
        return out
    }

    /// 把大 buffer 切成 ≤ bufSize-21 的塊，讓每塊加上 21-byte 前綴後仍 ≤ bufSize。
    static func reshape(_ data: Data) -> [Data] {
        let maxChunk = bufSize - 21
        guard data.count > maxChunk else { return [data] }
        var chunks: [Data] = []
        var idx = data.startIndex
        while idx < data.endIndex {
            let end = data.index(idx, offsetBy: Swift.min(maxChunk, data.distance(from: idx, to: data.endIndex)))
            chunks.append(Data(data[idx..<end]))
            idx = end
        }
        return chunks
    }

    /// 是否為完整 TLS application_data record 串（起始 17 03 03，長度剛好切齊）。
    static func isCompleteRecord(_ data: Data) -> Bool {
        let b = [UInt8](data)
        var headerLen = 5
        var recordLen = 0
        var i = 0
        while i < b.count {
            if headerLen > 0 {
                let d = b[i]; i += 1
                switch headerLen {
                case 5: if d != 0x17 { return false }
                case 4: if d != 0x03 { return false }
                case 3: if d != 0x03 { return false }
                case 2: recordLen = Int(d) << 8
                case 1: recordLen |= Int(d)
                default: break
                }
                headerLen -= 1
            } else if recordLen > 0 {
                let remaining = b.count - i
                if remaining < recordLen { return false }
                i += recordLen; recordLen = 0; headerLen = 5
            } else {
                return false
            }
        }
        return headerLen == 5 && recordLen == 0
    }

    /// XtlsFilterTls：偵測內層 TLS（ServerHello/ClientHello、TLS 1.3），設定 isTLS/enableXtls。
    static func filterTls(_ data: Data, _ s: VisionState) {
        s.numberOfPacketToFilter -= 1
        let b = [UInt8](data)
        if b.count >= 6 {
            if b[0] == 0x16 && b[1] == 0x03 && b[2] == 0x03 && b[5] == 0x02 {          // ServerHello
                s.remainingServerHello = (Int32(b[3]) << 8 | Int32(b[4])) + 5
                s.isTLS12orAbove = true
                s.isTLS = true
                if b.count >= 79 && s.remainingServerHello >= 79 {
                    let sidLen = Int(b[43])
                    if 43 + sidLen + 3 <= b.count {
                        s.cipher = UInt16(b[43 + sidLen + 1]) << 8 | UInt16(b[43 + sidLen + 2])
                    }
                }
            } else if b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01 {                    // ClientHello
                s.isTLS = true
            }
        }
        if s.remainingServerHello > 0 {
            var end = Int(s.remainingServerHello)
            if end > b.count { end = b.count }
            s.remainingServerHello -= Int32(b.count)
            if contains(Array(b[0..<end]), tls13SupportedVersions) {
                if s.cipher != 0x1305 { s.enableXtls = true }   // 非 TLS_AES_128_CCM_8_SHA256
                s.numberOfPacketToFilter = 0
            } else if s.remainingServerHello <= 0 {
                s.numberOfPacketToFilter = 0
            }
        }
        dbg("filter head=\([UInt8](data.prefix(6)).map { String(format: "%02x", $0) }.joined()) len=\(data.count) isTLS=\(s.isTLS) isTLS12=\(s.isTLS12orAbove) eXtls=\(s.enableXtls) cipher=\(String(s.cipher, radix: 16)) nOP=\(s.numberOfPacketToFilter) remSH=\(s.remainingServerHello)")
    }

    private static func contains(_ haystack: [UInt8], _ needle: [UInt8]) -> Bool {
        guard !needle.isEmpty, haystack.count >= needle.count else { return false }
        for i in 0...(haystack.count - needle.count) {
            var ok = true
            for j in 0..<needle.count where haystack[i + j] != needle[j] { ok = false; break }
            if ok { return true }
        }
        return false
    }
}

/// Vision 連線狀態（客戶端單一連線；filter 欄位跨收發共用，收/送 padding 狀態各自獨立）。
final class VisionState {
    let uuid: Data                       // 16 bytes
    let testseed: [UInt32]

    // 共用（filter）——read（下行）與 write（上行）兩個並發 task 都會存取，需 filterLock 保護
    let filterLock = NSLock()
    var numberOfPacketToFilter = 8
    var isTLS = false
    var isTLS12orAbove = false
    var enableXtls = false
    var cipher: UInt16 = 0
    var remainingServerHello: Int32 = -1

    // writer（uplink）
    var isPadding = true
    var writeOnceUUID: Data?
    var writerDirect = false

    // reader（downlink）
    var remainingCommand: Int32 = -1
    var remainingContent: Int32 = -1
    var remainingPadding: Int32 = -1
    var currentCommand = 0
    var withinPaddingBuffers = true
    var readerDirect = false

    init(uuid: Data, testseed: [UInt32] = [900, 500, 900, 256]) {
        self.uuid = uuid
        self.writeOnceUUID = uuid
        self.testseed = testseed
    }
}

/// 疊在隧道 ByteStream 之上的 Vision 收發：write 端做 padding/filter、read 端做 unpadding/filter，
/// 偵測內層 TLS 1.3 後切裸傳。VLESS 標頭不經此層（由 VlessStream 明文送出/解析）。
public final class VisionConn: ByteStream, @unchecked Sendable {
    private let under: ByteStream
    private let state: VisionState
    private var readBuf = Data()

    init(under: ByteStream, uuid: Data) {
        self.under = under
        self.state = VisionState(uuid: uuid)
    }

    /// 供 VlessStream 把「解析響應標頭後多讀到的載荷位元組」餵進來。
    func feedInitialRead(_ data: Data) { readBuf.append(data) }

    /// 首個「純 padding」frame：含 UUID 前綴、Continue、無內容、長 padding。
    /// 與 VLESS 標頭合併於同一次 under.write，讓標頭不單獨成為可被標記的小型外層記錄。
    func makeInitialFrame() -> Data {
        Vision.padding(content: nil, command: Vision.commandContinue,
                       uuid: &state.writeOnceUUID, longPadding: true, testseed: state.testseed)
    }

    // MARK: write（uplink，padding）

    public func write(_ data: Data) async throws {
        if state.writerDirect {
            Vision.dbg("W direct raw \(data.count)B")
            try await under.write(data); return
        }
        // 共享 filter 狀態在鎖內更新並快照，避免與並發的 read（下行）filter 競態
        let (isTLS, isTLS12, eXtls, nOP): (Bool, Bool, Bool, Int) = state.filterLock.withLock {
            if state.numberOfPacketToFilter > 0 { Vision.filterTls(data, state) }
            return (state.isTLS, state.isTLS12orAbove, state.enableXtls, state.numberOfPacketToFilter)
        }
        Vision.dbg("W in=\(data.count)B head=\([UInt8](data.prefix(3)).map { String(format: "%02x", $0) }.joined()) isTLS=\(isTLS) isTLS12=\(isTLS12) eXtls=\(eXtls) isPadding=\(state.isPadding) complete=\(Vision.isCompleteRecord(data))")
        guard state.isPadding else {
            Vision.dbg("W padding-ended raw \(data.count)B")
            try await under.write(data); return
        }   // padding 已結束 → 裸傳

        let isComplete = Vision.isCompleteRecord(data)
        let chunks = Vision.reshape(data)
        var longPadding = isTLS
        var out = Data()
        var goDirect = false
        var i = 0
        while i < chunks.count {
            let b = chunks[i]
            let isLast = (i == chunks.count - 1)
            if isTLS && b.count >= 6 && b.prefix(3) == Data([0x17, 0x03, 0x03]) && isComplete {
                // 首個內層 application_data record → 結束 padding 並（XTLS 時）切 Direct/splice。
                // Direct（2）讓伺服器對此連線兩個方向都改為 TLS splice：裸傳內層 record、繞過外層 TLS。
                // 伺服器本就會依自身偵測 splice 下行，上行也須配合裸傳，否則上行資料錯位/遺失。
                if eXtls { goDirect = true }
                var command = Vision.commandContinue
                if isLast { command = eXtls ? Vision.commandDirect : Vision.commandEnd }
                out.append(Vision.padding(content: b, command: command, uuid: &state.writeOnceUUID, longPadding: true, testseed: state.testseed))
                state.isPadding = false
                longPadding = false
                i += 1
                continue
            } else if !isTLS12 && nOP <= 1 {
                // 相容較早的接收端：提前一包結束 padding
                state.isPadding = false
                out.append(Vision.padding(content: b, command: Vision.commandEnd, uuid: &state.writeOnceUUID, longPadding: longPadding, testseed: state.testseed))
                i += 1
                break   // 其餘塊裸傳
            }
            var command = Vision.commandContinue
            if isLast && !state.isPadding { command = eXtls ? Vision.commandDirect : Vision.commandEnd }
            out.append(Vision.padding(content: b, command: command, uuid: &state.writeOnceUUID, longPadding: longPadding, testseed: state.testseed))
            i += 1
        }
        while i < chunks.count { out.append(chunks[i]); i += 1 }   // break 後剩餘塊裸傳
        try await under.write(out)   // 含 command-2 區塊，仍走外層 TLS（padding 藏內層握手）
        Vision.dbg("W emitted \(out.count)B goDirect=\(goDirect) isPadding=\(state.isPadding)")
        if goDirect {
            // 切 Direct 後，上行後續 record 裸傳（繞過外層 TLS），與伺服器 splice 對稱
            under.enterWriteSplice()
            state.writerDirect = true
        }
    }

    // MARK: read（downlink，unpadding）

    public func read() async throws -> Data {
        if state.readerDirect {
            if !readBuf.isEmpty { let d = readBuf; readBuf = Data(); Vision.dbg("R direct(buf) \(d.count)B head=\([UInt8](d.prefix(5)).map { String(format: "%02x", $0) }.joined())"); return d }
            let r = try await under.read(); Vision.dbg("R direct \(r.count)B head=\([UInt8](r.prefix(5)).map { String(format: "%02x", $0) }.joined())"); return r
        }
        while true {
            // 初始態：需 ≥21 bytes 且以 UserUUID 開頭才進入 padding 解析
            if state.remainingCommand == -1 && state.remainingContent == -1 && state.remainingPadding == -1 {
                while readBuf.count < 21 {
                    let chunk = try await under.read()
                    if chunk.isEmpty {
                        if readBuf.isEmpty { return Data() }
                        let d = readBuf; readBuf = Data(); state.readerDirect = true; return d
                    }
                    readBuf.append(chunk)
                }
                if readBuf.prefix(16) == state.uuid {
                    readBuf.removeFirst(16)
                    state.remainingCommand = 5
                } else {
                    // 非 Vision 框（不該發生）→ 裸傳
                    let d = readBuf; readBuf = Data(); state.readerDirect = true; return d
                }
            }
            if readBuf.isEmpty {
                let chunk = try await under.read()
                if chunk.isEmpty { return Data() }
                readBuf.append(chunk)
            }

            var out = Data()
            var terminalTail = Data()
            while !readBuf.isEmpty {
                if state.remainingCommand > 0 {
                    let d = readBuf.removeFirst()
                    switch state.remainingCommand {
                    case 5: state.currentCommand = Int(d)
                    case 4: state.remainingContent = Int32(d) << 8
                    case 3: state.remainingContent |= Int32(d)
                    case 2: state.remainingPadding = Int32(d) << 8
                    case 1: state.remainingPadding |= Int32(d)
                    default: break
                    }
                    state.remainingCommand -= 1
                } else if state.remainingContent > 0 {
                    let n = Swift.min(Int(state.remainingContent), readBuf.count)
                    out.append(readBuf.prefix(n)); readBuf.removeFirst(n)
                    state.remainingContent -= Int32(n)
                } else {   // padding
                    let n = Swift.min(Int(state.remainingPadding), readBuf.count)
                    readBuf.removeFirst(n)
                    state.remainingPadding -= Int32(n)
                }
                if state.remainingCommand <= 0 && state.remainingContent <= 0 && state.remainingPadding <= 0 {
                    if state.currentCommand == 0 {
                        state.remainingCommand = 5   // 下一個 block
                    } else {
                        state.remainingCommand = -1; state.remainingContent = -1; state.remainingPadding = -1
                        terminalTail = readBuf; readBuf = Data()
                        break
                    }
                }
            }
            // 更新狀態機。注意：只有「5-byte 標頭已讀完」(remainingCommand<=0) 才可套用終端轉換；
            // 否則標頭跨 TCP 分段被截斷時會誤判 currentCommand 而提前切 direct，污染下行串流。
            if state.remainingCommand > 0 {
                state.withinPaddingBuffers = true
            } else if state.remainingContent > 0 || state.remainingPadding > 0 || state.currentCommand == 0 {
                state.withinPaddingBuffers = true
            } else if state.currentCommand == 1 {
                // End：伺服器僅結束 padding，之後仍走外層 TLS（不 splice）
                state.withinPaddingBuffers = false; state.readerDirect = true
            } else if state.currentCommand == 2 {
                // Direct：伺服器切 TLS splice，之後裸傳內層 record，繞過外層 TLS。
                // 通知底層外層 TLS：此方向後續 read() 改回傳原始 TCP 位元組。
                state.withinPaddingBuffers = false; state.readerDirect = true
                under.enterReadSplice()
            }
            if state.numberOfPacketToFilter > 0 && !out.isEmpty {
                state.filterLock.withLock { Vision.filterTls(out, state) }
            }
            Vision.dbg("R block cmd=\(state.currentCommand) content=\(out.count)B tail=\(terminalTail.count)B direct=\(state.readerDirect) contHead=\([UInt8](out.prefix(5)).map { String(format: "%02x", $0) }.joined()) tailHead=\([UInt8](terminalTail.prefix(5)).map { String(format: "%02x", $0) }.joined())")
            if !terminalTail.isEmpty { out.append(terminalTail) }
            if !out.isEmpty { return out }
            if state.readerDirect { let r = try await under.read(); Vision.dbg("R direct raw \(r.count)B head=\([UInt8](r.prefix(5)).map { String(format: "%02x", $0) }.joined())"); return r }
            // 只吃到 padding、無內容 → 繼續讀
        }
    }

    public func close() { under.close() }
}
