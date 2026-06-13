import Foundation
import Network

/// TLS ClientHello 分片（抗封鎖）。
///
/// 以 NWProtocolFramer 插在 TLS 與 TCP 之間：攔截第一筆輸出（TLS ClientHello），
/// 切成多個小段分別送出 → 各自成為獨立 TCP 區段，DPI 無法在單一封包中比對到完整 SNI。
/// 入站與後續輸出皆原樣透傳，不影響 TLS 正常運作。
public final class TLSFragmentFramer: NWProtocolFramerImplementation {

    public static let definition = NWProtocolFramer.Definition(implementation: TLSFragmentFramer.self)
    public static var label: String { "TLSFragment" }

    /// 每段大小（位元組）。把 ClientHello 切成這麼大的小段。
    nonisolated(unsafe) public static var fragmentSize = 48

    private var firstHandled = false

    public init(framer: NWProtocolFramer.Instance) {}

    public func start(framer: NWProtocolFramer.Instance) -> NWProtocolFramer.StartResult { .ready }
    public func wakeup(framer: NWProtocolFramer.Instance) {}
    public func stop(framer: NWProtocolFramer.Instance) -> Bool { true }
    public func cleanup(framer: NWProtocolFramer.Instance) {}

    /// 入站：把 TCP 進來的位元組原樣往上層（TLS）交付，不分片。
    /// 先 peek 目前可得長度（closure 回傳 0 = 不在此消耗），再用 deliverInputNoCopy 交付＋消耗。
    public func handleInput(framer: NWProtocolFramer.Instance) -> Int {
        while true {
            var available = 0
            let parsed = framer.parseInput(minimumIncompleteLength: 1, maximumLength: 65535) {
                buffer, _ in
                available = buffer?.count ?? 0
                return 0
            }
            if !parsed || available == 0 { return 0 }
            let message = NWProtocolFramer.Message(definition: TLSFragmentFramer.definition)
            if !framer.deliverInputNoCopy(length: available, message: message, isComplete: false) {
                return 0
            }
        }
    }

    /// 出站：第一筆夠大的輸出（ClientHello）切片送出，其餘原樣透傳。
    public func handleOutput(framer: NWProtocolFramer.Instance,
                             message: NWProtocolFramer.Message,
                             messageLength: Int, isComplete: Bool) {
        guard messageLength > 0 else { return }

        if firstHandled || messageLength <= Self.fragmentSize {
            try? framer.writeOutputNoCopy(length: messageLength)
            return
        }
        firstHandled = true

        // 讀出整段，切成小段分別送出
        var data = Data(count: messageLength)
        let ok: Bool = data.withUnsafeMutableBytes { dst in
            framer.parseOutput(minimumIncompleteLength: messageLength,
                               maximumLength: messageLength) { buffer, _ in
                guard let buffer, buffer.count >= messageLength,
                      let src = buffer.baseAddress, let dstBase = dst.baseAddress else { return 0 }
                dstBase.copyMemory(from: src, byteCount: messageLength)
                return messageLength
            }
        }
        guard ok else { try? framer.writeOutputNoCopy(length: messageLength); return }

        var offset = 0
        while offset < data.count {
            let n = Swift.min(Self.fragmentSize, data.count - offset)
            framer.writeOutput(data: data.subdata(in: offset..<offset + n))
            offset += n
        }
    }
}
