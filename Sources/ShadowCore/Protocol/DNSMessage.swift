import Foundation

public enum DNSMessage {
    /// 回傳第一個 question 的 QNAME。解析失敗時回 nil，讓呼叫端走保守 fallback。
    public static func firstQuestionName(in data: Data) -> String? {
        guard data.count >= 12 else { return nil }
        let qdCount = UInt16(data[4]) << 8 | UInt16(data[5])
        guard qdCount > 0 else { return nil }

        var offset = 12
        guard let name = readName(in: data, offset: &offset, depth: 0),
              !name.isEmpty else {
            return nil
        }
        return name.lowercased()
    }

    private static func readName(in data: Data, offset: inout Int, depth: Int) -> String? {
        guard depth < 8 else { return nil }
        var labels: [String] = []

        while true {
            guard offset < data.count else { return nil }
            let length = data[offset]

            if length == 0 {
                offset += 1
                return labels.joined(separator: ".")
            }

            if length & 0xC0 == 0xC0 {
                guard offset + 1 < data.count else { return nil }
                let pointer = (Int(length & 0x3F) << 8) | Int(data[offset + 1])
                guard pointer < data.count else { return nil }
                offset += 2
                var pointedOffset = pointer
                guard let suffix = readName(in: data, offset: &pointedOffset, depth: depth + 1) else {
                    return nil
                }
                if !suffix.isEmpty { labels.append(suffix) }
                return labels.joined(separator: ".")
            }

            guard length & 0xC0 == 0,
                  offset + 1 + Int(length) <= data.count else {
                return nil
            }
            let start = offset + 1
            let end = start + Int(length)
            guard let label = String(data: data[start..<end], encoding: .utf8),
                  !label.isEmpty else {
                return nil
            }
            labels.append(label)
            offset = end
        }
    }
}
