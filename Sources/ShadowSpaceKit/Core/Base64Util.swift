import Foundation

/// 寬鬆的 base64 解碼：同時接受標準與 URL-safe 字元集、自動補齊 padding。
/// 訂閱內容與分享連結的 base64 經常不帶 padding 或混用字元集。
enum Base64Util {
    static func decode(_ input: String) -> Data? {
        var s = input.trimmingCharacters(in: .whitespacesAndNewlines)
        s = s.replacingOccurrences(of: "-", with: "+")
             .replacingOccurrences(of: "_", with: "/")
             .replacingOccurrences(of: "\n", with: "")
             .replacingOccurrences(of: "\r", with: "")
        guard !s.isEmpty else { return nil }
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
        guard s.unicodeScalars.allSatisfy({ allowed.contains($0) }) else { return nil }
        let remainder = s.count % 4
        if remainder > 0 {
            s += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: s)
    }

    static func decodeString(_ input: String) -> String? {
        guard let data = decode(input) else { return nil }
        return String(data: data, encoding: .utf8)
    }
}
