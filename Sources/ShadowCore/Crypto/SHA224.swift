import Foundation
import CommonCrypto   // Apple 內建；CryptoKit 沒有 SHA-224，Trojan 需要

/// Trojan 用：SHA-224(password) 的小寫十六進位（56 個 ASCII 位元組）。
public enum SHA224 {
    public static func hexLower(_ string: String) -> Data {
        let input = Array(string.utf8)
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH)) // 28
        _ = input.withUnsafeBytes { CC_SHA224($0.baseAddress, CC_LONG(input.count), &digest) }
        let hex = digest.map { String(format: "%02x", $0) }.joined()
        return Data(hex.utf8)
    }
}
