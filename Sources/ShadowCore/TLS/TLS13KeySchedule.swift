import Foundation
import CryptoKit

/// TLS 1.3 金鑰排程（RFC 8446 §7.1）與雜湊抽象。
///
/// 這是原生 TLS 1.3 客戶端（NativeTLS13Client，取代不可自訂 ClientHello 的 Apple NWProtocolTLS）
/// 的正確性核心；一切握手金鑰、traffic 金鑰、Finished 驗證都由此推導。
/// 以 RFC 8448 §3 的官方測試向量做逐 byte 已知答案驗證（見 TLS13KeyScheduleTests）。
///
/// 關鍵：HKDF-Expand-Label 用 `HKDF.expand`（純 expand，把 secret 當 PRK），
/// **不可**用 `HKDF.deriveKey`（那是 extract+expand 合一，會多跑一次 extract）。

/// 依密碼套件選 SHA-256（AES-128-GCM / ChaCha20-Poly1305）或 SHA-384（AES-256-GCM）。
public enum TLS13Hash: Sendable {
    case sha256
    case sha384

    /// 雜湊輸出長度（也是各 secret 的長度）。
    public var length: Int { self == .sha256 ? 32 : 48 }

    /// 完整雜湊一段資料。
    public func hash(_ data: Data) -> Data {
        switch self {
        case .sha256: return Data(SHA256.hash(data: data))
        case .sha384: return Data(SHA384.hash(data: data))
        }
    }

    /// HMAC（Finished verify_data 用）。
    public func hmac(key: Data, message: Data) -> Data {
        let k = SymmetricKey(data: key)
        switch self {
        case .sha256: return Data(HMAC<SHA256>.authenticationCode(for: message, using: k))
        case .sha384: return Data(HMAC<SHA384>.authenticationCode(for: message, using: k))
        }
    }

    /// HKDF-Extract(salt, IKM) -> PRK。
    public func hkdfExtract(salt: Data, ikm: Data) -> Data {
        let k = SymmetricKey(data: ikm)
        switch self {
        case .sha256: return Data(HKDF<SHA256>.extract(inputKeyMaterial: k, salt: salt))
        case .sha384: return Data(HKDF<SHA384>.extract(inputKeyMaterial: k, salt: salt))
        }
    }

    /// HKDF-Expand(PRK, info, L) -> OKM（純 expand，PRK 直接用，不重跑 extract）。
    public func hkdfExpand(prk: Data, info: Data, length: Int) -> Data {
        let key = SymmetricKey(data: prk)
        switch self {
        case .sha256:
            return HKDF<SHA256>.expand(pseudoRandomKey: key, info: info, outputByteCount: length)
                .withUnsafeBytes { Data($0) }
        case .sha384:
            return HKDF<SHA384>.expand(pseudoRandomKey: key, info: info, outputByteCount: length)
                .withUnsafeBytes { Data($0) }
        }
    }
}

public enum TLS13KeySchedule {

    /// HKDF-Expand-Label(Secret, Label, Context, Length)（RFC 8446 §7.1）。
    /// HkdfLabel = uint16(Length) ‖ uint8(len) ‖ "tls13 "+Label ‖ uint8(len) ‖ Context。
    public static func expandLabel(_ hash: TLS13Hash, secret: Data, label: String,
                                   context: Data, length: Int) -> Data {
        let fullLabel = Array(("tls13 " + label).utf8)
        precondition(fullLabel.count <= 255 && context.count <= 255 && length <= 0xFFFF)
        var info = Data()
        info.append(UInt8(length >> 8))
        info.append(UInt8(length & 0xff))
        info.append(UInt8(fullLabel.count))
        info.append(contentsOf: fullLabel)
        info.append(UInt8(context.count))
        info.append(context)
        return hash.hkdfExpand(prk: secret, info: info, length: length)
    }

    /// Derive-Secret(Secret, Label, Messages) = Expand-Label(Secret, Label, Hash(Messages), HashLen)。
    /// 呼叫端傳入「已算好的 transcript hash」作為 context（避免重複雜湊）。
    public static func deriveSecret(_ hash: TLS13Hash, secret: Data, label: String,
                                    transcriptHash: Data) -> Data {
        expandLabel(hash, secret: secret, label: label, context: transcriptHash, length: hash.length)
    }

    /// HKDF-Extract。zeros(HashLen) 用於 PSK=0 的 early secret 與 master secret 的 IKM。
    public static func extract(_ hash: TLS13Hash, salt: Data, ikm: Data) -> Data {
        hash.hkdfExtract(salt: salt, ikm: ikm)
    }

    public static func zeros(_ hash: TLS13Hash) -> Data { Data(repeating: 0, count: hash.length) }

    /// 由 traffic secret 推導 AEAD 金鑰與 static IV（RFC 8446 §7.3）。
    /// keyLen：AES-128-GCM=16、AES-256-GCM=32、ChaCha20-Poly1305=32。IV 恆 12。
    public static func trafficKeyIV(_ hash: TLS13Hash, secret: Data, keyLength: Int) -> (key: Data, iv: Data) {
        let key = expandLabel(hash, secret: secret, label: "key", context: Data(), length: keyLength)
        let iv = expandLabel(hash, secret: secret, label: "iv", context: Data(), length: 12)
        return (key, iv)
    }

    /// 交握後金鑰輪替（RFC 8446 §7.2）：next = HKDF-Expand-Label(secret, "traffic upd", "", HashLen)。
    public static func nextTrafficSecret(_ hash: TLS13Hash, secret: Data) -> Data {
        expandLabel(hash, secret: secret, label: "traffic upd", context: Data(), length: hash.length)
    }

    /// finished_key = Expand-Label(traffic_secret, "finished", "", HashLen)。
    public static func finishedKey(_ hash: TLS13Hash, secret: Data) -> Data {
        expandLabel(hash, secret: secret, label: "finished", context: Data(), length: hash.length)
    }

    /// verify_data = HMAC(finished_key, Transcript-Hash(到 Finished 之前))。
    public static func verifyData(_ hash: TLS13Hash, finishedKey: Data, transcriptHash: Data) -> Data {
        hash.hmac(key: finishedKey, message: transcriptHash)
    }

    /// 每筆 record 的 AEAD nonce = static_iv XOR (big-endian seq，右對齊補到 12 bytes)（RFC 8446 §5.3）。
    public static func perRecordNonce(staticIV: Data, sequence: UInt64) -> Data {
        precondition(staticIV.count == 12)
        var nonce = [UInt8](staticIV)
        // seq 佔最後 8 bytes（big-endian），與前 4 bytes 的 0 一起 XOR。
        for i in 0..<8 {
            let shift = UInt64(8 * (7 - i))
            nonce[4 + i] ^= UInt8((sequence >> shift) & 0xff)
        }
        return Data(nonce)
    }
}

/// 增量式 transcript hash（RFC 8446）：從 ClientHello 起，依序餵入每則握手訊息的
/// 「握手訊息位元組」（type ‖ uint24(len) ‖ body），**不含 record header、不含 inner content-type**。
public struct TLS13Transcript: Sendable {
    private let kind: TLS13Hash
    private var buffer = Data()   // CryptoKit 無公開「複製中間狀態」的 API，故保留已餵位元組重算

    public init(_ kind: TLS13Hash) { self.kind = kind }

    /// 餵入一則完整握手訊息位元組。
    public mutating func update(_ handshakeMessage: Data) { buffer.append(handshakeMessage) }

    /// 目前為止的 transcript hash（Hash(所有已餵訊息)）。
    public func current() -> Data { kind.hash(buffer) }
}
