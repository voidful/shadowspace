import Foundation
import CryptoKit

/// REALITY 客戶端設定與密碼運算。線格式以 Xray-core `transport/internet/reality/reality.go`（UClient /
/// VerifyPeerCertificate）為準：
/// - authKey = HKDF-SHA256(ikm = X25519(client 短暫私鑰, 伺服器 pbk), salt = ClientHello.Random[0:20], info="REALITY", 32)
/// - session_id(32) = AES-256-GCM(key=authKey, nonce=Random[20:32], plaintext=16-byte 認證資料,
///                                AAD = 整個 ClientHello 但 session_id 欄位為 32 個 0)
/// - 伺服器驗證 = HMAC-SHA512(authKey, leaf 憑證 Ed25519 公鑰) == leaf.signatureValue
public struct RealityClientConfig: Sendable {
    public let publicKey: Data   // 伺服器 REALITY X25519 公鑰（32 bytes）
    public let shortID: Data     // 0..8 bytes

    public init(publicKey: Data, shortID: Data) {
        self.publicKey = publicKey
        self.shortID = shortID
    }

    /// 由節點字串建立：pbk = base64url(32 bytes)（相容 hex）、sid = hex（0..8 bytes，可空）。
    public init?(publicKeyString pbk: String, shortIDHex sid: String) {
        guard let key = RealityClientConfig.decodeKey(pbk), key.count == 32 else { return nil }
        let sidData = RealityClientConfig.hexDecode(sid) ?? Data()
        guard sidData.count <= 8 else { return nil }
        self.publicKey = key
        self.shortID = sidData
    }

    static func decodeKey(_ s: String) -> Data? {
        if let d = base64URLDecode(s), d.count == 32 { return d }
        if let d = hexDecode(s), d.count == 32 { return d }
        return nil
    }

    static func base64URLDecode(_ s: String) -> Data? {
        var t = s.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        while t.count % 4 != 0 { t += "=" }
        return Data(base64Encoded: t)
    }

    static func hexDecode(_ s: String) -> Data? {
        let chars = Array(s)
        guard chars.count % 2 == 0 else { return nil }
        var d = Data()
        var i = 0
        while i < chars.count {
            guard let b = UInt8(String(chars[i]) + String(chars[i + 1]), radix: 16) else { return nil }
            d.append(b); i += 2
        }
        return d
    }
}

enum RealityCrypto {
    // Xray core 版本（session_id 前 3 byte，伺服器僅作資訊性記錄，不據以拒絕）。
    static let versionXYZ: [UInt8] = [26, 6, 27]

    /// authKey = HKDF-SHA256(ikm=X25519 祕密, salt=Random[0:20], info="REALITY", 32)。
    static func authKey(x25519Shared: Data, helloRandom: Data) -> Data {
        let salt = Data(helloRandom.prefix(20))
        let key = HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: x25519Shared),
                                         salt: salt, info: Data("REALITY".utf8), outputByteCount: 32)
        return key.withUnsafeBytes { Data($0) }
    }

    /// 16-byte session_id 明文：[Vx,Vy,Vz,0] ‖ unixtime(4,BE) ‖ shortId(補 0 到 8)。
    static func sessionIDPlaintext(shortID: Data, now: UInt32) -> Data {
        var d = Data(versionXYZ)
        d.append(0)   // reserved
        d.append(UInt8((now >> 24) & 0xff)); d.append(UInt8((now >> 16) & 0xff))
        d.append(UInt8((now >> 8) & 0xff)); d.append(UInt8(now & 0xff))
        d.append(shortID.prefix(8))
        while d.count < 16 { d.append(0) }
        return d
    }

    /// 封 session_id：AES-256-GCM，回傳 32 bytes（ciphertext16 ‖ tag16）。
    static func sealSessionID(authKey: Data, helloRandom: Data, plaintext16: Data, aad: Data) throws -> Data {
        let nonce = Data(helloRandom.suffix(12))   // Random[20:32]
        let box = try AES.GCM.seal(plaintext16, using: SymmetricKey(data: authKey),
                                   nonce: AES.GCM.Nonce(data: nonce), authenticating: aad)
        return box.ciphertext + box.tag
    }

    /// 伺服器驗證：leaf 憑證公鑰須為 Ed25519，且 HMAC-SHA512(authKey, pub) == 憑證 signatureValue。
    static func verifyServer(authKey: Data, leafCertDER: Data) -> Bool {
        guard let pub = X509Minimal.ed25519PublicKey(certDER: leafCertDER),
              let sig = X509Minimal.signatureValue(certDER: leafCertDER) else { return false }
        let mac = Data(HMAC<SHA512>.authenticationCode(for: pub, using: SymmetricKey(data: authKey)))
        return mac.count == sig.count && mac == sig
    }
}

/// 極簡 X.509 DER 解析：只取 REALITY 驗證需要的兩樣——leaf 的 Ed25519 公鑰與外層 signatureValue。
enum X509Minimal {

    /// 解一個 DER TLV，回傳 (tag, 值起點, 值長度, 下一個 TLV 起點)。
    static func readTLV(_ b: [UInt8], _ off: Int) -> (tag: Int, valStart: Int, valLen: Int, next: Int)? {
        guard off >= 0, off + 1 < b.count else { return nil }
        let tag = Int(b[off])
        var i = off + 1
        var len = Int(b[i]); i += 1
        if len & 0x80 != 0 {
            let n = len & 0x7f
            guard n >= 1, n <= 4, i + n <= b.count else { return nil }
            len = 0
            for _ in 0..<n { len = (len << 8) | Int(b[i]); i += 1 }
        }
        guard len >= 0, i + len <= b.count else { return nil }
        return (tag, i, len, i + len)
    }

    /// Ed25519 SubjectPublicKeyInfo 位元組模式：SEQ{OID 1.3.101.112} ‖ BITSTRING(33,0) ‖ 32-byte 公鑰。
    static func ed25519PublicKey(certDER: Data) -> Data? {
        let b = [UInt8](certDER)
        let pat: [UInt8] = [0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]
        guard let idx = firstIndex(of: pat, in: b) else { return nil }
        let start = idx + pat.count
        guard start + 32 <= b.count else { return nil }
        return Data(b[start..<start + 32])
    }

    /// 外層 Certificate SEQUENCE 的第 3 個子元素（BIT STRING）= signatureValue（去掉前導未用位元 byte）。
    static func signatureValue(certDER: Data) -> Data? {
        let b = [UInt8](certDER)
        guard let outer = readTLV(b, 0), outer.tag == 0x30 else { return nil }
        var off = outer.valStart
        let end = outer.valStart + outer.valLen
        var children: [(tag: Int, valStart: Int, valLen: Int)] = []
        while off < end {
            guard let t = readTLV(b, off) else { break }
            children.append((t.tag, t.valStart, t.valLen))
            off = t.next
        }
        guard children.count >= 3 else { return nil }
        let sig = children[2]
        guard sig.tag == 0x03, sig.valLen >= 1 else { return nil }   // BIT STRING
        return Data(b[(sig.valStart + 1)..<(sig.valStart + sig.valLen)])   // 去前導 unused-bits byte
    }

    private static func firstIndex(of pattern: [UInt8], in b: [UInt8]) -> Int? {
        guard !pattern.isEmpty, b.count >= pattern.count else { return nil }
        for i in 0...(b.count - pattern.count) {
            var ok = true
            for j in 0..<pattern.count where b[i + j] != pattern[j] { ok = false; break }
            if ok { return i }
        }
        return nil
    }
}
