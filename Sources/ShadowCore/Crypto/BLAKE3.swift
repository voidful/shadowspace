import Foundation

/// 純 Swift BLAKE3（hash / keyed_hash / derive_key 三模式），依官方 reference_impl。
/// 供 Shadowsocks-2022（2022-blake3-*）的 session subkey 衍生使用（CryptoKit 無 BLAKE3）。
/// 以官方 test_vectors.json 逐 case 驗證（見 BLAKE3Tests）。
public enum BLAKE3 {
    public static let outLen = 32

    fileprivate static let blockLen = 64
    fileprivate static let chunkLen = 1024
    fileprivate static let CHUNK_START: UInt32 = 1
    fileprivate static let CHUNK_END: UInt32 = 2
    fileprivate static let PARENT: UInt32 = 4
    fileprivate static let ROOT: UInt32 = 8
    fileprivate static let KEYED_HASH: UInt32 = 16
    fileprivate static let DERIVE_KEY_CONTEXT: UInt32 = 32
    fileprivate static let DERIVE_KEY_MATERIAL: UInt32 = 64

    fileprivate static let IV: [UInt32] = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]
    fileprivate static let MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]

    // MARK: 公開 API

    public static func hash(_ data: Data, length: Int = 32) -> Data {
        let h = Hasher(key: IV, flags: 0); h.update([UInt8](data)); return h.finalize(length)
    }

    /// keyed_hash：key 恰 32 bytes。
    public static func keyedHash(key: Data, _ data: Data, length: Int = 32) -> Data {
        precondition(key.count == 32)
        let h = Hasher(key: keyWords(key), flags: KEYED_HASH); h.update([UInt8](data)); return h.finalize(length)
    }

    /// derive_key(context, keyMaterial)：先以 DERIVE_KEY_CONTEXT 雜湊 context 得 32-byte context key，
    /// 再以其為 key 對 keyMaterial 做 DERIVE_KEY_MATERIAL keyed hash。
    public static func deriveKey(context: String, keyMaterial: Data, length: Int = 32) -> Data {
        let ctxHasher = Hasher(key: IV, flags: DERIVE_KEY_CONTEXT)
        ctxHasher.update([UInt8](context.utf8))
        let contextKey = ctxHasher.finalize(32)
        let h = Hasher(key: keyWords(contextKey), flags: DERIVE_KEY_MATERIAL)
        h.update([UInt8](keyMaterial))
        return h.finalize(length)
    }

    // MARK: 核心

    @inline(__always) fileprivate static func rotr(_ x: UInt32, _ n: UInt32) -> UInt32 { (x >> n) | (x << (32 - n)) }

    @inline(__always) fileprivate static func g(_ s: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int, _ mx: UInt32, _ my: UInt32) {
        s[a] = s[a] &+ s[b] &+ mx
        s[d] = rotr(s[d] ^ s[a], 16)
        s[c] = s[c] &+ s[d]
        s[b] = rotr(s[b] ^ s[c], 12)
        s[a] = s[a] &+ s[b] &+ my
        s[d] = rotr(s[d] ^ s[a], 8)
        s[c] = s[c] &+ s[d]
        s[b] = rotr(s[b] ^ s[c], 7)
    }

    fileprivate static func roundFn(_ s: inout [UInt32], _ m: [UInt32]) {
        g(&s, 0, 4, 8, 12, m[0], m[1]); g(&s, 1, 5, 9, 13, m[2], m[3])
        g(&s, 2, 6, 10, 14, m[4], m[5]); g(&s, 3, 7, 11, 15, m[6], m[7])
        g(&s, 0, 5, 10, 15, m[8], m[9]); g(&s, 1, 6, 11, 12, m[10], m[11])
        g(&s, 2, 7, 8, 13, m[12], m[13]); g(&s, 3, 4, 9, 14, m[14], m[15])
    }

    fileprivate static func permute(_ m: [UInt32]) -> [UInt32] {
        var out = [UInt32](repeating: 0, count: 16)
        for i in 0..<16 { out[i] = m[MSG_PERMUTATION[i]] }
        return out
    }

    /// 壓縮函式，回傳 16 words（前 8 = 輸出 chaining value）。
    fileprivate static func compress(_ cv: [UInt32], _ blockWords: [UInt32], _ counter: UInt64, _ blockLen: UInt32, _ flags: UInt32) -> [UInt32] {
        var state: [UInt32] = [
            cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
            IV[0], IV[1], IV[2], IV[3],
            UInt32(truncatingIfNeeded: counter),
            UInt32(truncatingIfNeeded: counter >> 32),
            blockLen, flags]
        var block = blockWords
        roundFn(&state, block)
        for _ in 0..<6 { block = permute(block); roundFn(&state, block) }
        for i in 0..<8 { state[i] ^= state[i + 8] }
        for i in 0..<8 { state[i + 8] ^= cv[i] }
        return state
    }

    fileprivate static func wordsFromBlock(_ block: [UInt8]) -> [UInt32] {
        var w = [UInt32](repeating: 0, count: 16)
        for i in 0..<16 {
            let o = i * 4
            w[i] = UInt32(block[o]) | UInt32(block[o + 1]) << 8 | UInt32(block[o + 2]) << 16 | UInt32(block[o + 3]) << 24
        }
        return w
    }

    fileprivate static func keyWords(_ key: Data) -> [UInt32] {
        let a = [UInt8](key)
        var w = [UInt32](repeating: 0, count: 8)
        for i in 0..<8 { let o = i * 4; w[i] = UInt32(a[o]) | UInt32(a[o + 1]) << 8 | UInt32(a[o + 2]) << 16 | UInt32(a[o + 3]) << 24 }
        return w
    }

    fileprivate struct Output {
        let inputCV: [UInt32]
        let blockWords: [UInt32]
        let counter: UInt64
        let blockLen: UInt32
        let flags: UInt32
        func chainingValue() -> [UInt32] { Array(compress(inputCV, blockWords, counter, blockLen, flags)[0..<8]) }
        func rootBytes(_ length: Int) -> Data {
            var out = Data()
            var blockCounter: UInt64 = 0
            while out.count < length {
                let words = compress(inputCV, blockWords, blockCounter, blockLen, flags | ROOT)
                for w in words {
                    out.append(UInt8(w & 0xff)); out.append(UInt8((w >> 8) & 0xff))
                    out.append(UInt8((w >> 16) & 0xff)); out.append(UInt8((w >> 24) & 0xff))
                }
                blockCounter += 1
            }
            return out.prefix(length)
        }
    }

    fileprivate struct ChunkState {
        var cv: [UInt32]
        let chunkCounter: UInt64
        var block = [UInt8](repeating: 0, count: 64)
        var blockLen = 0
        var blocksCompressed = 0
        let flags: UInt32
        init(key: [UInt32], counter: UInt64, flags: UInt32) { cv = key; chunkCounter = counter; self.flags = flags }
        var len: Int { 64 * blocksCompressed + blockLen }
        var startFlag: UInt32 { blocksCompressed == 0 ? CHUNK_START : 0 }
        mutating func update(_ input: [UInt8]) {
            var i = 0
            while i < input.count {
                if blockLen == 64 {
                    cv = Array(compress(cv, wordsFromBlock(block), chunkCounter, 64, flags | startFlag)[0..<8])
                    blocksCompressed += 1
                    block = [UInt8](repeating: 0, count: 64)
                    blockLen = 0
                }
                let take = Swift.min(64 - blockLen, input.count - i)
                for k in 0..<take { block[blockLen + k] = input[i + k] }
                blockLen += take
                i += take
            }
        }
        func output() -> Output {
            Output(inputCV: cv, blockWords: wordsFromBlock(block), counter: chunkCounter,
                   blockLen: UInt32(blockLen), flags: flags | startFlag | CHUNK_END)
        }
    }

    fileprivate final class Hasher {
        var chunkState: ChunkState
        let key: [UInt32]
        var cvStack: [[UInt32]] = []
        let flags: UInt32
        init(key: [UInt32], flags: UInt32) { self.key = key; self.flags = flags; chunkState = ChunkState(key: key, counter: 0, flags: flags) }

        private func parentOutput(_ left: [UInt32], _ right: [UInt32]) -> Output {
            var bw = [UInt32](repeating: 0, count: 16)
            for i in 0..<8 { bw[i] = left[i]; bw[i + 8] = right[i] }
            return Output(inputCV: key, blockWords: bw, counter: 0, blockLen: 64, flags: flags | PARENT)
        }
        private func parentCV(_ l: [UInt32], _ r: [UInt32]) -> [UInt32] { parentOutput(l, r).chainingValue() }

        private func addChunkCV(_ cvIn: [UInt32], _ totalIn: UInt64) {
            var cv = cvIn; var total = totalIn
            while total & 1 == 0 { cv = parentCV(cvStack.removeLast(), cv); total >>= 1 }
            cvStack.append(cv)
        }

        func update(_ input: [UInt8]) {
            var i = 0
            while i < input.count {
                if chunkState.len == chunkLen {
                    let cv = chunkState.output().chainingValue()
                    let total = chunkState.chunkCounter + 1
                    addChunkCV(cv, total)
                    chunkState = ChunkState(key: key, counter: total, flags: flags)
                }
                let want = chunkLen - chunkState.len
                let take = Swift.min(want, input.count - i)
                chunkState.update(Array(input[i..<i + take]))
                i += take
            }
        }

        func finalize(_ length: Int) -> Data {
            var output = chunkState.output()
            var i = cvStack.count
            while i > 0 { i -= 1; output = parentOutput(cvStack[i], output.chainingValue()) }
            return output.rootBytes(length)
        }
    }
}
