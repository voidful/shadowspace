import Foundation

/// 透過 GitHub Releases 檢查新版本（Developer ID DMG 分發用）。
/// 不靜默安裝；找到新版就通知使用者前往下載。App Store 版由商店自動更新，不走這裡。
enum UpdateChecker {
    static let repo = "voidful/shadowspace"

    struct Release {
        let tag: String        // 例 "v0.2.1"
        let version: String    // 例 "0.2.1"
        let htmlURL: String
        let notes: String
    }

    /// 語意化版本比較："0.2.10" > "0.2.2" > "0.2.1"。
    static func isNewer(_ remote: String, than current: String) -> Bool {
        func parts(_ s: String) -> [Int] {
            s.split(separator: ".").map { Int($0.prefix(while: \.isNumber)) ?? 0 }
        }
        let r = parts(remote), c = parts(current)
        for i in 0..<max(r.count, c.count) {
            let a = i < r.count ? r[i] : 0
            let b = i < c.count ? c[i] : 0
            if a != b { return a > b }
        }
        return false
    }

    static func latest() async -> Release? {
        guard let url = URL(string: "https://api.github.com/repos/\(repo)/releases/latest") else { return nil }
        var req = URLRequest(url: url)
        req.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        req.timeoutInterval = 10
        guard let (data, resp) = try? await URLSession.shared.data(for: req),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let tag = obj["tag_name"] as? String else {
            return nil
        }
        let version = tag.hasPrefix("v") ? String(tag.dropFirst()) : tag
        let html = (obj["html_url"] as? String) ?? "https://github.com/\(repo)/releases"
        let notes = (obj["body"] as? String) ?? ""
        return Release(tag: tag, version: version, htmlURL: html, notes: notes)
    }
}

/// 可供 UI 顯示的更新資訊。
struct UpdateInfo: Equatable {
    let version: String
    let url: String
    let notes: String
}
