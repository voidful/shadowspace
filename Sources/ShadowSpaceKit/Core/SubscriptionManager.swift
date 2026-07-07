import Foundation

/// 抓取與解析訂閱連結（base64 節點清單格式）。
enum SubscriptionManager {

    /// 預設拉取 User-Agent。機場常依 UA 決定回傳格式，送 sing-box 可拿到最完整的設定。
    static let defaultUserAgent = "sing-box/1.13.13"

    enum SubError: LocalizedError {
        case badURL
        case fetchFailed(String)
        case noNodes

        var errorDescription: String? {
            switch self {
            case .badURL: return "訂閱連結格式不正確"
            case .fetchFailed(let msg): return "訂閱下載失敗：\(msg)"
            case .noNodes: return "訂閱內容解析不到任何節點（支援 base64 分享連結、sing-box JSON、Clash YAML）。可到「設定 → 訂閱」調整 User-Agent 再試。"
            }
        }
    }

    struct FetchResult {
        var nodes: [ProxyNode]
        var userInfo: String?
        var suggestedName: String?
    }

    static func fetch(urlString: String, userAgent: String = defaultUserAgent) async throws -> FetchResult {
        guard let url = URL(string: urlString.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = url.scheme, ["http", "https"].contains(scheme.lowercased()) else {
            throw SubError.badURL
        }
        var req = URLRequest(url: url)
        // 機場常依 User-Agent 決定回傳格式（base64 分享連結 / sing-box JSON / Clash YAML）
        req.setValue(userAgent.isEmpty ? defaultUserAgent : userAgent, forHTTPHeaderField: "User-Agent")
        req.timeoutInterval = 20

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await URLSession.shared.data(for: req)
        } catch {
            throw SubError.fetchFailed(error.localizedDescription)
        }
        guard let http = response as? HTTPURLResponse else {
            throw SubError.fetchFailed("伺服器無回應")
        }
        guard http.statusCode == 200 else {
            throw SubError.fetchFailed("HTTP \(http.statusCode)")
        }
        guard let text = String(data: data, encoding: .utf8) else {
            throw SubError.fetchFailed("回應內容無法解碼")
        }

        let nodes = parseContent(text, data: data)
        guard !nodes.isEmpty else { throw SubError.noNodes }

        let userInfo = http.value(forHTTPHeaderField: "subscription-userinfo")

        // 訂閱名稱：content-disposition 檔名 > 主機名
        let name = http.value(forHTTPHeaderField: "content-disposition")
            .flatMap(filename(fromContentDisposition:)) ?? url.host
        return FetchResult(nodes: nodes, userInfo: userInfo, suggestedName: name)
    }

    /// 從 content-disposition 標頭取檔名：filename*=UTF-8''（RFC 5987 百分比編碼）優先，其次 filename=。
    /// 純函式，可離線測。取不到或為空回 nil（讓呼叫端落回主機名）。
    static func filename(fromContentDisposition disposition: String) -> String? {
        func firstToken(after marker: String) -> String? {
            guard let range = disposition.range(of: marker) else { return nil }
            return String(disposition[range.upperBound...]).split(separator: ";").first.map(String.init)
        }
        if let raw = firstToken(after: "filename*=UTF-8''") {
            // 解碼失敗（含非法 % 序列）→ nil，讓呼叫端落回主機名（與舊行為一致，不回傳未解碼的原字串）
            guard let decoded = raw.removingPercentEncoding, !decoded.isEmpty else { return nil }
            return decoded
        }
        if let raw = firstToken(after: "filename=") {
            let trimmed = raw.trimmingCharacters(in: CharacterSet(charactersIn: "\" "))
            return trimmed.isEmpty ? nil : trimmed
        }
        return nil
    }

    /// 依內容判型解析節點：sing-box JSON > Clash YAML > base64 / 分享連結。
    /// 純函式（不碰網路），可離線測判型優先序。
    static func parseContent(_ text: String, data: Data) -> [ProxyNode] {
        if SingBoxNodeParser.looksLikeConfig(text) {
            let parsed = SingBoxNodeParser.parse(data)
            return parsed.isEmpty ? URIParser.parseMultiple(text) : parsed
        } else if ClashYAMLParser.looksLikeConfig(text) {
            let parsed = ClashYAMLParser.parse(text)
            return parsed.isEmpty ? URIParser.parseMultiple(text) : parsed
        } else {
            return URIParser.parseMultiple(text)
        }
    }
}
