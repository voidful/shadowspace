import Foundation

/// 抓取與解析訂閱連結（base64 節點清單格式）。
enum SubscriptionManager {

    enum SubError: LocalizedError {
        case badURL
        case fetchFailed(String)
        case noNodes

        var errorDescription: String? {
            switch self {
            case .badURL: return "訂閱連結格式不正確"
            case .fetchFailed(let msg): return "訂閱下載失敗：\(msg)"
            case .noNodes: return "訂閱內容解析不到任何節點（支援 base64 分享連結與 sing-box JSON；Clash YAML 還在開發中）。可到「設定 → 訂閱」調整 User-Agent 再試。"
            }
        }
    }

    struct FetchResult {
        var nodes: [ProxyNode]
        var userInfo: String?
        var suggestedName: String?
    }

    static func fetch(urlString: String, userAgent: String = "sing-box/1.13.13") async throws -> FetchResult {
        guard let url = URL(string: urlString.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = url.scheme, ["http", "https"].contains(scheme.lowercased()) else {
            throw SubError.badURL
        }
        var req = URLRequest(url: url)
        // 機場常依 User-Agent 決定回傳格式（base64 分享連結 / sing-box JSON / Clash YAML）
        req.setValue(userAgent.isEmpty ? "sing-box/1.13.13" : userAgent, forHTTPHeaderField: "User-Agent")
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

        // sing-box JSON config（送 sing-box UA 時機場常回此格式）優先，否則 base64 / 分享連結
        let nodes: [ProxyNode]
        if SingBoxNodeParser.looksLikeConfig(text) {
            let parsed = SingBoxNodeParser.parse(data)
            nodes = parsed.isEmpty ? URIParser.parseMultiple(text) : parsed
        } else {
            nodes = URIParser.parseMultiple(text)
        }
        guard !nodes.isEmpty else { throw SubError.noNodes }

        let userInfo = http.value(forHTTPHeaderField: "subscription-userinfo")

        // 訂閱名稱：content-disposition 檔名 > 主機名
        var name: String? = url.host
        if let disposition = http.value(forHTTPHeaderField: "content-disposition") {
            // 例: attachment; filename*=UTF-8''%E6%A9%9F%E5%A0%B4 或 filename="xxx"
            if let range = disposition.range(of: "filename*=UTF-8''") {
                let raw = String(disposition[range.upperBound...])
                    .split(separator: ";").first.map(String.init) ?? ""
                name = raw.removingPercentEncoding ?? name
            } else if let range = disposition.range(of: "filename=") {
                let raw = String(disposition[range.upperBound...])
                    .split(separator: ";").first.map(String.init) ?? ""
                name = raw.trimmingCharacters(in: CharacterSet(charactersIn: "\" "))
            }
        }
        return FetchResult(nodes: nodes, userInfo: userInfo, suggestedName: name)
    }
}
