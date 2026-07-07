import Foundation

/// sing-box Clash API 客戶端：模式熱切換、節點選擇、流量串流、連線管理、延遲測試。
struct ClashAPIClient {
    var port: Int
    var secret: String

    private var base: String { "http://127.0.0.1:\(port)" }

    private func request(_ path: String, method: String = "GET", body: [String: Any]? = nil) -> URLRequest {
        var req = URLRequest(url: URL(string: base + path)!)
        req.httpMethod = method
        req.setValue("Bearer \(secret)", forHTTPHeaderField: "Authorization")
        if let body {
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
            req.httpBody = try? JSONSerialization.data(withJSONObject: body)
        }
        req.timeoutInterval = 5
        return req
    }

    private static func encodeTag(_ tag: String) -> String {
        tag.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? tag
    }

    /// 等待 API 起來（引擎啟動完成的訊號）
    func waitReady(timeout: TimeInterval = 8) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let (_, resp) = try? await URLSession.shared.data(for: request("/version")),
               (resp as? HTTPURLResponse)?.statusCode == 200 {
                return true
            }
            try? await Task.sleep(nanoseconds: 200_000_000)
        }
        return false
    }

    /// 切換 規則/全域/直連 模式
    func setMode(_ clashMode: String) async {
        _ = try? await URLSession.shared.data(
            for: request("/configs", method: "PATCH", body: ["mode": clashMode]))
    }

    /// 切換 PROXY 群組的節點
    func selectNode(group: String, tag: String) async throws {
        let (_, resp) = try await URLSession.shared.data(
            for: request("/proxies/\(Self.encodeTag(group))", method: "PUT", body: ["name": tag]))
        guard let http = resp as? HTTPURLResponse, http.statusCode == 204 || http.statusCode == 200 else {
            throw URLError(.badServerResponse)
        }
    }

    /// 透過引擎做真實 URL 延遲測試（毫秒），失敗回傳 nil
    func urlDelay(tag: String, timeoutMs: Int = 5000) async -> Int? {
        let path = "/proxies/\(Self.encodeTag(tag))/delay"
            + "?timeout=\(timeoutMs)&url=http%3A%2F%2Fwww.gstatic.com%2Fgenerate_204"
        var req = request(path)
        req.timeoutInterval = Double(timeoutMs) / 1000 + 3
        guard let (data, resp) = try? await URLSession.shared.data(for: req),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let delay = obj["delay"] as? Int else {
            return nil
        }
        return delay
    }

    /// 流量串流：每秒一行 {"up": bytes/s, "down": bytes/s}
    func trafficLines() async throws -> AsyncLineSequence<URLSession.AsyncBytes> {
        var req = request("/traffic")
        req.timeoutInterval = 60 * 60 * 24
        let (bytes, _) = try await URLSession.shared.bytes(for: req)
        return bytes.lines
    }

    static func parseTrafficLine(_ line: String) -> (up: Int, down: Int)? {
        guard let data = line.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        return ((obj["up"] as? Int) ?? 0, (obj["down"] as? Int) ?? 0)
    }

    // MARK: - 連線管理

    struct ConnectionsSnapshot {
        var items: [ConnectionInfo]
        var uploadTotal: Int
        var downloadTotal: Int
    }

    // 連線頁每秒重繪，formatter 抽成 static 避免每次重配置。ISO8601DateFormatter 執行緒安全（Apple 文件保證）。
    private static let isoFractional: ISO8601DateFormatter = {
        let fmt = ISO8601DateFormatter()
        fmt.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return fmt
    }()
    private static let isoPlain = ISO8601DateFormatter()

    /// 目前所有活躍連線。欄位型別在不同引擎間不一致，用寬鬆解析。
    func connections() async -> ConnectionsSnapshot? {
        guard let (data, resp) = try? await URLSession.shared.data(for: request("/connections")),
              (resp as? HTTPURLResponse)?.statusCode == 200,
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }

        var items: [ConnectionInfo] = []
        for conn in (obj["connections"] as? [[String: Any]]) ?? [] {
            guard let id = conn["id"] as? String else { continue }
            let md = (conn["metadata"] as? [String: Any]) ?? [:]
            func str(_ key: String) -> String {
                if let s = md[key] as? String { return s }
                if let v = md[key] { return "\(v)" }
                return ""
            }
            let host = str("host").isEmpty ? str("destinationIP") : str("host")
            let portStr = str("destinationPort")
            let startStr = (conn["start"] as? String) ?? ""
            var rule = (conn["rule"] as? String) ?? ""
            if let payload = conn["rulePayload"] as? String, !payload.isEmpty {
                rule += "(\(payload))"
            }
            items.append(ConnectionInfo(
                id: id,
                target: portStr.isEmpty ? host : "\(host):\(portStr)",
                network: str("network"),
                rule: rule,
                chain: (conn["chains"] as? [String])?.first ?? "",
                upload: (conn["upload"] as? Int) ?? 0,
                download: (conn["download"] as? Int) ?? 0,
                start: Self.isoFractional.date(from: startStr) ?? Self.isoPlain.date(from: startStr)
            ))
        }
        // 新連線排前面
        items.sort { ($0.start ?? .distantPast) > ($1.start ?? .distantPast) }
        return ConnectionsSnapshot(
            items: items,
            uploadTotal: (obj["uploadTotal"] as? Int) ?? 0,
            downloadTotal: (obj["downloadTotal"] as? Int) ?? 0
        )
    }

    func closeConnection(_ id: String) async {
        _ = try? await URLSession.shared.data(
            for: request("/connections/\(Self.encodeTag(id))", method: "DELETE"))
    }

    func closeAllConnections() async {
        _ = try? await URLSession.shared.data(for: request("/connections", method: "DELETE"))
    }
}
