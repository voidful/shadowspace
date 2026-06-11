import Foundation

/// HTTP 代理入站：CONNECT（HTTPS 隧道）為主，明文 HTTP 轉發為輔。
public enum HttpProxyHandler {

    public struct Parsed {
        public let target: Target
        public let isConnect: Bool
        /// 連到目標後要先送出的位元組（CONNECT 通常為空；明文 HTTP 為改寫後的請求）。
        public let initialToRemote: Data
    }

    private static let headerEnd = Data("\r\n\r\n".utf8)

    public static func readRequest(_ client: NWStream, prefix: Data) async throws -> Parsed {
        var buf = prefix
        while range(of: headerEnd, in: buf) == nil {
            if buf.count > 65536 { throw ProxyError.protocolError("HTTP 標頭過大") }
            let more = try await client.read()
            if more.isEmpty { throw ProxyError.protocolError("連線中斷於 HTTP 標頭") }
            buf.append(more)
        }
        let endRange = range(of: headerEnd, in: buf)!
        let headerData = buf[buf.startIndex..<endRange.lowerBound]
        let leftover = Data(buf[endRange.upperBound...])    // 標頭之後的位元組

        let headerText = String(decoding: headerData, as: UTF8.self)
        var lines = headerText.components(separatedBy: "\r\n")
        let requestLine = lines.first ?? ""
        let parts = requestLine.split(separator: " ", maxSplits: 2).map(String.init)
        guard parts.count >= 2 else { throw ProxyError.protocolError("HTTP 請求行錯誤") }
        let method = parts[0].uppercased()
        let rawTarget = parts[1]

        if method == "CONNECT" {
            let target = try parseHostPort(rawTarget, defaultPort: 443)
            return Parsed(target: target, isConnect: true, initialToRemote: leftover)
        }

        // 明文 HTTP：絕對形式 URI → 取 host、改寫成 origin-form
        guard let url = URL(string: rawTarget), let host = url.host else {
            throw ProxyError.protocolError("HTTP 代理需要絕對 URI")
        }
        let port = UInt16(url.port ?? 80)
        var path = url.path.isEmpty ? "/" : url.path
        if let q = url.query { path += "?\(q)" }
        let version = parts.count >= 3 ? parts[2] : "HTTP/1.1"
        lines[0] = "\(method) \(path) \(version)"
        // 移除 proxy 專用標頭
        lines.removeAll { $0.lowercased().hasPrefix("proxy-connection:") }
        var rebuilt = Data(lines.joined(separator: "\r\n").utf8)
        rebuilt.append(headerEnd)
        rebuilt.append(leftover)
        return Parsed(target: Target(host: host, port: port), isConnect: false, initialToRemote: rebuilt)
    }

    public static func replyConnectSuccess(_ client: NWStream) async throws {
        try await client.write(Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8))
    }

    public static func replyError(_ client: NWStream) async throws {
        try await client.write(Data("HTTP/1.1 502 Bad Gateway\r\n\r\n".utf8))
    }

    // host:port，支援 [IPv6]:port
    private static func parseHostPort(_ s: String, defaultPort: UInt16) throws -> Target {
        if s.hasPrefix("["), let close = s.firstIndex(of: "]") {
            let host = String(s[s.index(after: s.startIndex)..<close])
            let rest = s[s.index(after: close)...]
            let port = rest.hasPrefix(":") ? UInt16(rest.dropFirst()) ?? defaultPort : defaultPort
            return Target(host: host, port: port)
        }
        if let colon = s.lastIndex(of: ":") {
            let host = String(s[..<colon])
            let port = UInt16(s[s.index(after: colon)...]) ?? defaultPort
            return Target(host: host, port: port)
        }
        return Target(host: s, port: defaultPort)
    }

    private static func range(of needle: Data, in haystack: Data) -> Range<Data.Index>? {
        haystack.range(of: needle)
    }
}
