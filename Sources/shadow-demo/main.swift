import Foundation
import ShadowCore

// 原生核心煙霧測試：在指定埠起一個 SOCKS5 / HTTP 混合代理。
// 用法：shadow-demo [port] [--socks HOST:PORT]
//   預設出站 Direct；給 --socks 則出站走上游 SOCKS5（用來測 SocksOutbound 鏈接）。
//   curl -x socks5h://127.0.0.1:1080 https://api.ipify.org

let args = CommandLine.arguments
let port = UInt16(args.dropFirst().first(where: { UInt16($0) != nil }) ?? "") ?? 1080

func log(_ s: String) { FileHandle.standardError.write(Data((s + "\n").utf8)) }

/// 最小 vless:// 解析（測試用）：vless://uuid@host:port?security&type&sni&host&path#name
func parseVlessURI(_ uri: String, fragment: Bool = false) -> Outbound? {
    guard uri.hasPrefix("vless://") else { return nil }
    var rest = String(uri.dropFirst("vless://".count))
    if let h = rest.firstIndex(of: "#") { rest = String(rest[..<h]) }
    var query: [String: String] = [:]
    if let q = rest.firstIndex(of: "?") {
        for pair in rest[rest.index(after: q)...].split(separator: "&") {
            let kv = pair.split(separator: "=", maxSplits: 1)
            if kv.count == 2 { query[String(kv[0])] = String(kv[1]).removingPercentEncoding ?? String(kv[1]) }
        }
        rest = String(rest[..<q])
    }
    guard let at = rest.firstIndex(of: "@") else { return nil }
    let uuid = String(rest[..<at])
    let hostPort = rest[rest.index(after: at)...]
    guard let colon = hostPort.lastIndex(of: ":"),
          let port = UInt16(hostPort[hostPort.index(after: colon)...]) else { return nil }
    let host = String(hostPort[..<colon])
    var t = TransportConfig()
    t.tls = (query["security"] == "tls" || query["security"] == "reality")
    t.sni = query["sni"]
    t.fragment = fragment
    if query["type"] == "ws" {
        t.network = .ws
        t.wsPath = query["path"] ?? "/"
        t.wsHost = query["host"]
    }
    return VlessOutbound(name: "vless", host: host, port: port, uuid: uuid, transport: t)
}

let outbound: Outbound
if let i = args.firstIndex(of: "--socks"), i + 1 < args.count {
    let parts = args[i + 1].split(separator: ":")
    if parts.count == 2, let upPort = UInt16(parts[1]) {
        outbound = SocksOutbound(name: "upstream", host: String(parts[0]), port: upPort)
        log("出站 = SOCKS5 上游 \(args[i + 1])")
    } else {
        log("--socks 參數格式錯誤"); exit(1)
    }
} else if let i = args.firstIndex(of: "--vless"), i + 1 < args.count {
    let frag = args.contains("--fragment")
    guard let o = parseVlessURI(args[i + 1], fragment: frag) else { log("--vless URI 解析失敗"); exit(1) }
    outbound = o
    log("出站 = VLESS（\(args[i + 1].prefix(50))…）\(frag ? " [TLS 分片]" : "")")
} else {
    outbound = DirectOutbound()
}

let engine: NativeEngine
if let i = args.firstIndex(of: "--reject"), i + 1 < args.count {
    let suffix = args[i + 1]
    let router = Router(rules: [RoutingRule(.domainSuffix(suffix), .reject)],
                        proxy: outbound, finalPolicy: .proxy)
    engine = NativeEngine(port: port, router: router)
    log("規則：reject *.\(suffix)，其餘走 \(outbound.name)")
} else {
    engine = NativeEngine(port: port, outbound: outbound)
}
do {
    try engine.start()
    log("shadow-demo 監聽 127.0.0.1:\(port)")
} catch {
    log("啟動失敗：\(error)")
    exit(1)
}

RunLoop.main.run()
