import Foundation
import ShadowCore

// 原生核心煙霧測試：在指定埠起一個 SOCKS5 / HTTP 混合代理。
// 用法：shadow-demo [port] [--socks HOST:PORT]
//   預設出站 Direct；給 --socks 則出站走上游 SOCKS5（用來測 SocksOutbound 鏈接）。
//   curl -x socks5h://127.0.0.1:1080 https://api.ipify.org

let args = CommandLine.arguments
let port = UInt16(args.dropFirst().first(where: { UInt16($0) != nil }) ?? "") ?? 1080

func log(_ s: String) { FileHandle.standardError.write(Data((s + "\n").utf8)) }

let outbound: Outbound
if let i = args.firstIndex(of: "--socks"), i + 1 < args.count {
    let parts = args[i + 1].split(separator: ":")
    if parts.count == 2, let upPort = UInt16(parts[1]) {
        outbound = SocksOutbound(name: "upstream", host: String(parts[0]), port: upPort)
        log("出站 = SOCKS5 上游 \(args[i + 1])")
    } else {
        log("--socks 參數格式錯誤"); exit(1)
    }
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
