import Foundation
import Network
import ShadowCore

// 原生核心煙霧測試：在指定埠起一個 SOCKS5 / HTTP 混合代理。
// 用法：shadow-demo [port] [--socks HOST:PORT]
//   預設出站 Direct；給 --socks 則出站走上游 SOCKS5（用來測 SocksOutbound 鏈接）。
//   curl -x socks5h://127.0.0.1:1080 https://api.ipify.org

let args = CommandLine.arguments
let port = UInt16(args.dropFirst().first(where: { UInt16($0) != nil }) ?? "") ?? 1080

func log(_ s: String) { FileHandle.standardError.write(Data((s + "\n").utf8)) }

// 原生 UDP 子系統端到端測試：shadow-demo --udptest
// 起原生引擎（Direct 出站）→ 自做 SOCKS5 UDP ASSOCIATE → 經 relay 送 DNS 查詢到 8.8.8.8:53 → 驗回應。
if args.contains("--udptest") {
    let q = DispatchQueue(label: "udptest")
    let engine = NativeEngine(port: 11080, outbound: DirectOutbound())
    do { try engine.start() } catch { log("引擎啟動失敗：\(error)"); exit(1) }
    let sem = DispatchSemaphore(value: 0)
    Task {
        func recvUDP(_ c: NWConnection) async -> Data? {
            await withCheckedContinuation { (k: CheckedContinuation<Data?, Never>) in
                c.receiveMessage { d, _, _, e in k.resume(returning: e == nil ? d : nil) }
            }
        }
        do {
            // 1) SOCKS5 控制連線 + UDP ASSOCIATE
            let ctl = NWStream(host: "127.0.0.1", port: 11080, queue: q); try await ctl.start()
            try await ctl.write(Data([0x05, 0x01, 0x00]))
            _ = try await ctl.readExactly(2)                                   // [05 00]
            try await ctl.write(Data([0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))  // UDP ASSOCIATE 0.0.0.0:0
            let rep = try await ctl.readExactly(10)                            // 05 00 00 01 BND(4) PORT(2)
            let relayPort = UInt16(rep[8]) << 8 | UInt16(rep[9])
            log("UDP relay 埠 = \(relayPort)")

            // 2) DNS 查詢 example.com A
            var dns = Data([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
            dns.append(0x07); dns.append(contentsOf: Array("example".utf8))
            dns.append(0x03); dns.append(contentsOf: Array("com".utf8)); dns.append(0x00)
            dns.append(contentsOf: [0x00, 0x01, 0x00, 0x01])
            // SOCKS UDP 標頭：RSV RSV FRAG + 位址(8.8.8.8:53) + DNS
            var pkt = Data([0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35]); pkt.append(dns)

            let udp = NWConnection(to: .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: relayPort)!), using: .udp)
            udp.start(queue: q)
            try await withCheckedThrowingContinuation { (k: CheckedContinuation<Void, Error>) in
                udp.send(content: pkt, completion: .contentProcessed { e in e == nil ? k.resume() : k.resume(throwing: e!) })
            }
            guard let resp = await recvUDP(udp), resp.count > 10 else { log("❌ 無 UDP 回應"); exit(1) }
            let r = [UInt8](resp)
            // 剝 SOCKS UDP 標頭（RSV2+FRAG1+ATYP1+IPv4 4+port 2 = 10）→ DNS 回應
            let dnsResp = Array(r[10...])
            let anCount = Int(dnsResp[6]) << 8 | Int(dnsResp[7])
            log("✅ 收到 DNS 回應（ID=\(String(format: "%02x%02x", dnsResp[0], dnsResp[1]))，answers=\(anCount)）→ 原生 UDP relay 端到端運作")
            udp.cancel(); ctl.close(); sem.signal()
        } catch { log("❌ UDP 測試失敗：\(error)"); exit(1) }
    }
    sem.wait()
    exit(0)
}

// 原生 TLS 1.3 客戶端自我測試：shadow-demo --tls13 HOST[:PORT]
// 對真實伺服器完成手刻 TLS 1.3 握手，送 HTTP/1.1 GET / 並印回應首行。
if let i = args.firstIndex(of: "--tls13"), i + 1 < args.count {
    let hostArg = args[i + 1]
    let parts = hostArg.split(separator: ":")
    let host = String(parts[0])
    let p = parts.count > 1 ? (UInt16(parts[1]) ?? 443) : 443
    let queue = DispatchQueue(label: "tls13-demo")
    let sem = DispatchSemaphore(value: 0)
    Task {
        do {
            let preset: FingerprintPreset = ProcessInfo.processInfo.environment["TLS_X25519"] != nil ? .chromeX25519 : .chrome
            let c = try await NativeTLS13Client.dial(
                host: host, port: p, sni: host, alpn: ["http/1.1"],
                preset: preset, queue: queue)
            log("✅ TLS 1.3 握手成功 \(host):\(p)")
            let req = "GET / HTTP/1.1\r\nHost: \(host)\r\nConnection: close\r\nUser-Agent: shadow-demo\r\n\r\n"
            try await c.write(Data(req.utf8))
            var got = Data()
            while got.count < 4096 {
                let chunk = try await c.read()
                if chunk.isEmpty { break }
                got.append(chunk)
            }
            let head = String(decoding: got.prefix(180), as: UTF8.self)
            log("回應前 180 bytes:\n\(head)")
            c.close()
            sem.signal()
        } catch {
            log("❌ TLS 1.3 失敗：\(error)")
            exit(1)
        }
    }
    sem.wait()
    exit(0)
}

/// 最小 vless:// 解析（測試用）：vless://uuid@host:port?security&type&sni&host&path#name
func parseVlessURI(_ uri: String, fragment: Bool = false, nativeTLS: Bool = false) -> Outbound? {
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
    t.nativeTLS = nativeTLS
    t.fingerprint = query["fp"] ?? "chrome"
    if query["security"] == "reality", let pbk = query["pbk"] {
        // REALITY 走自建 TLS 1.3；注意 M2 僅支援 flow=""（無 XTLS Vision）
        t.reality = RealityClientConfig(publicKeyString: pbk, shortIDHex: query["sid"] ?? "")
        if t.reality == nil { log("⚠︎ REALITY pbk/sid 解析失敗") }
    }
    if query["type"] == "ws" {
        t.network = .ws
        t.wsPath = query["path"] ?? "/"
        t.wsHost = query["host"]
    }
    return VlessOutbound(name: "vless", host: host, port: port, uuid: uuid, transport: t, flow: query["flow"])
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
    let ntls = args.contains("--native-tls")
    guard let o = parseVlessURI(args[i + 1], fragment: frag, nativeTLS: ntls) else { log("--vless URI 解析失敗"); exit(1) }
    outbound = o
    log("出站 = VLESS（\(args[i + 1].prefix(50))…）\(frag ? " [TLS 分片]" : "")\(ntls ? " [原生 TLS 指紋]" : "")")
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
