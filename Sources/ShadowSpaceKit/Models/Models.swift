import Foundation

// MARK: - 協議類型

enum NodeProtocol: String, Codable, CaseIterable {
    case shadowsocks
    case vmess
    case vless
    case trojan
    case hysteria2
    case tuic
    case anytls
    case socks
    case wireguard

    var displayName: String {
        switch self {
        case .shadowsocks: return "SS"
        case .vmess: return "VMess"
        case .vless: return "VLESS"
        case .trojan: return "Trojan"
        case .hysteria2: return "Hysteria2"
        case .tuic: return "TUIC"
        case .anytls: return "AnyTLS"
        case .socks: return "SOCKS"
        case .wireguard: return "WireGuard"
        }
    }
}

// MARK: - 節點

struct ProxyNode: Codable, Identifiable, Hashable {
    var id = UUID()
    var name: String
    var proto: NodeProtocol
    var server: String
    var port: Int

    // 認證
    var method: String?          // ss 加密方式
    var password: String?        // ss / trojan / hysteria2 / tuic
    var uuid: String?            // vmess / vless / tuic
    var alterId: Int?            // vmess
    var security: String?        // vmess 加密 (scy)
    var flow: String?            // vless (xtls-rprx-vision)
    var username: String?        // socks

    // TLS
    var tls: Bool = false
    var sni: String?
    var insecure: Bool = false
    var alpn: [String]?
    var fingerprint: String?     // uTLS 指紋
    var realityPublicKey: String?
    var realityShortID: String?

    // 傳輸層
    var network: String?         // ws / grpc / http
    var wsPath: String?
    var wsHost: String?
    var grpcServiceName: String?

    // Hysteria2 混淆
    var obfs: String?
    var obfsPassword: String?

    // TUIC
    var congestionControl: String?

    // WireGuard
    var wgPrivateKey: String?
    var wgPeerPublicKey: String?
    var wgPresharedKey: String?
    var wgLocalAddress: [String]?
    var wgMTU: Int?

    // 節點鏈：先經此中轉節點，再連到本節點伺服器（sing-box detour）
    var dialerNodeID: UUID?

    // 來源訂閱（手動新增為 nil）
    var subscriptionID: UUID?
}

// MARK: - 訂閱

struct Subscription: Codable, Identifiable, Hashable {
    var id = UUID()
    var name: String
    var url: String
    var lastUpdated: Date?
    /// 機場回傳的 subscription-userinfo 原始字串
    var rawUserInfo: String?

    /// 格式化的流量資訊，例如「已用 12.3 GB / 100 GB · 07/01 到期」
    var trafficSummary: String? {
        guard let raw = rawUserInfo else { return nil }
        var fields: [String: Int64] = [:]
        for part in raw.split(separator: ";") {
            let kv = part.split(separator: "=", maxSplits: 1)
            guard kv.count == 2 else { continue }
            let key = kv[0].trimmingCharacters(in: .whitespaces).lowercased()
            let value = Int64(kv[1].trimmingCharacters(in: .whitespaces)) ?? 0
            fields[key] = value
        }
        guard !fields.isEmpty else { return nil }
        let used = (fields["upload"] ?? 0) + (fields["download"] ?? 0)
        var pieces: [String] = []
        if let total = fields["total"], total > 0 {
            pieces.append("已用 \(used.byteString) / \(total.byteString)")
        } else if used > 0 {
            pieces.append("已用 \(used.byteString)")
        }
        if let expire = fields["expire"], expire > 0 {
            let date = Date(timeIntervalSince1970: TimeInterval(expire))
            let fmt = DateFormatter()
            fmt.dateFormat = "yyyy/MM/dd"
            pieces.append("\(fmt.string(from: date)) 到期")
        }
        return pieces.isEmpty ? nil : pieces.joined(separator: " · ")
    }
}

// MARK: - 代理模式

enum ProxyMode: String, Codable, CaseIterable {
    case rule
    case global
    case direct

    var displayName: String {
        switch self {
        case .rule: return String(localized: "規則")
        case .global: return String(localized: "全域")
        case .direct: return String(localized: "直連")
        }
    }

    /// 對應 sing-box clash_mode 的名稱
    var clashMode: String {
        switch self {
        case .rule: return "Rule"
        case .global: return "Global"
        case .direct: return "Direct"
        }
    }
}

// MARK: - 連線狀態

enum ConnectionState: Equatable {
    case disconnected
    case connecting
    case connected
    case stopping

    var label: String {
        switch self {
        case .disconnected: return String(localized: "未連線")
        case .connecting: return String(localized: "連線中…")
        case .connected: return String(localized: "已連線")
        case .stopping: return String(localized: "正在中斷…")
        }
    }
}

// MARK: - 自訂分流規則

enum RuleType: String, Codable, CaseIterable {
    case domainSuffix
    case domainKeyword
    case domainExact
    case ipCIDR
    case geoIP
    case geosite
    case processName
    case ruleSet

    var displayName: String {
        switch self {
        case .domainSuffix: return String(localized: "網域後綴")
        case .domainKeyword: return String(localized: "網域關鍵字")
        case .domainExact: return String(localized: "完整網域")
        case .ipCIDR: return String(localized: "IP 區段")
        case .geoIP: return String(localized: "GeoIP 國家")
        case .geosite: return String(localized: "Geosite 分類")
        case .processName: return String(localized: "程序名稱")
        case .ruleSet: return String(localized: "規則集 URL")
        }
    }

    var placeholder: String {
        switch self {
        case .domainSuffix: return "example.com"
        case .domainKeyword: return "google"
        case .domainExact: return "www.example.com"
        case .ipCIDR: return "8.8.8.0/24"
        case .geoIP: return "us"
        case .geosite: return "netflix"
        case .processName: return "Telegram"
        case .ruleSet: return "https://example.com/rules.srs"
        }
    }
}

enum RulePolicy: String, Codable, CaseIterable {
    case proxy
    case direct
    case reject

    var displayName: String {
        switch self {
        case .proxy: return String(localized: "代理")
        case .direct: return String(localized: "直連")
        case .reject: return String(localized: "拒絕")
        }
    }
}

struct UserRule: Codable, Identifiable, Hashable {
    var id = UUID()
    var enabled = true
    var type: RuleType = .domainSuffix
    /// 比對值，逗號分隔可填多個
    var value: String = ""
    var policy: RulePolicy = .proxy

    var values: [String] {
        value.split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }
}

// MARK: - 代理群組

/// sing-box 原生支援的兩種群組型別：手動選擇與自動最快（urltest）。
/// Clash 的 fallback / load-balance 屬 Clash 核心專有，sing-box 不支援，故不提供。
enum ProxyGroupType: String, Codable, CaseIterable {
    case select
    case urltest

    var displayName: String {
        switch self {
        case .select: return String(localized: "手動選擇")
        case .urltest: return String(localized: "自動（最快）")
        }
    }

    var icon: String {
        switch self {
        case .select: return "hand.point.up.left"
        case .urltest: return "bolt"
        }
    }
}

/// 代理群組：把多個節點組成一個可被選為出口的群組（地區群組、自動測速群組等）。
struct ProxyGroup: Codable, Identifiable, Hashable {
    var id = UUID()
    var name: String = "群組"
    var type: ProxyGroupType = .select
    var memberNodeIDs: [UUID] = []
}

// MARK: - 設定

enum EngineKind: String, Codable, CaseIterable {
    case native
    case singbox

    var displayName: String {
        switch self {
        case .singbox: return String(localized: "sing-box（完整）")
        case .native: return String(localized: "原生")
        }
    }
}

struct AppSettings: Codable {
    var mixedPort = 7890
    var apiPort = 9090
    var apiSecret = UUID().uuidString
    var allowLAN = false
    var autoSystemProxy = true
    /// TUN 模式：以管理員權限執行引擎，接管全部流量
    var tunMode = false
    /// 阻擋廣告（geosite-category-ads-all，所有模式生效）
    var adBlock = false
    /// 規則模式下中國大陸網站直連
    var chinaDirect = true
    /// 遠端 DNS（代理流量解析用）：IP、https:// DoH 或 tls:// DoT
    var remoteDNS = "8.8.8.8"
    /// 直連 DNS：IP、DoH/DoT，或 "local" 使用系統解析
    var localDNS = "223.5.5.5"
    /// 訂閱自動更新間隔（小時，0 = 關閉）
    var subAutoUpdateHours = 0
    /// 代理引擎：sing-box（完整）或 native（純原生）
    var engineKind: EngineKind = .native
    /// 拉取訂閱時的 User-Agent（機場常依此決定回傳格式）
    var subscriptionUA = "sing-box/1.13.13"
    /// TLS ClientHello 分片（原生引擎，抗封鎖）
    var tlsFragment = false
    /// uTLS 指紋：sing-box 引擎於節點未帶 fp 時套用；原生引擎的自建 TLS 1.3 客戶端亦用它決定 ClientHello 指紋
    /// （chrome/safari/firefox/edge/ios/randomized…），抗 JA3 指紋與主動探測。空字串 = sing-box 不套用。
    var tlsFingerprint = "chrome"
    /// 原生引擎：以自建 TLS 1.3 客戶端（可控 ClientHello、瀏覽器指紋，macOS 26+ 送後量子 X25519MLKEM768）
    /// 取代 Apple NWProtocolTLS，僅套用於 Trojan / VLESS 的 TCP+TLS 路徑（WS/wss 仍走系統 TLS）。
    var nativeTLS = true
    /// 偵測到網路可用時自動連線（On-demand）
    var autoConnect = false
    /// Kill switch：引擎意外停止時保留系統代理以阻擋流量外洩
    var killSwitch = false
    /// 啟動時自動檢查更新（GitHub Releases）
    var autoCheckUpdates = true

    init() {}

    private enum CodingKeys: String, CodingKey {
        case mixedPort, apiPort, apiSecret, allowLAN, autoSystemProxy
        case tunMode, adBlock, chinaDirect, remoteDNS, localDNS, subAutoUpdateHours, engineKind
        case subscriptionUA, tlsFragment, tlsFingerprint, nativeTLS, autoConnect, killSwitch, autoCheckUpdates
    }

    // 手寫 decode：舊版設定檔缺新欄位時用預設值，避免升級後設定全失
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        mixedPort = try c.decodeIfPresent(Int.self, forKey: .mixedPort) ?? 7890
        apiPort = try c.decodeIfPresent(Int.self, forKey: .apiPort) ?? 9090
        apiSecret = try c.decodeIfPresent(String.self, forKey: .apiSecret) ?? UUID().uuidString
        allowLAN = try c.decodeIfPresent(Bool.self, forKey: .allowLAN) ?? false
        autoSystemProxy = try c.decodeIfPresent(Bool.self, forKey: .autoSystemProxy) ?? true
        tunMode = try c.decodeIfPresent(Bool.self, forKey: .tunMode) ?? false
        adBlock = try c.decodeIfPresent(Bool.self, forKey: .adBlock) ?? false
        chinaDirect = try c.decodeIfPresent(Bool.self, forKey: .chinaDirect) ?? true
        remoteDNS = try c.decodeIfPresent(String.self, forKey: .remoteDNS) ?? "8.8.8.8"
        localDNS = try c.decodeIfPresent(String.self, forKey: .localDNS) ?? "223.5.5.5"
        subAutoUpdateHours = try c.decodeIfPresent(Int.self, forKey: .subAutoUpdateHours) ?? 0
        engineKind = try c.decodeIfPresent(EngineKind.self, forKey: .engineKind) ?? .native
        subscriptionUA = try c.decodeIfPresent(String.self, forKey: .subscriptionUA) ?? "sing-box/1.13.13"
        tlsFragment = try c.decodeIfPresent(Bool.self, forKey: .tlsFragment) ?? false
        tlsFingerprint = try c.decodeIfPresent(String.self, forKey: .tlsFingerprint) ?? "chrome"
        nativeTLS = try c.decodeIfPresent(Bool.self, forKey: .nativeTLS) ?? true
        autoConnect = try c.decodeIfPresent(Bool.self, forKey: .autoConnect) ?? false
        killSwitch = try c.decodeIfPresent(Bool.self, forKey: .killSwitch) ?? false
        autoCheckUpdates = try c.decodeIfPresent(Bool.self, forKey: .autoCheckUpdates) ?? true
    }
}

// MARK: - 持久化

struct PersistedState: Codable {
    var nodes: [ProxyNode] = []
    var subscriptions: [Subscription] = []
    var settings = AppSettings()
    var mode: ProxyMode = .rule
    var selectedNodeID: UUID?
    var rules: [UserRule] = []
    var groups: [ProxyGroup] = []

    init(nodes: [ProxyNode] = [],
         subscriptions: [Subscription] = [],
         settings: AppSettings = AppSettings(),
         mode: ProxyMode = .rule,
         selectedNodeID: UUID? = nil,
         rules: [UserRule] = [],
         groups: [ProxyGroup] = []) {
        self.nodes = nodes
        self.subscriptions = subscriptions
        self.settings = settings
        self.mode = mode
        self.selectedNodeID = selectedNodeID
        self.rules = rules
        self.groups = groups
    }

    private enum CodingKeys: String, CodingKey {
        case nodes, subscriptions, settings, mode, selectedNodeID, rules, groups
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        nodes = try c.decodeIfPresent([ProxyNode].self, forKey: .nodes) ?? []
        subscriptions = try c.decodeIfPresent([Subscription].self, forKey: .subscriptions) ?? []
        settings = try c.decodeIfPresent(AppSettings.self, forKey: .settings) ?? AppSettings()
        mode = try c.decodeIfPresent(ProxyMode.self, forKey: .mode) ?? .rule
        selectedNodeID = try c.decodeIfPresent(UUID.self, forKey: .selectedNodeID)
        rules = try c.decodeIfPresent([UserRule].self, forKey: .rules) ?? []
        groups = try c.decodeIfPresent([ProxyGroup].self, forKey: .groups) ?? []
    }
}

// MARK: - 連線記錄（Clash API /connections）

/// 即時流量取樣（流量圖用）。seq 為遞增序號，當作圖表 X 軸。
struct TrafficSample: Identifiable, Equatable {
    let seq: Int
    let up: Int      // bytes/s
    let down: Int    // bytes/s
    var id: Int { seq }
}

struct ConnectionInfo: Identifiable, Equatable {
    var id: String
    var target: String       // host:port
    var network: String      // tcp / udp
    var rule: String         // 命中的規則
    var chain: String        // 實際出口節點
    var upload: Int
    var download: Int
    var start: Date?

    var durationText: String {
        guard let start else { return "-" }
        let secs = Int(Date().timeIntervalSince(start))
        if secs < 60 { return "\(secs) 秒" }
        if secs < 3600 { return "\(secs / 60) 分 \(secs % 60) 秒" }
        return "\(secs / 3600) 時 \(secs % 3600 / 60) 分"
    }
}

// MARK: - 小工具

extension Int64 {
    /// 1234567 -> "1.2 MB"
    var byteString: String {
        ByteCountFormatter.string(fromByteCount: self, countStyle: .binary)
    }
}

extension Int {
    var byteString: String { Int64(self).byteString }
    /// 速率顯示用，例如 "1.2 MB/s"
    var rateString: String { Int64(self).byteString + "/s" }
    /// 選單列空間有限，使用較短的速率格式，例如 "1.2 MB/s"。
    var menuBarRateString: String {
        let bytes = Swift.max(0, self)
        guard bytes >= 1024 else { return "\(bytes) B/s" }

        let units = ["KB", "MB", "GB", "TB"]
        var value = Double(bytes) / 1024.0
        var index = 0
        while value >= 1024.0 && index < units.count - 1 {
            value /= 1024.0
            index += 1
        }

        let format = value < 10 ? "%.1f %@/s" : "%.0f %@/s"
        return String(format: format, value, units[index])
    }
}
