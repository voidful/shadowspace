import SwiftUI
import ServiceManagement
import AppKit
import UniformTypeIdentifiers

struct SettingsView: View {
    @EnvironmentObject private var state: AppState
    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled
    @State private var showConfigSheet = false

    private let remoteDNSPresets: [(String, String)] = [
        ("Google (8.8.8.8)", "8.8.8.8"),
        ("Cloudflare (1.1.1.1)", "1.1.1.1"),
        ("Google DoH", "https://dns.google/dns-query"),
        ("Cloudflare DoH", "https://cloudflare-dns.com/dns-query"),
    ]
    private let localDNSPresets: [(String, String)] = [
        ("AliDNS (223.5.5.5)", "223.5.5.5"),
        ("DNSPod (119.29.29.29)", "119.29.29.29"),
        ("Hinet (168.95.1.1)", "168.95.1.1"),
        ("系統解析", "local"),
    ]

    var body: some View {
        Form {
#if APP_STORE
            Section {
                LabeledContent("代理引擎", value: "原生 NetworkExtension")
            } header: {
                Text("引擎")
            } footer: {
                Text("App Store 版使用 Apple NetworkExtension 透明代理，不包含 sing-box 子程序、TUN 管理員授權或系統代理改寫。支援 SS / Trojan / VLESS / SOCKS5（含 ws/wss）。")
                    .font(.caption).foregroundStyle(.secondary)
            }
#else
            Section {
                Picker("代理引擎", selection: Binding(
                    get: { state.settings.engineKind },
                    set: { newKind in
                        state.settings.engineKind = newKind
                        state.save()
                        if state.connectionState == .connected {
                            state.toastMessage = "已切換引擎，重新連線後生效"
                        }
                    }
                )) {
                    ForEach(EngineKind.allCases, id: \.self) { kind in
                        Text(kind.displayName).tag(kind)
                    }
                }
                if state.settings.engineKind == .native {
                    Toggle(isOn: Binding(
                        get: { state.settings.nativeTLS },
                        set: { state.settings.nativeTLS = $0; state.saveAndApply() }
                    )) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("原生 TLS 指紋偽裝（抗封鎖）")
                            Text("以自建 TLS 1.3 客戶端取代系統 TLS，把 ClientHello 偽裝成瀏覽器（macOS 26+ 送後量子指紋）。套用於 Trojan / VLESS 的 TCP+TLS；ws/wss 仍走系統 TLS。")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                    Toggle(isOn: Binding(
                        get: { state.settings.tlsFragment },
                        set: { state.settings.tlsFragment = $0; state.saveAndApply() }
                    )) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("TLS 分片（抗封鎖）")
                            Text("把 TLS ClientHello 切成多段送出，干擾 DPI 的 SNI 偵測。原生引擎適用。")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                // 指紋選擇器：sing-box 引擎，或原生引擎已開啟原生 TLS 時皆適用
                if state.settings.engineKind == .singbox
                    || (state.settings.engineKind == .native && state.settings.nativeTLS) {
                    VStack(alignment: .leading, spacing: 2) {
                        Picker("TLS 指紋偽裝（uTLS）", selection: Binding(
                            get: { state.settings.tlsFingerprint },
                            set: { state.settings.tlsFingerprint = $0; state.saveAndApply() }
                        )) {
                            Text("Chrome").tag("chrome")
                            Text("Safari").tag("safari")
                            Text("Firefox").tag("firefox")
                            Text("Edge").tag("edge")
                            Text("iOS").tag("ios")
                            Text("隨機").tag("randomized")
                            Text("關閉").tag("")
                        }
                        Text("把外層 TLS ClientHello 偽裝成瀏覽器，抗 JA3 指紋與主動探測（對應 Shadowrocket 的作法）。原生引擎目前以 Chrome 指紋實作。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            } header: {
                Text("引擎")
            } footer: {
                Text("原生引擎純 Apple 框架、不依賴外部核心，支援 SS / Trojan / VLESS / SOCKS5（含 ws/wss），並可自建 TLS 1.3 偽裝瀏覽器指紋；尚不支援 Reality / XTLS Vision / Hysteria2 / TUIC / VMess / TUN——這些請改用 sing-box 引擎。")
                    .font(.caption).foregroundStyle(.secondary)
            }
#endif

            Section {
#if !APP_STORE
                if state.settings.engineKind == .singbox {
                    Toggle(isOn: Binding(
                        get: { state.settings.tunMode },
                        set: { state.settings.tunMode = $0; state.saveAndApply() }
                    )) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("TUN 模式（增強模式）")
                            Text("建立虛擬網卡接管全部流量，含終端機與不吃系統代理的 App。連線時需輸入一次管理員密碼。")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                if state.settings.engineKind == .native || !state.settings.tunMode {
                    Toggle("連線時自動設定系統代理", isOn: Binding(
                        get: { state.settings.autoSystemProxy },
                        set: { state.settings.autoSystemProxy = $0; state.save() }
                    ))
                }
                if state.settings.engineKind == .singbox {
                    Toggle(isOn: Binding(
                        get: { state.settings.killSwitch },
                        set: { state.settings.killSwitch = $0; state.save() }
                    )) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Kill switch（防洩漏）")
                            Text("sing-box 引擎意外停止時保留系統代理以阻擋流量直連外洩；重新連線即可恢復。")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
#endif
                Toggle("登入時啟動", isOn: $launchAtLogin)
                    .onChange(of: launchAtLogin) { _, enabled in
                        toggleLaunchAtLogin(enabled)
                    }
                Toggle(isOn: Binding(
                    get: { state.settings.autoConnect },
                    set: { state.settings.autoConnect = $0; state.save() }
                )) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("偵測到網路就自動連線")
                        Text("開機或網路切換、恢復時自動連上；手動斷線後不會自動重連。")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            } header: {
                Text("一般")
            }

            Section {
                DNSPickerRow(title: "遠端 DNS（代理流量）",
                             presets: remoteDNSPresets,
                             value: Binding(
                                get: { state.settings.remoteDNS },
                                set: { state.settings.remoteDNS = $0; state.saveAndApply() }
                             ))
                DNSPickerRow(title: "直連 DNS",
                             presets: localDNSPresets,
                             value: Binding(
                                get: { state.settings.localDNS },
                                set: { state.settings.localDNS = $0; state.saveAndApply() }
                             ))
            } header: {
                Text("DNS")
            } footer: {
                Text("自訂值支援 IP、https://（DoH）與 tls://（DoT）。遠端 DNS 透過代理解析，避免 DNS 污染。")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Section {
                LabeledContent("代理連接埠（HTTP/SOCKS 共用）") {
#if APP_STORE
                    Text("由系統管理")
                        .foregroundStyle(.secondary)
#else
                    TextField("", value: Binding(
                        get: { state.settings.mixedPort },
                        set: { state.settings.mixedPort = $0; state.save() }
                    ), format: .number.grouping(.never))
                    .frame(width: 80)
                    .multilineTextAlignment(.trailing)
#endif
                }
#if !APP_STORE
                LabeledContent("控制 API 連接埠") {
                    TextField("", value: Binding(
                        get: { state.settings.apiPort },
                        set: { state.settings.apiPort = $0; state.save() }
                    ), format: .number.grouping(.never))
                    .frame(width: 80)
                    .multilineTextAlignment(.trailing)
                }
                Toggle("允許區域網路連入", isOn: Binding(
                    get: { state.settings.allowLAN },
                        set: { state.settings.allowLAN = $0; state.save() }
                ))
#endif
            } header: {
                Text("網路")
            } footer: {
#if APP_STORE
                Text("透明代理由 NetworkExtension 管理，不開本機 HTTP/SOCKS 監聽埠。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
#else
                Text("連線中修改連接埠，需重新連線後生效。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
#endif
            }

            Section {
                Picker("自動更新", selection: Binding(
                    get: { state.settings.subAutoUpdateHours },
                    set: { state.settings.subAutoUpdateHours = $0; state.save() }
                )) {
                    Text("關閉").tag(0)
                    Text("每 6 小時").tag(6)
                    Text("每 12 小時").tag(12)
                    Text("每 24 小時").tag(24)
                }
                LabeledContent("拉取 User-Agent") {
                    HStack {
                        TextField("", text: Binding(
                            get: { state.settings.subscriptionUA },
                            set: { state.settings.subscriptionUA = $0; state.save() }
                        ))
                        .frame(maxWidth: 200)
                        .multilineTextAlignment(.trailing)
                        Menu("常用") {
                            Button("sing-box") { state.settings.subscriptionUA = "sing-box/1.13.13"; state.save() }
                            Button("Shadowrocket") { state.settings.subscriptionUA = "Shadowrocket/2.2.65"; state.save() }
                            Button("clash.meta") { state.settings.subscriptionUA = "clash.meta"; state.save() }
                            Button("v2rayN") { state.settings.subscriptionUA = "v2rayN/6.45"; state.save() }
                        }
                        .fixedSize()
                    }
                }
            } header: {
                Text("訂閱")
            } footer: {
                Text("機場常依 User-Agent 回傳不同格式。送 sing-box 會拿到完整設定（含 VLESS、WS/Reality 等）；改 UA 後到「節點」分頁重新整理訂閱即生效。")
                    .font(.caption).foregroundStyle(.secondary)
            }

#if !APP_STORE
            Section("核心引擎") {
                LabeledContent("sing-box 版本") {
                    Text(state.engineVersion ?? "尚未安裝")
                        .foregroundStyle(state.engineVersion == nil ? .red : .secondary)
                }
                HStack {
                    Button(state.engineVersion == nil ? "下載並安裝引擎" : "更新引擎") {
                        Task { await state.installOrUpdateEngine() }
                    }
                    .disabled(state.isInstallingEngine || state.connectionState != .disconnected)
                    if state.isInstallingEngine {
                        ProgressView().controlSize(.small)
                        Text(state.engineInstallStatus ?? "")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                Button("開啟設定資料夾") {
                    NSWorkspace.shared.open(AppState.supportDir)
                }
            }
#else
            Section("資料") {
                Button("開啟設定資料夾") {
                    NSWorkspace.shared.open(AppState.supportDir)
                }
            }
#endif

            Section("進階") {
#if !APP_STORE
                Button("檢視產生的 sing-box 設定") { showConfigSheet = true }
#endif
                Button("匯出備份…") { exportBackup() }
                Button("匯入備份…") { importBackup() }
            }

            Section("關於") {
                LabeledContent("ShadowSpace", value: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "未知版本")
#if APP_STORE
                Text("App Store 版使用原生代理核心與 NetworkExtension，不包含外部代理核心或管理員授權流程。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
#else
                Text("核心引擎使用開源專案 sing-box（GPLv3），以獨立子程序方式執行。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let update = state.availableUpdate {
                    HStack {
                        Label("有新版本 \(update.version)", systemImage: "arrow.down.circle.fill")
                            .foregroundStyle(.green)
                        Spacer()
                        Button("前往下載") {
                            if let url = URL(string: update.url) { NSWorkspace.shared.open(url) }
                        }
                        .buttonStyle(.borderedProminent)
                    }
                }
                Button("檢查更新…") { state.checkForUpdates(manual: true) }
                Toggle("啟動時自動檢查更新", isOn: Binding(
                    get: { state.settings.autoCheckUpdates },
                    set: { state.settings.autoCheckUpdates = $0; state.save() }
                ))
#endif
            }
        }
        .formStyle(.grouped)
        .navigationTitle("設定")
        .sheet(isPresented: $showConfigSheet) {
            ConfigViewerSheet(json: state.generatedConfigJSON())
        }
    }

    private func exportBackup() {
        guard let data = state.exportBackup() else { return }
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "ShadowSpace-backup.json"
        panel.allowedContentTypes = [.json]
        if panel.runModal() == .OK, let url = panel.url {
            try? data.write(to: url)
            state.toastMessage = "已匯出備份"
        }
    }

    private func importBackup() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        panel.allowsMultipleSelection = false
        if panel.runModal() == .OK, let url = panel.url, let data = try? Data(contentsOf: url) {
            state.importBackup(data)
        }
    }

    private func toggleLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
        } catch {
            launchAtLogin = SMAppService.mainApp.status == .enabled
            state.errorMessage = "無法設定登入啟動：\(error.localizedDescription)\n（提示：需以 .app 形式執行，開發模式 swift run 不支援）"
        }
    }
}

// MARK: - 設定檢視 Sheet

struct ConfigViewerSheet: View {
    @Environment(\.dismiss) private var dismiss
    let json: String

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("產生的 sing-box 設定")
                .font(.headline)
            ScrollView {
                Text(json)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(8)
            }
            .overlay(RoundedRectangle(cornerRadius: 6).stroke(.quaternary))
            HStack {
                Button("複製") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(json, forType: .string)
                }
                Spacer()
                Button("完成") { dismiss() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
        .frame(width: 600, height: 560)
    }
}

/// DNS 選擇列：預設清單 + 自訂輸入
private struct DNSPickerRow: View {
    let title: String
    let presets: [(String, String)]
    @Binding var value: String
    @State private var customMode = false

    private var matchesPreset: Bool {
        presets.contains { $0.1 == value }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Picker(title, selection: Binding(
                get: { (customMode || !matchesPreset) ? "__custom__" : value },
                set: { newValue in
                    if newValue == "__custom__" {
                        customMode = true
                    } else {
                        customMode = false
                        value = newValue
                    }
                }
            )) {
                ForEach(presets, id: \.1) { label, preset in
                    Text(label).tag(preset)
                }
                Text("自訂…").tag("__custom__")
            }
            if customMode || !matchesPreset {
                TextField("", text: $value, prompt: Text("例如 9.9.9.9 或 https://dns.example.com/dns-query"))
                    .textFieldStyle(.roundedBorder)
            }
        }
        .onAppear { customMode = !matchesPreset }
    }
}
