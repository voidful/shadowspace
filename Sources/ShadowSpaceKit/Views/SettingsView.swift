import SwiftUI
import ServiceManagement
import AppKit

struct SettingsView: View {
    @EnvironmentObject private var state: AppState
    @State private var launchAtLogin = SMAppService.mainApp.status == .enabled

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
            Section {
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
                if !state.settings.tunMode {
                    Toggle("連線時自動設定系統代理", isOn: Binding(
                        get: { state.settings.autoSystemProxy },
                        set: { state.settings.autoSystemProxy = $0; state.save() }
                    ))
                }
                Toggle("登入時啟動", isOn: $launchAtLogin)
                    .onChange(of: launchAtLogin) { _, enabled in
                        toggleLaunchAtLogin(enabled)
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
                    TextField("", value: Binding(
                        get: { state.settings.mixedPort },
                        set: { state.settings.mixedPort = $0; state.save() }
                    ), format: .number.grouping(.never))
                    .frame(width: 80)
                    .multilineTextAlignment(.trailing)
                }
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
            } header: {
                Text("網路")
            } footer: {
                Text("連線中修改連接埠，需重新連線後生效。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("訂閱") {
                Picker("自動更新", selection: Binding(
                    get: { state.settings.subAutoUpdateHours },
                    set: { state.settings.subAutoUpdateHours = $0; state.save() }
                )) {
                    Text("關閉").tag(0)
                    Text("每 6 小時").tag(6)
                    Text("每 12 小時").tag(12)
                    Text("每 24 小時").tag(24)
                }
            }

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
                    NSWorkspace.shared.open(EngineManager.supportDir)
                }
            }

            Section("關於") {
                LabeledContent("ShadowSpace", value: "0.2.0")
                Text("核心引擎使用開源專案 sing-box（GPLv3），以獨立子程序方式執行。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .navigationTitle("設定")
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
