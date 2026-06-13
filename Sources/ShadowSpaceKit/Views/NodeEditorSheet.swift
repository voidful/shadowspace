import SwiftUI

/// 節點手動新增 / 編輯表單。依協議動態顯示欄位。
struct NodeEditorSheet: View {
    @EnvironmentObject private var state: AppState
    @Environment(\.dismiss) private var dismiss

    let node: ProxyNode?
    @State private var draft = ProxyNode(name: "", proto: .shadowsocks, server: "", port: 443)

    private let fingerprints = ["", "chrome", "firefox", "safari", "ios", "edge", "random"]
    private let ssMethodSuggestions = [
        "aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305",
        "2022-blake3-aes-256-gcm", "2022-blake3-aes-128-gcm",
    ]

    var body: some View {
        VStack(spacing: 0) {
            Text(node == nil ? "手動新增節點" : "編輯節點")
                .font(.headline)
                .padding(.top, 16)

            Form {
                Section("基本") {
                    TextField("名稱", text: $draft.name, prompt: Text("我的節點"))
                    Picker("協議", selection: $draft.proto) {
                        ForEach(NodeProtocol.allCases, id: \.self) { proto in
                            Text(proto.displayName).tag(proto)
                        }
                    }
                    TextField("伺服器", text: $draft.server, prompt: Text("example.com 或 IP"))
                    TextField("連接埠", value: $draft.port, format: .number.grouping(.never))
                }

                authSection
                if showsTLSSection { tlsSection }
                if showsTransportSection { transportSection }
                relaySection
            }
            .formStyle(.grouped)

            HStack {
                Spacer()
                Button("取消") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("儲存") {
                    var final = draft
                    if final.name.trimmingCharacters(in: .whitespaces).isEmpty {
                        final.name = "\(final.server):\(final.port)"
                    }
                    state.upsertNode(final)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(!isValid)
            }
            .padding(16)
        }
        .frame(width: 480, height: 560)
        .onAppear {
            if let node { draft = node }
        }
        .onChange(of: draft.proto) { _, newProto in
            // 切換協議時調整 TLS 預設：trojan/hy2/tuic 必為 TLS
            switch newProto {
            case .trojan, .hysteria2, .tuic: draft.tls = true
            case .shadowsocks, .socks: draft.tls = false
            default: break
            }
        }
    }

    private var isValid: Bool {
        guard !draft.server.trimmingCharacters(in: .whitespaces).isEmpty,
              (1...65535).contains(draft.port) else { return false }
        switch draft.proto {
        case .shadowsocks:
            return !(draft.method ?? "").isEmpty && !(draft.password ?? "").isEmpty
        case .vmess, .vless:
            return !(draft.uuid ?? "").isEmpty
        case .trojan, .hysteria2, .anytls:
            return !(draft.password ?? "").isEmpty
        case .tuic:
            return !(draft.uuid ?? "").isEmpty
        case .socks:
            return true
        case .wireguard:
            return !(draft.wgPrivateKey ?? "").isEmpty && !(draft.wgPeerPublicKey ?? "").isEmpty
        }
    }

    // MARK: - 認證欄位

    @ViewBuilder
    private var authSection: some View {
        Section("認證") {
            switch draft.proto {
            case .shadowsocks:
                Picker("加密方式", selection: optional($draft.method, default: "aes-256-gcm")) {
                    ForEach(ssMethodSuggestions, id: \.self) { method in
                        Text(method).tag(method)
                    }
                }
                SecureInput("密碼", text: optional($draft.password))
            case .vmess:
                TextField("UUID", text: optional($draft.uuid))
                TextField("Alter ID", value: Binding(
                    get: { draft.alterId ?? 0 },
                    set: { draft.alterId = $0 }
                ), format: .number)
                Picker("加密", selection: optional($draft.security, default: "auto")) {
                    ForEach(["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"], id: \.self) {
                        Text($0).tag($0)
                    }
                }
            case .vless:
                TextField("UUID", text: optional($draft.uuid))
                Picker("Flow", selection: optional($draft.flow, default: "")) {
                    Text("無").tag("")
                    Text("xtls-rprx-vision").tag("xtls-rprx-vision")
                }
            case .trojan, .anytls:
                SecureInput("密碼", text: optional($draft.password))
            case .hysteria2:
                SecureInput("密碼", text: optional($draft.password))
                TextField("混淆（obfs，可空）", text: optional($draft.obfs))
                if (draft.obfs ?? "").isEmpty == false {
                    SecureInput("混淆密碼", text: optional($draft.obfsPassword))
                }
            case .tuic:
                TextField("UUID", text: optional($draft.uuid))
                SecureInput("密碼", text: optional($draft.password))
                Picker("壅塞控制", selection: optional($draft.congestionControl, default: "")) {
                    Text("預設").tag("")
                    ForEach(["bbr", "cubic", "new_reno"], id: \.self) { Text($0).tag($0) }
                }
            case .socks:
                TextField("帳號（可空）", text: optional($draft.username))
                SecureInput("密碼（可空）", text: optional($draft.password))
            case .wireguard:
                Text("WireGuard 請用「貼上匯入」貼入 .conf 設定檔內容")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
    }

    // MARK: - TLS

    private var showsTLSSection: Bool {
        switch draft.proto {
        case .vmess, .vless, .trojan, .hysteria2, .tuic, .anytls: return true
        case .shadowsocks, .socks, .wireguard: return false
        }
    }

    private var tlsForced: Bool {
        switch draft.proto {
        case .trojan, .hysteria2, .tuic, .anytls: return true
        default: return false
        }
    }

    @ViewBuilder
    private var tlsSection: some View {
        Section("TLS") {
            Toggle("啟用 TLS", isOn: $draft.tls)
                .disabled(tlsForced)
            if draft.tls {
                TextField("SNI（可空，預設用伺服器位址）", text: optional($draft.sni))
                Toggle("允許不安全憑證", isOn: $draft.insecure)
                Picker("uTLS 指紋", selection: optional($draft.fingerprint, default: "")) {
                    ForEach(fingerprints, id: \.self) { fp in
                        Text(fp.isEmpty ? "無" : fp).tag(fp)
                    }
                }
                if draft.proto == .vless {
                    TextField("Reality 公鑰（pbk，可空）", text: optional($draft.realityPublicKey))
                    TextField("Reality Short ID（sid）", text: optional($draft.realityShortID))
                }
            }
        }
    }

    // MARK: - 傳輸層

    private var showsTransportSection: Bool {
        switch draft.proto {
        case .vmess, .vless, .trojan: return true
        default: return false
        }
    }

    @ViewBuilder
    private var transportSection: some View {
        Section("傳輸") {
            Picker("傳輸方式", selection: optional($draft.network, default: "")) {
                Text("TCP").tag("")
                Text("WebSocket").tag("ws")
                Text("gRPC").tag("grpc")
                Text("HTTP/2").tag("http")
            }
            switch draft.network {
            case "ws", "http":
                TextField("路徑", text: optional($draft.wsPath), prompt: Text("/"))
                TextField("Host（可空）", text: optional($draft.wsHost))
            case "grpc":
                TextField("gRPC 服務名稱", text: optional($draft.grpcServiceName))
            default:
                EmptyView()
            }
        }
    }

    // MARK: - 節點鏈（中轉）

    @ViewBuilder
    private var relaySection: some View {
        let candidates = state.nodes.filter { $0.id != draft.id && $0.proto != .wireguard }
        if !candidates.isEmpty, draft.proto != .wireguard {
            Section {
                Picker("中轉節點", selection: Binding(
                    get: { draft.dialerNodeID ?? Self.noRelay },
                    set: { draft.dialerNodeID = ($0 == Self.noRelay) ? nil : $0 }
                )) {
                    Text("無（直接連線）").tag(Self.noRelay)
                    ForEach(candidates) { node in
                        Text(node.name).tag(node.id)
                    }
                }
            } header: {
                Text("節點鏈")
            } footer: {
                Text("先經中轉節點再連到本節點，形成「中轉 → 落地」鏈路。")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
    private static let noRelay = UUID(uuidString: "00000000-0000-0000-0000-000000000000")!

    // MARK: - Optional<String> 綁定小工具

    private func optional(_ binding: Binding<String?>, default def: String = "") -> Binding<String> {
        Binding(
            get: { binding.wrappedValue ?? def },
            set: { binding.wrappedValue = $0.isEmpty ? nil : $0 }
        )
    }
}

/// 可顯示/隱藏的密碼欄位
private struct SecureInput: View {
    let title: String
    @Binding var text: String
    @State private var reveal = false

    init(_ title: String, text: Binding<String>) {
        self.title = title
        self._text = text
    }

    var body: some View {
        HStack {
            if reveal {
                TextField(title, text: $text)
            } else {
                SecureField(title, text: $text)
            }
            Button {
                reveal.toggle()
            } label: {
                Image(systemName: reveal ? "eye.slash" : "eye")
            }
            .buttonStyle(.borderless)
        }
    }
}
