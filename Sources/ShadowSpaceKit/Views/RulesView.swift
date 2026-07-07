import SwiftUI

/// 分流規則：快速開關（廣告阻擋、中國大陸直連）+ 自訂規則清單。
struct RulesView: View {
    @EnvironmentObject private var state: AppState
    @State private var editingRule: UserRule?
    @State private var showAddSheet = false

    var body: some View {
        List {
            Section {
                Toggle(isOn: state.appliedSetting(\.adBlock)) {
                    CaptionedLabel("阻擋廣告", "使用 geosite 廣告網域清單（category-ads-all）；sing-box 引擎下所有模式皆生效")
                }
                Toggle(isOn: state.appliedSetting(\.chinaDirect)) {
                    CaptionedLabel("中國大陸網站直連", "規則模式下，中國大陸網域與 IP 不走代理")
                }
            } header: {
                Text("內建規則")
            } footer: {
                builtinRulesNotice
            }

            Section {
                if state.rules.isEmpty {
                    Text("還沒有自訂規則。點右上角「＋」新增，例如讓特定網站永遠直連或拒絕。")
                        .foregroundStyle(.secondary)
                        .font(.callout)
                } else {
                    ForEach(state.rules) { rule in
                        ruleRow(rule)
                    }
                    .onMove { state.moveRules(from: $0, to: $1) }
                }
            } header: {
                Text("自訂規則（由上而下比對，可拖曳排序）")
            } footer: {
                Text("自訂規則在「規則」模式下生效；「程序名稱」類型需開啟 TUN 模式才能比對。")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .navigationTitle("規則")
        .toolbar {
            ToolbarItem {
                Button {
                    showAddSheet = true
                } label: {
                    Label("新增規則", systemImage: "plus")
                }
            }
        }
        .sheet(isPresented: $showAddSheet) {
            RuleEditorSheet(rule: nil)
        }
        .sheet(item: $editingRule) { rule in
            RuleEditorSheet(rule: rule)
        }
    }

    /// 原生引擎（含 App Store 版）不吃內建規則與 GeoIP/Geosite/規則集，提醒使用者避免誤以為已生效。
    @ViewBuilder
    private var builtinRulesNotice: some View {
#if APP_STORE
        Label("App Store 版使用原生引擎，內建規則與 GeoIP／Geosite／規則集類型的自訂規則暫不支援。",
              systemImage: "info.circle")
            .font(.caption).foregroundStyle(.orange)
#else
        if state.settings.engineKind == .native {
            Label("原生引擎暫不支援內建規則與 GeoIP／Geosite／規則集類型，需改用 sing-box 引擎（節點原生不支援而自動改用 sing-box 時仍會生效）。",
                  systemImage: "info.circle")
                .font(.caption).foregroundStyle(.orange)
        }
#endif
    }

    private func ruleRow(_ rule: UserRule) -> some View {
        HStack(spacing: 10) {
            // 用規則內容當標籤（labelsHidden 隱藏外觀），VoiceOver 才唸得出「這是哪條規則的開關」。
            Toggle(rule.value.isEmpty ? "未填寫的規則" : rule.value, isOn: Binding(
                get: { rule.enabled },
                set: { state.toggleRule(rule.id, enabled: $0) }
            ))
            .labelsHidden()
            .toggleStyle(.switch)
            .controlSize(.mini)

            VStack(alignment: .leading, spacing: 1) {
                Text(rule.value.isEmpty ? "（未填寫）" : rule.value)
                    .lineLimit(1)
                Text(rule.type.displayName)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Text(rule.policy.displayName)
                .font(.caption.weight(.medium))
                .padding(.horizontal, 8)
                .padding(.vertical, 2)
                .background(policyColor(rule.policy).opacity(0.15), in: Capsule())
                .foregroundStyle(policyColor(rule.policy))
            Button {
                editingRule = rule
            } label: {
                Image(systemName: "pencil")
            }
            .buttonStyle(.borderless)
            .help("編輯規則")
            .accessibilityLabel("編輯規則")
        }
        .opacity(rule.enabled ? 1 : 0.45)
        .contentShape(Rectangle())
        .contextMenu {
            Button("編輯…") { editingRule = rule }
            Button("刪除", role: .destructive) { state.deleteRule(rule.id) }
        }
        .onTapGesture(count: 2) { editingRule = rule }
    }

    private func policyColor(_ policy: RulePolicy) -> Color {
        switch policy {
        case .proxy: return .blue
        case .direct: return .green
        case .reject: return .red
        }
    }
}

// MARK: - 規則編輯 Sheet

struct RuleEditorSheet: View {
    @EnvironmentObject private var state: AppState
    @Environment(\.dismiss) private var dismiss

    let rule: UserRule?
    @State private var draft: UserRule

    init(rule: UserRule?) {
        self.rule = rule
        _draft = State(initialValue: rule ?? UserRule())
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text(rule == nil ? "新增規則" : "編輯規則")
                .font(.headline)

            Picker("類型", selection: $draft.type) {
                ForEach(RuleType.allCases, id: \.self) { type in
                    Text(type.displayName).tag(type)
                }
            }

            VStack(alignment: .leading, spacing: 4) {
                TextField("比對值", text: $draft.value, prompt: Text(draft.type.placeholder))
                    .textFieldStyle(.roundedBorder)
                Text("逗號分隔可一次填多個，例如：youtube.com, ytimg.com")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if draft.type == .processName {
                    Label("分應用分流需開啟 TUN 模式才能依程序比對；系統代理模式下此規則不會生效。",
                          systemImage: "info.circle")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }

            Picker("策略", selection: $draft.policy) {
                ForEach(RulePolicy.allCases, id: \.self) { policy in
                    Text(policy.displayName).tag(policy)
                }
            }
            .pickerStyle(.segmented)

            EditorSheetFooter(
                onDelete: rule == nil ? nil : { state.deleteRule(draft.id); dismiss() },
                saveDisabled: draft.values.isEmpty,
                onCancel: { dismiss() },
                onSave: {
                    state.upsertRule(draft)
                    dismiss()
                }
            )
        }
        .padding(20)
        .frame(width: 420)
    }
}
