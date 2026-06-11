import SwiftUI

/// 分流規則：快速開關（廣告阻擋、中國大陸直連）+ 自訂規則清單。
struct RulesView: View {
    @EnvironmentObject private var state: AppState
    @State private var editingRule: UserRule?
    @State private var showAddSheet = false

    var body: some View {
        List {
            Section {
                Toggle(isOn: Binding(
                    get: { state.settings.adBlock },
                    set: { state.settings.adBlock = $0; state.saveAndApply() }
                )) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("阻擋廣告")
                        Text("使用 AdGuard 廣告網域清單，所有模式皆生效")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                Toggle(isOn: Binding(
                    get: { state.settings.chinaDirect },
                    set: { state.settings.chinaDirect = $0; state.saveAndApply() }
                )) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("中國大陸網站直連")
                        Text("規則模式下，中國大陸網域與 IP 不走代理")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            } header: {
                Text("內建規則")
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

    private func ruleRow(_ rule: UserRule) -> some View {
        HStack(spacing: 10) {
            Toggle("", isOn: Binding(
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
    @State private var draft = UserRule()

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
            }

            Picker("策略", selection: $draft.policy) {
                ForEach(RulePolicy.allCases, id: \.self) { policy in
                    Text(policy.displayName).tag(policy)
                }
            }
            .pickerStyle(.segmented)

            HStack {
                if rule != nil {
                    Button("刪除", role: .destructive) {
                        state.deleteRule(draft.id)
                        dismiss()
                    }
                }
                Spacer()
                Button("取消") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("儲存") {
                    state.upsertRule(draft)
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(draft.values.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 420)
        .onAppear {
            if let rule { draft = rule }
        }
    }
}
