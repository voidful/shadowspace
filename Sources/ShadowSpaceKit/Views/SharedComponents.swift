import SwiftUI
import AppKit

// MARK: - 剪貼簿

extension NSPasteboard {
    /// 清空並寫入字串到剪貼簿。
    static func copyString(_ string: String) {
        general.clearContents()
        general.setString(string, forType: .string)
    }
}

// MARK: - 共用元件

/// 「標題＋灰色說明」兩行標籤（設定/規則的開關描述樣板）。
struct CaptionedLabel: View {
    let title: LocalizedStringKey
    let caption: LocalizedStringKey

    init(_ title: LocalizedStringKey, _ caption: LocalizedStringKey) {
        self.title = title
        self.caption = caption
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(title)
            Text(caption)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }
}

/// 規則/全域/直連 模式切換（segmented）。呼叫端自行決定 .labelsHidden()/frame/help。
struct ProxyModePicker: View {
    @ObservedObject var state: AppState

    var body: some View {
        Picker("代理模式", selection: Binding(
            get: { state.mode },
            set: { state.setMode($0) }
        )) {
            ForEach(ProxyMode.allCases, id: \.self) { mode in
                Text(mode.displayName).tag(mode)
            }
        }
        .pickerStyle(.segmented)
    }
}

/// 「從剪貼簿匯入」按鈕（自動辨識節點/訂閱）。樣式與 help 等情境修飾留呼叫端外掛。
struct ImportFromClipboardButton: View {
    @ObservedObject var state: AppState

    var body: some View {
        Button {
            Task { await state.importFromClipboard() }
        } label: {
            Label("從剪貼簿匯入", systemImage: "doc.on.clipboard")
        }
    }
}

/// 編輯 Sheet 底部按鈕列：可選刪除鈕、缺欄提示、取消、儲存。外距(padding)刻意留呼叫端決定。
struct EditorSheetFooter: View {
    var onDelete: (() -> Void)? = nil
    var hint: String? = nil
    var saveDisabled: Bool = false
    let onCancel: () -> Void
    let onSave: () -> Void

    var body: some View {
        HStack {
            if let onDelete {
                Button("刪除", role: .destructive, action: onDelete)
            }
            if let hint {
                Text(hint).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button("取消", action: onCancel)
                .keyboardShortcut(.cancelAction)
            Button("儲存", action: onSave)
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(saveDisabled)
        }
    }
}

/// 複製按鈕，附本地「已複製」回饋。用於 sheet 內（全域 toast 會被 modal 遮住）。
struct CopyButton: View {
    let title: LocalizedStringKey
    var copiedTitle: LocalizedStringKey = "已複製"
    let action: () -> Void
    @State private var copied = false

    var body: some View {
        Button {
            action()
            copied = true
        } label: {
            Text(copied ? copiedTitle : title)
        }
        .task(id: copied) {
            guard copied else { return }
            try? await Task.sleep(for: .seconds(1.5))
            copied = false
        }
    }
}
