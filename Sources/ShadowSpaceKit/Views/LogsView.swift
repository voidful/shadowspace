import SwiftUI
import AppKit

struct LogsView: View {
    @EnvironmentObject private var state: AppState
    @State private var autoScroll = true

    var body: some View {
        Group {
            if state.engineLog.isEmpty {
                ContentUnavailableView {
                    Label("尚無日誌", systemImage: "doc.text")
                } description: {
                    Text("連線後，核心引擎的執行紀錄會顯示在這裡。")
                }
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 2) {
                            ForEach(state.engineLog) { line in
                                Text(line.text)
                                    .font(.caption.monospaced())
                                    .textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .id(line.id)
                            }
                        }
                        .padding(12)
                    }
                    // 追蹤最後一行的 id 而非 count——環形緩衝裁剪後 count 恆為 800、永不觸發。
                    .onChange(of: state.engineLog.last?.id) { _, id in
                        if autoScroll, let id {
                            proxy.scrollTo(id, anchor: .bottom)
                        }
                    }
                }
            }
        }
        .navigationTitle("日誌")
        .toolbar {
            ToolbarItemGroup {
                Toggle(isOn: $autoScroll) {
                    Label("自動捲動", systemImage: "arrow.down.to.line")
                }
                .help("自動捲動到最新日誌")
                Button {
                    NSPasteboard.copyString(state.engineLog.map(\.text).joined(separator: "\n"))
                    state.toastMessage = "日誌已複製"
                } label: {
                    Label("複製全部", systemImage: "doc.on.doc")
                }
                .disabled(state.engineLog.isEmpty)
                Button {
                    state.engineLog.removeAll()
                } label: {
                    Label("清除", systemImage: "trash")
                }
                .disabled(state.engineLog.isEmpty)
            }
        }
    }
}
