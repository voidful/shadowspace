import SwiftUI
import Charts

/// 首頁：大開關 + 模式 + 目前節點 + 流量，一眼看懂、一鍵連線。
struct HomeView: View {
    @EnvironmentObject private var state: AppState
    @EnvironmentObject private var traffic: TrafficStatsStore

    /// 首頁卡片統一寬度上限。
    private let cardMaxWidth: CGFloat = 460

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                connectButton
                statusText

                ProxyModePicker(state: state)
                    .labelsHidden()
                    .frame(maxWidth: 300)
                    .help("規則：依分流規則決定直連或代理；全域：全部走代理；直連：全部不走代理")

                if state.nodes.isEmpty {
                    firstRunCard
                } else {
                    nodeCard
                    if state.connectionState == .connected {
                        trafficCard
                    }
                }
                Spacer(minLength: 0)
            }
            .padding(28)
            .frame(maxWidth: .infinity)
        }
        .navigationTitle("首頁")
    }

    // MARK: - 連線大按鈕

    private var connectButton: some View {
        Button {
            state.toggleConnection()
        } label: {
            ZStack {
                Circle()
                    .fill(buttonGradient)
                    .frame(width: 130, height: 130)
                    .shadow(color: buttonShadow, radius: 16, y: 6)
                if state.connectionState == .connecting || state.connectionState == .stopping {
                    ProgressView()
                        .controlSize(.large)
                        .tint(.white)
                } else {
                    Image(systemName: "power")
                        .font(.system(size: 44, weight: .semibold))
                        .foregroundStyle(.white)
                }
            }
        }
        .buttonStyle(.plain)
        .disabled(state.connectionState == .stopping)
        .animation(.easeInOut(duration: 0.25), value: state.connectionState)
        .accessibilityLabel(state.connectionState == .connected ? "中斷連線" : "連線")
        .accessibilityValue(state.connectionState.label)
        .help(state.connectionState == .connected ? "中斷代理連線" : "啟動代理連線")
    }

    private var buttonGradient: LinearGradient {
        let colors: [Color] = state.connectionState == .connected
            ? [Color.blue, Color.cyan]
            : [Color(nsColor: .systemGray), Color(nsColor: .darkGray)]
        return LinearGradient(colors: colors, startPoint: .topLeading, endPoint: .bottomTrailing)
    }

    private var buttonShadow: Color {
        state.connectionState == .connected ? Color.blue.opacity(0.45) : Color.black.opacity(0.18)
    }

    private var statusText: some View {
        VStack(spacing: 4) {
            Text(state.connectionState.label)
                .font(.title3.weight(.semibold))
            if state.isInstallingEngine, let status = state.engineInstallStatus {
                Text("首次連線需要下載核心引擎：\(status)")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            } else if state.connectionState == .connected {
                Text(state.transportStatusSentence)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            if state.connectionState == .connecting {
                Text("按一下大按鈕可取消")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .multilineTextAlignment(.center)
    }

    // MARK: - 目前節點卡片

    private var nodeCard: some View {
        GroupBox {
            HStack(spacing: 10) {
                if let group = state.selectedGroup {
                    Image(systemName: group.type.icon)
                        .foregroundStyle(Color.accentColor)
                        .frame(width: 28)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(group.name).fontWeight(.medium).lineLimit(1)
                        Text("\(group.type.displayName) · \(group.memberNodeIDs.count) 個節點")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                    Spacer()
                    outboundSwitchMenu
                } else if let node = state.selectedNode {
                    ProtocolBadge(proto: node.proto)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(node.name).fontWeight(.medium).lineLimit(1)
                        Text("\(node.server):\(String(node.port))")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                    Spacer()
                    LatencyBadge(ms: state.latencies[node.id])
                    outboundSwitchMenu
                }
            }
            .padding(6)
        } label: {
            Text("目前出口").foregroundStyle(.secondary)
        }
        .frame(maxWidth: cardMaxWidth)
    }

    private var outboundSwitchMenu: some View {
        Menu("切換") {
            OutboundMenuContent(state: state)
        }
        .fixedSize()
    }

    // MARK: - 流量卡片

    private var trafficCard: some View {
        GroupBox {
            VStack(spacing: 8) {
                HStack(spacing: 32) {
                    Label {
                        Text(traffic.upRate.rateString).monospacedDigit()
                    } icon: {
                        Image(systemName: "arrow.up").foregroundStyle(.orange)
                    }
                    Label {
                        Text(traffic.downRate.rateString).monospacedDigit()
                    } icon: {
                        Image(systemName: "arrow.down").foregroundStyle(.green)
                    }
                }
                .font(.title3)
                Text("本次共 ↑ \(traffic.sessionUpTotal.byteString) · ↓ \(traffic.sessionDownTotal.byteString)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
                if traffic.trafficHistory.count > 1 {
                    trafficChart
                }
            }
            .padding(6)
            .frame(maxWidth: .infinity)
        } label: {
            Text("即時流量").foregroundStyle(.secondary)
        }
        .frame(maxWidth: cardMaxWidth)
    }

    /// 即時流量折線圖（上傳橘、下載綠），X 軸為取樣序號。
    private var trafficChart: some View {
        Chart {
            ForEach(traffic.trafficHistory) { s in
                AreaMark(x: .value("序", s.seq), y: .value("速率", s.down))
                    .foregroundStyle(.green.opacity(0.12))
                    .interpolationMethod(.monotone)
            }
            ForEach(traffic.trafficHistory) { s in
                LineMark(x: .value("序", s.seq), y: .value("速率", s.down))
                    .foregroundStyle(by: .value("方向", "下載"))
                    .interpolationMethod(.monotone)
            }
            ForEach(traffic.trafficHistory) { s in
                LineMark(x: .value("序", s.seq), y: .value("速率", s.up))
                    .foregroundStyle(by: .value("方向", "上傳"))
                    .interpolationMethod(.monotone)
            }
        }
        .chartForegroundStyleScale(["下載": Color.green, "上傳": Color.orange])
        .chartLegend(.hidden)
        .chartXAxis(.hidden)
        .chartYAxis {
            AxisMarks(position: .leading, values: .automatic(desiredCount: 3)) { value in
                AxisGridLine()
                AxisValueLabel {
                    if let v = value.as(Int.self) { Text(v.rateString).font(.caption2) }
                }
            }
        }
        .frame(height: 96)
        .padding(.top, 4)
    }

    // MARK: - 新手引導

    private var firstRunCard: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                Label("三步驟開始使用", systemImage: "sparkles")
                    .font(.headline)
                VStack(alignment: .leading, spacing: 8) {
#if APP_STORE
                    Text("1️⃣  複製你的節點分享連結（ss://、trojan://、vless://、socks://）或訂閱網址")
#else
                    Text("1️⃣  複製你的節點分享連結（ss:// vmess:// trojan://…）或機場訂閱網址")
#endif
                    Text("2️⃣  點下方按鈕，自動辨識並匯入")
                    Text("3️⃣  回到這裡按下大圓鈕，完成連線")
                }
                .font(.callout)
                .foregroundStyle(.secondary)
                ImportFromClipboardButton(state: state)
                    .controlSize(.large)
                    .buttonStyle(.borderedProminent)
            }
            .padding(10)
        }
        .frame(maxWidth: cardMaxWidth)
    }
}
