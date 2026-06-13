<div align="center">

# ShadowSpace

**台灣用語友善的 macOS 代理工具：選單列常駐、SwiftUI 介面、支援原生與完整引擎雙路線**

![platform](https://img.shields.io/badge/macOS-14%2B-blue)
![license](https://img.shields.io/badge/license-GPL--3.0-green)
![swift](https://img.shields.io/badge/Swift-6-orange)

</div>

ShadowSpace 是一款 Shadowrocket 風格的 macOS 代理工具。它保留簡單的一鍵連線體驗，並提供兩條清楚的版本路線：

| 路線 | 用途 | 引擎 | 狀態 |
|---|---|---|---|
| Developer ID 直發版 | 給需要完整協議、TUN、系統代理控制的使用者 | `sing-box（完整）`，也可切換 `原生` | 以公證 DMG 發佈 |
| Mac App Store 版 | 給沙箱環境與審查相容的透明代理版本 | `ShadowCore` + `NetworkExtension` | 開發中 |

<div align="center">
<img src="docs/screenshot-main.png" width="560" alt="ShadowSpace 主視窗">
</div>

## 下載

到 **[Releases](https://github.com/voidful/shadowspace/releases)** 下載最新 `.dmg`，拖進「應用程式」即可。直發版使用 Developer ID 簽章與 Apple 公證，第一次開啟應可通過 Gatekeeper。

## 功能

### 共用體驗

- 一鍵連線：首頁大圓鈕，連線與中斷狀態清楚
- 三種模式：規則、全域、直連
- 匯入分享連結與訂閱：支援常見節點 URI、base64 訂閱與剪貼簿匯入
- 節點管理：手動新增、編輯、複製分享連結、QR Code 匯出
- 分流規則：網域後綴、網域關鍵字、完整網域、IP CIDR，策略可選代理、直連、拒絕
- 訂閱管理：剩餘流量、到期日、一鍵更新、定時自動更新
- 選單列常駐：快速連線、切換模式、切換節點、查看流量
- 本機資料：設定與節點存在 `~/Library/Application Support/ShadowSpace/`

### 原生引擎 / App Store 版

- 使用純 Apple 框架實作的 `ShadowCore`，不依賴外部代理核心
- 支援 Shadowsocks、Trojan、VLESS、SOCKS5
- 支援 TCP、TLS、WebSocket / WSS
- App Store 版可使用 `NETransparentProxyProvider`，以透明代理方式接流量
- App Store 版的 extension 已補 UDP flow 與 DNS 分流骨架；DNS 可依 Router policy 走 direct / proxy / reject
- 不支援 Reality、VMess、Hysteria2、TUIC、WireGuard、TUN、GeoIP / Geosite 與 DoH / DoT 分流

更多原生核心細節見 [Sources/ShadowCore/README.md](Sources/ShadowCore/README.md)。

### sing-box 完整引擎 / Developer ID 路線

- 支援 Shadowsocks、VMess、VLESS（含 Reality）、Trojan、Hysteria2、TUIC、SOCKS5、WireGuard
- 支援 TUN / 增強模式，可接管終端機、Docker 等不吃系統代理的流量
- 可自動設定系統代理，也可手動指向 `127.0.0.1:7890`
- 支援 GeoIP / Geosite、程序名稱規則、一鍵廣告阻擋
- 支援遠端 / 直連 DNS 分流，包含 DoH 與 DoT
- 第一次連線可自動下載官方 `sing-box` 核心；發佈版建議先內嵌核心

## 系統需求

- macOS 14 Sonoma 以上
- 編譯需要 Xcode 或 Command Line Tools
- App Store 版實機測試需要 Apple 核准的 Network Extensions capability 與 App Group 佈建描述檔

## 快速開始

```bash
make setup
make run
```

`make setup` 會下載 `sing-box` 核心、編譯並打包 `.app`。如果只想跑開發版：

```bash
make dev
```

第一次使用：

1. 複製你的節點分享連結或訂閱網址。
2. 開啟 ShadowSpace，點「從剪貼簿匯入」。
3. 回首頁選節點與模式，按下連線按鈕。

Developer ID 直發版可在「設定」切換代理引擎：

- `原生（App Store）`：預設路線，純 Swift / Apple framework，適合 SS / Trojan / VLESS / SOCKS5。
- `sing-box（完整）`：完整協議與 TUN 能力，適合需要 Reality、Hysteria2、TUIC、WireGuard 或 GeoIP / Geosite 的使用者。

## App Store 版

App Store 版採 Apple NetworkExtension（透明代理）實作，目前開發中。

## 常見問題

**直發版和 App Store 版差在哪？**  
直發版可使用完整 `sing-box` 能力，包含 TUN、系統代理設定與更多協議；App Store 版必須符合沙箱與審查規則，因此改用 `NetworkExtension` 和原生核心，功能範圍較保守。

**第一次連線很慢？**  
使用 `sing-box（完整）` 時，首次連線可能會下載核心引擎與分流規則檔；之後就會快很多。發佈版建議用 `make engine` 先內嵌核心。

**設定系統代理失敗？**  
修改網路設定需要管理員帳號。也可以關掉「連線時自動設定系統代理」，手動把 HTTP / SOCKS 代理指到 `127.0.0.1:7890`。App Store 版不使用這條路徑，而是由 NetworkExtension 接管。

**和 Shadowrocket 一樣有 VPN / TUN 模式嗎？**  
Developer ID 直發版的 `sing-box（完整）` 引擎支援 TUN / 增強模式。App Store 版使用 App Proxy Provider 透明代理，不包含 TUN 管理員模式。

**訂閱匯入失敗？**  
目前支援 base64 節點清單格式。Clash YAML 專用訂閱仍待補，可先請服務提供者給 Shadowrocket / V2Ray 通用訂閱連結。

## 專案結構

```text
Sources/
├── ShadowCore/                       # 純 Apple framework 原生代理核心
├── ShadowSpace/                      # App 進入點
├── ShadowSpaceKit/                   # SwiftUI UI、AppState、設定與引擎橋接
└── shadow-demo/                      # ShadowCore smoke test executable

Tests/
├── ShadowCoreTests/
└── ShadowSpaceKitTests/

scripts/
├── fetch-singbox.sh
├── generate-appstore-xcodeproj.rb
├── appstore-preflight.sh
├── sign.sh
├── make-dmg.sh
└── notarize.sh
```

## 開發

```bash
swift test
make dev
make app
make engine
```

常用命令：

- `swift test`：單元測試
- `make dev`：直接執行開發版
- `make app`：打包 `build/ShadowSpace.app`
- `make engine`：下載並內嵌 `sing-box`

## 發佈

直發版使用 **Developer ID 簽章 + Apple 公證 + DMG**。完整步驟見 [PACKAGING.md](PACKAGING.md)。

```bash
make engine
make release SIGN_IDENTITY="Developer ID Application: 你的名字 (TEAMID)"
```

完成後會產出 `build/ShadowSpace-<版本>.dmg`。不帶 `SIGN_IDENTITY` 時會使用 ad-hoc 簽章，僅適合本機測試，不能拿來對外發佈。

## 路線圖

- [x] 原生 ShadowCore 引擎
- [x] sing-box 完整引擎
- [x] TUN / 增強模式
- [x] 規則編輯器與一鍵廣告阻擋
- [x] 連線檢視器
- [x] 節點編輯、分享連結與 QR Code 匯出
- [x] DNS 自訂與訂閱自動更新
- [x] App Store 版（NetworkExtension）
- [ ] App Store 已核准 entitlement 的實機透明代理測試
- [ ] Clash YAML 訂閱格式
- [ ] QR Code 掃描匯入
- [ ] 多語系 UI
- [ ] Sparkle 自動更新

## 授權

本專案以 **[GPL-3.0](LICENSE)** 釋出。

Developer ID 直發版可使用 [sing-box](https://github.com/SagerNet/sing-box)（GPLv3）作為獨立、未修改的子程序；二進位檔來自官方 GitHub Releases，發佈版可內嵌於 `.app`。分流規則集來自 [sing-geosite](https://github.com/SagerNet/sing-geosite) 與 [sing-geoip](https://github.com/SagerNet/sing-geoip)。

Mac App Store 版改用 `ShadowCore` 與 Apple `NetworkExtension`，不包含 `sing-box`、外部核心下載或管理員授權流程。
