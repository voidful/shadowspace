<div align="center">
<img src="Resources/AppIcon.png" width="128" alt="ShadowSpace">

# ShadowSpace ✈️

**Shadowrocket 風格的 macOS 代理工具——介面簡單、功能豐富、對新手友善**

![platform](https://img.shields.io/badge/macOS-14%2B-blue)
![license](https://img.shields.io/badge/license-GPL--3.0-green)
![swift](https://img.shields.io/badge/Swift-6-orange)

</div>

原生 SwiftUI 打造（選單列 + 主視窗），核心使用 [sing-box](https://github.com/SagerNet/sing-box) 引擎，協議支援度與 Shadowrocket 對齊。

<div align="center">
<img src="docs/screenshot-main.png" width="560" alt="ShadowSpace 主視窗">
</div>

## 下載

到 **[Releases](https://github.com/voidful/shadowspace/releases)** 下載最新的 `.dmg`，拖進「應用程式」即可。已經過 Apple 公證，首次開啟不會跳安全警告。

> 想自行從原始碼建置？見下方[快速開始](#快速開始)。

## 功能

- **一鍵連線**：首頁大圓鈕，連線時自動設定系統代理、中斷時自動還原
- **TUN／增強模式**：建立虛擬網卡接管「全部」流量（含終端機與不吃系統代理的 App），
  如同 Shadowrocket 的 VPN 模式；連線時輸入一次管理員密碼即可
- **三種模式**：規則（中國大陸網站直連、其餘走代理）／全域／直連，連線中可熱切換、不需重啟
- **協議支援**：Shadowsocks、VMess、VLESS（含 Reality）、Trojan、Hysteria2、TUIC、SOCKS5、WireGuard
- **分流規則編輯器**：網域後綴／關鍵字／IP 區段／GeoIP／Geosite／程序名稱，
  策略可選代理、直連、拒絕，拖曳排序；內建**一鍵廣告阻擋**
- **連線檢視器**：即時顯示每條連線的目標、命中規則、出口節點與流量，可強制中斷
- **匯入超簡單**：複製分享連結後點「從剪貼簿匯入」，自動辨識節點連結與訂閱網址
- **節點管理**：手動新增／編輯表單、複製分享連結、QR Code 匯出（給手機掃）
- **訂閱管理**：機場 base64 訂閱、剩餘流量與到期日、一鍵更新、定時自動更新
- **延遲測試**：未連線時 TCP 測試、連線中走引擎做真實 URL 測試，綠橘紅燈號顯示
- **DNS 自訂**：遠端／直連 DNS 分流，支援 DoH 與 DoT，避免 DNS 污染
- **即時流量**：上下行速率與本次連線總量（首頁 + 選單列）
- **自動裝引擎**：第一次連線自動下載 sing-box 官方核心，不用碰終端機
- **選單列常駐**：關掉視窗也能從 ✈️ 圖示快速開關、切模式、換節點

## 系統需求

- macOS 14（Sonoma）以上
- 編譯需要 Xcode（或 Command Line Tools）

## 快速開始

```bash
make setup   # 下載 sing-box 核心 + 編譯 + 打包
make run     # 啟動 ShadowSpace
```

> 跳過引擎下載也可以：直接 `make run`，App 會在第一次連線時自動下載核心。

### 新手三步驟

1. 複製你的節點分享連結（`ss://`、`vmess://`、`trojan://`…）或機場訂閱網址
2. 開啟 ShadowSpace，點「**從剪貼簿匯入**」
3. 回到首頁按下**大圓鈕**，完成 🎉

連線後系統代理會自動指向本機（預設連接埠 7890），瀏覽器與多數 App 立即生效。

## 常見問題

**第一次連線很慢？**
首次連線會下載核心引擎與分流規則檔（geosite/geoip），之後就快了。

**設定系統代理失敗？**
修改網路設定需要管理員帳號。也可以關掉「自動設定系統代理」，
手動把應用程式的代理指到 `127.0.0.1:7890`（HTTP 與 SOCKS5 共用）。

**訂閱匯入失敗？**
目前支援 base64 節點清單格式（Shadowrocket / V2Ray 通用格式）。
Clash YAML 專用訂閱還在開發中，可先請機場提供通用訂閱連結。

**和 Shadowrocket 一樣有 VPN（TUN）模式嗎？**
有。到「設定」開啟「TUN 模式（增強模式）」，連線時輸入一次管理員密碼，
之後中斷連線、關閉 App 都不用再輸入（背後用哨兵檔案＋看門狗機制管理 root 引擎，
App 就算閃退也不會留下殘留程序）。一般情況下系統代理模式就涵蓋瀏覽器與多數 App，
需要讓終端機、Docker 等也走代理時再開 TUN。

## 專案結構

```
Sources/
├── ShadowSpace/          # 進入點
└── ShadowSpaceKit/
    ├── App/              # AppState（狀態中樞）、App 生命週期
    ├── Core/             # URI 解析、設定檔產生、引擎管理、系統代理、延遲測試
    ├── Models/           # 節點 / 訂閱 / 設定資料模型
    └── Views/            # 首頁、節點、設定、日誌、選單列
```

架構：GUI 以子程序方式啟動 sing-box，透過 Clash API（`127.0.0.1:9090`）做
節點切換、模式熱切換與流量串流。設定與狀態存於
`~/Library/Application Support/ShadowSpace/`。

## 開發

```bash
swift test    # 單元測試（URI 解析、設定檔產生）
make dev      # 開發模式直接執行（不打包）
make app      # 打包 build/ShadowSpace.app
```

## 發佈

以 **Developer ID 簽章 + Apple 公證 + DMG** 對外散佈（不走 App Store——沙箱會封鎖
sing-box 子程序、系統代理與 TUN，且 GPLv3 與 App Store 條款不相容）。完整步驟見
[PACKAGING.md](PACKAGING.md)，簡述：

```bash
make engine                                                   # 內嵌核心
make release SIGN_IDENTITY="Developer ID Application: 你的名字 (TEAMID)"
```

會自動完成簽章 → 公證 `.app` → 打包 → 公證 DMG，產出 `build/ShadowSpace-<版本>.dmg`。
不帶 `SIGN_IDENTITY` 時為 ad-hoc 簽章，僅供本機測試。

## 路線圖

- [x] TUN／VPN 模式（全域接管）
- [x] 規則編輯器（自訂網域 / IP / GeoIP / 程序分流規則）＋廣告阻擋
- [x] 連線檢視器
- [x] 節點手動編輯表單、分享連結與 QR Code 匯出
- [x] DNS 自訂（DoH / DoT）與訂閱自動更新
- [x] App 圖示
- [x] 選單列 VPN 狀態顯示
- [ ] Clash YAML 訂閱格式
- [ ] QR Code 掃描匯入（讀取螢幕上的 QR）
- [ ] 多語系（English UI）
- [ ] Sparkle 自動更新

## 授權

本專案以 **[GPL-3.0](LICENSE)** 釋出。

核心引擎 [sing-box](https://github.com/SagerNet/sing-box)（GPLv3）以獨立、未修改的子程序方式執行，二進位檔來自官方 GitHub Releases，發佈版內嵌於 `.app`。分流規則集來自 [sing-geosite](https://github.com/SagerNet/sing-geosite) 與 [sing-geoip](https://github.com/SagerNet/sing-geoip)。
