# 發佈打包指南

ShadowSpace 以 **Developer ID 簽章 + Apple 公證（Notarization）+ DMG** 對外發佈，
跟 Clash Verge、ShadowsocksX-NG 等同類工具相同。使用者下載後 Gatekeeper 直接放行。

> **為什麼不上 Mac App Store？**
> App Store 強制沙箱，會封鎖本專案的三個核心能力：① 執行下載／內嵌的 sing-box 子程序、
> ② 用 `networksetup` 設定系統代理、③ TUN 模式的管理員授權。此外 sing-box 為 GPLv3，
> 與 App Store 條款不相容（VLC 當年被下架即此因）。上架需改寫成 NetworkExtension + libbox
> 框架並解決授權問題，等於另一個 App。Developer ID 發佈沒有上述限制。

---

## 一次性準備

### 1. 建立 Developer ID Application 憑證

你目前的憑證（`security find-identity -v -p codesigning` 可查）：

| 憑證 | 用途 | 能否公證 DMG |
|---|---|---|
| Apple Development | 開發測試 | ❌ |
| Apple Distribution | App Store 上架 | ❌ |
| **Developer ID Application** | **App Store 外發佈** | ✅ ← 需要這張 |

建立方式（需為團隊的 Account Holder / Admin）：

- **Xcode**：設定 → Accounts → 選團隊 → Manage Certificates → 左下「＋」→ **Developer ID Application**
- 或 **網頁**：<https://developer.apple.com/account/resources/certificates> → ＋ → Developer ID Application

建好後再次執行 `security find-identity -v -p codesigning`，會多一行
`Developer ID Application: 你的名字 (TEAMID)`，整段就是要填的 `SIGN_IDENTITY`。

### 2. 儲存公證憑證

先到 <https://appleid.apple.com> → 登入與安全性 → App 專用密碼，產生一組。

```bash
xcrun notarytool store-credentials ShadowSpaceNotary \
    --apple-id "你的 AppleID 信箱" \
    --team-id "TEAMID" \
    --password "剛產生的 App 專用密碼"
```

`TEAMID` 是上面憑證括號內那串（例如 Developer ID 憑證顯示的 10 碼）。
存一次即可，之後 `make release` 會自動使用。

---

## 發佈

```bash
make engine                                                   # 下載並內嵌 sing-box 核心
make release SIGN_IDENTITY="Developer ID Application: 你的名字 (TEAMID)"
```

`make release` 會依序：

1. 編譯 release → 組裝 `.app` → 內嵌核心
2. 由內而外用 Hardened Runtime 簽署（先簽 sing-box，再簽 App）
3. 公證 `.app` 並 staple 票證
4. 打包並簽署 `ShadowSpace-<版本>.dmg`
5. 公證 DMG 並 staple

完成後得到 `build/ShadowSpace-0.2.1.dmg`，可直接散佈。

### 驗證成品

```bash
spctl -a -vvv --type execute build/ShadowSpace.app   # 應顯示 accepted / Notarized Developer ID
xcrun stapler validate build/ShadowSpace-0.2.1.dmg   # 應顯示 The validate action worked
```

---

## 分段執行（除錯用）

```bash
make app SIGN_IDENTITY="Developer ID Application: ..."   # 只簽 .app
make sign SIGN_IDENTITY="Developer ID Application: ..."  # 重簽既有 bundle
make notarize                                           # 只公證 .app
make dmg SIGN_IDENTITY="Developer ID Application: ..."   # 只打包 DMG
```

不帶 `SIGN_IDENTITY` 時一律用 ad-hoc 簽章，可在本機跑、但**無法公證、無法給別台 Mac**。

---

## 發版前檢查清單

- [ ] 更新 `Resources/Info.plist` 的 `CFBundleShortVersionString` 與 `CFBundleVersion`
- [ ] `make test` 全綠
- [ ] `make engine` 確認核心為最新版
- [ ] （建議）加上 App 圖示，見下方
- [ ] `make release …` 並用 `spctl` / `stapler validate` 驗證
- [ ] 在**另一台**沒裝過開發工具的 Mac 上實測下載開啟

---

## 之後可補強

- **App 圖示**：已內建（火箭穿越星空）。換圖時把新的 1024² PNG 丟進 `Resources/`，執行
  `swift scripts/round-icon.swift 你的圖.png Resources/AppIcon.png`（自動裁掉外框、套透明圓角），
  再 `./scripts/make-icon.sh`，之後 `make app` 會自動嵌入。原始方圖留存於 `Resources/AppIcon-source.png`。
- **自動更新**：整合 [Sparkle](https://sparkle-project.org)（需自架 appcast 與 EdDSA 簽章）。
- **CI 出版**：把上述流程搬到 GitHub Actions，憑證用 base64 存進 Secrets，標 tag 自動出 DMG。
