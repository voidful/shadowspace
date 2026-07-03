# 變更紀錄

版本依語意化版本（SemVer）。

## v0.4.2

### 修正
- **原生 XTLS Vision（`flow=xtls-rprx-vision`）完整可用**：修復切換後資料流損毀、HTTP/2 與大檔傳輸失敗的問題。
  XTLS Vision 在偵測到內層 TLS 握手完成後，會切換為 **TLS splice**——之後兩個方向都裸傳內層 TLS record、
  繞過外層 TLS（避免雙重加密）。先前原生實作在切換後仍以外層 TLS 讀寫，導致上行/下行資料錯位（外層解密
  失敗、內層 record MAC 錯誤），表現為「HTTP/1.1 小回應僥倖可用、HTTP/2 與大檔下載/上傳全損」。現已在自建
  TLS 1.3 上實作**對稱 splice**（切 Direct 後改讀/寫原始 TCP），vision 節點恢復由原生引擎處理。
  已對本機與真實節點逐 byte 驗證：h1/h2、雙向 128 KB、108 KB 檔上傳下載皆無誤。vision 一律走 nativeTLS
  （splice 依賴自建 TLS，Apple `NWProtocolTLS` 無法配合）。

## v0.4.1

### 修正
- **修復連上 VLESS XTLS Vision（`flow=xtls-rprx-vision`）節點後所有流量損毀、系統網路卡死（「打開就當機」）的問題**：
  原生引擎的 Vision 實作尚未對真機驗證、會破壞資料流，已暫停用。改為在連線時，原生引擎不支援的節點
  （XTLS Vision / Hysteria2 / TUIC 等）自動改用 sing-box 引擎，避免「連上卻通不了」。原生支援的節點
  （ws / SS / SS-2022 / Trojan / flow-less REALITY）仍走原生引擎。

## v0.4.0

### 新增（原生引擎抗封鎖堆疊，純 Apple 框架、零 sing-box）
- **自建 TLS 1.3 客戶端**：以 CryptoKit 在原始 TCP 上實作可控 ClientHello 的 TLS 1.3，
  取代不可自訂握手的 `NWProtocolTLS`，把外層握手偽裝成瀏覽器指紋；macOS 26+ 送現代 Chrome
  的後量子 X25519MLKEM768 混合金鑰。金鑰排程對 RFC 8448 測試向量逐 byte 驗證。原生引擎
  預設對 Trojan / VLESS 的 TCP+TLS 啟用（可於設定關閉），並提供指紋選擇（Chrome/Safari…）。
- **REALITY**：原生支援 VLESS REALITY（authKey 衍生、session_id 認證封裝、HMAC-SHA512 憑證
  驗證），抗主動探測。
- **XTLS Vision**：原生支援 `flow=xtls-rprx-vision`（padding / TLS-in-TLS 過濾 / direct 切換），
  打散內層握手的長度與時序特徵。（v0.4.1 因互通問題暫停用；v0.4.2 補上 TLS splice 後恢復原生處理。）
- **Shadowsocks-2022**：原生支援 `2022-blake3-aes-128/256-gcm`（TCP 與 AES 系 UDP），含純 Swift
  BLAKE3（對官方測試向量驗證）。
- **原生 UDP 子系統**：SOCKS5 UDP ASSOCIATE 入站 + UDP relay，支援 Direct 與 SS-2022 UDP 出站，
  讓原生引擎可代理 UDP（QUIC/HTTP3、DNS 等）。
- sing-box 引擎：TLS 節點未指定指紋時預設套用 uTLS `chrome`，對齊 Shadowrocket 的抗指紋作法。

## v0.3.2

### 修正
- **原生引擎自迴圈根治**：原生引擎的出站連線不再遵循系統代理（`preferNoProxies`），
  避免「系統代理指向引擎自己 → 出站被繞回引擎」造成的連線後完全沒網路。比先前
  只把節點主機加進 bypass 的修補更徹底，direct／規則模式命中直連的流量也不再迴圈。
- **VPN 開關殘留修正**：系統代理只設在主要網路服務，不再污染 Tailscale／Surfshark
  等其他服務，且關閉時徹底還原（清掉本機代理與 bypass 例外清單）；網路切換時代理
  跟著主要服務搬。
- **啟動校正**：上次強制結束／閃退若殘留系統代理或孤兒引擎，啟動時自動清除，回到
  乾淨的未連線狀態；啟動引擎前先清孤兒程序，避免埠衝突導致開不起來。

## v0.2.1

### 新增
- 原生引擎的 NetworkExtension 透明代理補上 UDP flow 與 DNS 分流處理。
- ShadowCore 新增 datagram session 介面，Direct outbound 可做 UDP 直連，為透明代理 DNS / UDP 路徑鋪路。

### 改進
- NetworkExtension 透明代理改用共享設定目錄與 tunnel payload 啟動流程，與 sing-box / 系統代理流程分離。
- 設定頁版本改讀取 bundle metadata，之後發版不需同步硬編碼版本字串。

## v0.2.0

功能對齊 Shadowrocket 核心能力，維持簡潔的分頁式介面。

### 新增
- **TUN／增強模式**：虛擬網卡接管全部流量（含終端機、Docker 等不吃系統代理的程式）。連線時輸入一次管理員密碼；以哨兵檔案＋看門狗管理 root 引擎，中斷或 App 閃退都不殘留程序。
- **分流規則編輯器**：網域後綴／關鍵字／完整網域／IP 區段／GeoIP／Geosite／程序名稱，策略可選代理／直連／拒絕，可拖曳排序。
- **一鍵廣告阻擋**：AdGuard 網域清單，所有模式皆生效。
- **連線檢視器**：即時顯示每條連線的目標、命中規則、出口節點與流量，可單條或全部中斷。
- **節點手動新增／編輯表單**，依協議動態顯示欄位。
- **分享節點**：複製分享連結、產生 QR Code。
- **DNS 自訂**：遠端／直連 DNS 分流，支援 DoH 與 DoT。
- **訂閱定時自動更新**（6／12／24 小時）。
- **選單列 VPN 狀態**：圖示三態（已連線／連線中／未連線），下拉面板顯示模式、節點與即時流量。
- **App 圖示**（火箭穿越星空）。

### 改進
- 延遲測試：連線中改用引擎做真實 URL 測試，未連線時用 TCP。
- 首頁加上本次連線流量總量。
- 設定檔向後相容，升級不丟失既有節點與設定。

## v0.1.0

- 首個版本：一鍵連線、三種模式（規則／全域／直連）、系統代理自動設定。
- 協議：Shadowsocks、VMess、VLESS（含 Reality）、Trojan、Hysteria2、TUIC、SOCKS5。
- 訂閱與分享連結匯入、TCP 延遲測試、即時流量、選單列常駐。
- 首次連線自動下載 sing-box 核心。
