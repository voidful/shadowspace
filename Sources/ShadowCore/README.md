# ShadowCore — 全原生代理核心

純 Apple 框架（Network.framework + CryptoKit + CommonCrypto）實作的代理核心，**不依賴 sing-box**。
目的：讓 ShadowSpace 不必下載或內嵌外部核心即可代理，啟動輕量、無 GPLv3 授權牽連，
並具備抗主動探測 / TLS-in-TLS 偵測的完整協議能力。

## 支援矩陣

| 類別 | 已支援 | 說明 |
|---|---|---|
| 入站 | SOCKS5（CONNECT + UDP ASSOCIATE）、HTTP（CONNECT + 明文） | 本地混合伺服器，依首位元組分流；UDP relay 見下 |
| 出站 (TCP) | Direct、Shadowsocks、Shadowsocks-2022、Trojan、VLESS、SOCKS5 | SS 用 CryptoKit AEAD；Trojan 用 CommonCrypto SHA-224 |
| 出站 (UDP) | Direct、Shadowsocks-2022（AES 系） | 多工 `UDPRelaySession`（每封包自帶目標）|
| 傳輸 | TCP、TLS、WebSocket（ws/wss） | `TransportConfig` / `Transport.dial` |
| **自建 TLS 1.3** | 可控 ClientHello（瀏覽器指紋）、macOS 26+ 送後量子 X25519MLKEM768 | `NativeTLS13Client`，取代不可自訂的 `NWProtocolTLS`；金鑰排程對 RFC 8448 驗證 |
| **REALITY** | authKey(HKDF) + session_id 認證 + HMAC-SHA512 憑證驗證 | 依 Xray-core 線格式；`Reality.swift` |
| **XTLS Vision** | flow=xtls-rprx-vision（padding / TLS-in-TLS filter / direct 切換）| `Vision.swift`；藏內層握手長度特徵 |
| **BLAKE3** | hash / keyed_hash / derive_key | 純 Swift，對官方 test_vectors.json 驗證；SS-2022 金鑰衍生用 |
| 路由 | domain suffix/keyword/exact、IP CIDR、reject、final | 由上而下，命中即止 |

> 「自建 TLS 1.3 + REALITY + Vision」讓原生引擎能像 Shadowrocket 一樣偽裝 TLS 指紋、
> 抗主動探測與 TLS-in-TLS 統計偵測——這是早期版本因 `NWProtocolTLS` 無法自訂握手而做不到、
> 現以自建 TLS 1.3 客戶端解決的能力。

## 刻意不支援 / 走 sing-box

- **Hysteria2 / TUIC**：需自訂 QUIC 壅塞控制與混淆，Apple 的 QUIC 是黑盒。
- **gRPC（gun）**：需全雙工 HTTP/2 雙向串流，Network.framework 無公開 HTTP/2；WebSocket 已涵蓋多數 CDN 傳輸需求。
- **WireGuard**：L3 VPN（需 IP 封包 + userspace TCP/IP stack），與 flow 式代理架構不合；走 sing-box。
- **VMess**：純 Apple 框架可行但已被 VLESS 取代，暫緩。
- **SS-2022 chacha20 UDP**：UDP 構造與 AES 系不同，暫未實作（TCP 全支援；AES 系 UDP 已支援）。

> 需要上述協議的使用者，請在「設定」切換到 sing-box 引擎（功能完整）。

## 端到端驗證狀態

- **離線 byte-exact**：TLS 1.3 金鑰排程（RFC 8448 KAT）、BLAKE3（官方向量）、REALITY session_id seal / 憑證驗證、
  Vision padding round-trip、SS-2022 TCP/UDP 編解碼 round-trip。
- **真機**：自建 TLS 1.3 握手（google/cloudflare，含後量子指紋）、UDP relay（SOCKS5 UDP ASSOCIATE → Direct → 真實 DNS）。
- **待真機驗證**：REALITY+Vision 與 SS-2022 對真實伺服器的完整互通（無公開伺服器可離線驗）。

## 架構

```
入站(SOCKS5/HTTP，含 UDP ASSOCIATE) ──► Router(規則) ──► 出站(SS/SS-2022/Trojan/VLESS/SOCKS5/Direct)
        │                                                      │
   NWStream(async 包裝 Network.framework) ◄── Relay 雙向中繼 ──► ByteStream
                                              UDPRelayBridge ◄─► UDPRelaySession
```

所有 TCP 串流統一為 `ByteStream`（`read()`/`write()`/`close()`），UDP 走 `UDPRelaySession`（`send(_:to:)`/`receive()`）。
加密協議對中繼層透明。`shadow-demo` 是煙霧測試執行檔（`--tls13 HOST`、`--udptest`、`--vless URI`）。
