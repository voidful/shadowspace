# ShadowCore — 全原生代理核心

純 Apple 框架（Network.framework + CryptoKit + CommonCrypto）實作的代理核心，**不依賴 sing-box**。
目的：讓 ShadowSpace 能走 App Store 路線（沙箱 + NetworkExtension，且無 GPLv3 授權衝突）。

## 支援矩陣

| 類別 | 已支援 | 說明 |
|---|---|---|
| 入站 | SOCKS5、HTTP（CONNECT＋明文） | 本地混合伺服器，依首位元組分流 |
| 出站 | Direct、Shadowsocks、Trojan、VLESS、SOCKS5 | SS 用 CryptoKit AEAD；Trojan 用 CommonCrypto SHA-224 |
| 傳輸 | TCP、TLS（SNI／allowInsecure／ALPN）、WebSocket（ws/wss） | `TransportConfig` / `Transport.dial` |
| 路由 | domain suffix/keyword/exact、IP CIDR、reject、final | 由上而下，命中即止 |

## 刻意不支援（純 Apple 框架的硬限制）

這些都需要 Apple 框架不開放的底層控制，硬做等於自行實作整個協議堆疊，超出合理範圍：

- **Reality**：需要偽造特定指紋的 TLS ClientHello（uTLS），但 `NWProtocolTLS` 不讓你客製握手。
- **Hysteria2 / TUIC**：需要自訂 QUIC 壅塞控制與混淆，Apple 的 QUIC 是黑盒。
- **gRPC（gun）**：需要全雙工 HTTP/2 雙向串流，但 Network.framework 無公開 HTTP/2；
  自行實作 HTTP/2（HPACK + 框架 + 流量控制）工程量比 VMess 更大。**WebSocket 已涵蓋多數 CDN 傳輸需求**，故不做。

> 需要上述協議的使用者，請改用 Developer ID 發佈版（內嵌 sing-box，功能完整）。

## 尚未實作（可行但暫緩）

- **VMess**：純 Apple 框架可行（AES-GCM/ChaCha20 body + CommonCrypto 的 MD5/AES-ECB），
  但約 300 行精密密碼學、且本機無法驗證互通性，已被 VLESS 取代，故暫緩。

## 架構

```
入站(SOCKS5/HTTP) ──► Router(規則) ──► 出站(SS/Trojan/VLESS/SOCKS5/Direct)
        │                                      │
   NWStream(async 包裝 Network.framework) ◄── Relay 雙向中繼 ──► ByteStream
```

所有串流統一為 `ByteStream`（`read()`/`write()`/`close()`），加密協議對中繼層透明。
`shadow-demo` 是煙霧測試執行檔（`swift build --product shadow-demo`）。
