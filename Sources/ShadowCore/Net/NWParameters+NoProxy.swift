import Network

extension NWParameters {
    /// 原生引擎「出站」連線一律套用：關閉 NWConnection 預設「遵循系統代理」的行為。
    ///
    /// 背景：macOS（實測 Darwin 25）上 `NWConnection` 預設會遵循系統 HTTP/HTTPS/SOCKS
    /// 代理與其 bypass 清單。ShadowSpace 開 autoSystemProxy 時把系統代理指向原生引擎自己，
    /// 引擎的出站若又遵循系統代理 → 引擎 → 系統代理 → 引擎 自迴圈 → 連線後完全沒網路。
    /// 設 `preferNoProxies` 後，引擎所有出站直接連，不再被繞回自己；比「把 server 加進 bypass」
    /// 的舊修補更徹底（direct / rule 模式命中直連的流量也不會迴圈）。
    ///
    /// `preferNoProxies` 為公開屬性、可回溯部署至 macOS 10.14。
    /// 註：入站 listener（`MixedServer`）不可套用此旗標。
    @discardableResult
    func disablingSystemProxy() -> NWParameters {
        preferNoProxies = true
        return self
    }
}
