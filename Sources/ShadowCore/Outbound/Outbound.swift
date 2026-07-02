import Foundation
import Network

/// 出站撥接器：把「要連到 target」轉成一條可讀寫的串流。
/// Direct 直接連；代理協議（SS/Trojan/VLESS/VMess/SOCKS）連到自家伺服器後完成握手，
/// 回傳的串流讀寫的就是「與 target 之間的明文」。
public protocol Outbound: Sendable {
    var name: String { get }
    func connect(to target: Target, queue: DispatchQueue) async throws -> ByteStream
    // 以下為 requirement + extension 預設：確保具體型別的實作走動態分派（否則存在型別呼叫會誤用預設）。
    func openDatagramSession(to target: Target, queue: DispatchQueue) async throws -> DatagramSession
    func openUDPRelay(queue: DispatchQueue) async throws -> UDPRelaySession
}

public extension Outbound {
    func openDatagramSession(to target: Target, queue: DispatchQueue) async throws -> DatagramSession {
        throw ProxyError.unsupported("\(name) 不支援 UDP 出站：\(target.host):\(target.port)")
    }

    /// 多工 UDP relay（一個 session 送/收多個目標，供 SOCKS5 UDP ASSOCIATE）。預設不支援。
    func openUDPRelay(queue: DispatchQueue) async throws -> UDPRelaySession {
        throw ProxyError.unsupported("\(name) 不支援 UDP relay")
    }
}

/// 多工 UDP relay session：每筆封包自帶目標位址（SS-2022 UDP、Direct UDP 用）。
public protocol UDPRelaySession: AnyObject, Sendable {
    func send(_ payload: Data, to target: Target) async throws
    func receive() async throws -> (payload: Data, from: Target)
    func close()
}
