import Foundation
import Network

/// 出站撥接器：把「要連到 target」轉成一條可讀寫的串流。
/// Direct 直接連；代理協議（SS/Trojan/VLESS/VMess/SOCKS）連到自家伺服器後完成握手，
/// 回傳的串流讀寫的就是「與 target 之間的明文」。
public protocol Outbound: Sendable {
    var name: String { get }
    func connect(to target: Target, queue: DispatchQueue) async throws -> ByteStream
}
