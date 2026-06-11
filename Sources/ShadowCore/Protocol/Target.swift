import Foundation
import Network

/// 連線目標：網域或 IP + 連接埠。
public struct Target: Sendable, Equatable {
    public var host: String
    public var port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    public var isIPLiteral: Bool {
        IPv4Address(host) != nil || IPv6Address(host) != nil
    }

    public var description: String { "\(host):\(port)" }
}
