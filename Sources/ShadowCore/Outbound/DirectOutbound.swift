import Foundation
import Network

/// 直連：不經任何代理，直接連到目標。
public struct DirectOutbound: Outbound {
    public let name = "DIRECT"
    public init() {}

    public func connect(to target: Target, queue: DispatchQueue) async throws -> ByteStream {
        let stream = NWStream(host: target.host, port: target.port, queue: queue)
        try await stream.start()
        return stream
    }

    public func openDatagramSession(to target: Target, queue: DispatchQueue) async throws -> DatagramSession {
        let session = NWDatagramSession(host: target.host, port: target.port, queue: queue)
        try await session.start()
        return session
    }
}
