import Foundation

/// 雙向中繼：在兩條串流間搬位元組，任一方向 EOF/出錯就收掉兩邊。
public enum Relay {

    /// onBytes(up, down)：up = client→remote 的位元組數，down = remote→client。
    public static func run(client: ByteStream, remote: ByteStream,
                           onBytes: (@Sendable (Int, Int) -> Void)? = nil) async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask {
                await pump(from: client, to: remote) { onBytes?($0, 0) }
            }
            group.addTask {
                await pump(from: remote, to: client) { onBytes?(0, $0) }
            }
            // 任一方向結束就收掉兩條連線，讓另一方向的 read 解除阻塞
            await group.next()
            client.close()
            remote.close()
        }
    }

    private static func pump(from: ByteStream, to: ByteStream,
                             count: @Sendable (Int) -> Void) async {
        do {
            while true {
                let data = try await from.read()
                if data.isEmpty { break }     // EOF
                try await to.write(data)
                count(data.count)
            }
        } catch {
            // 連線中斷，結束此方向
        }
    }
}
