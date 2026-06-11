import Foundation

/// 管理 sing-box 子程序的生命週期，以及引擎二進位檔的尋找與下載。
/// 兩種執行路徑：
/// - 一般模式：直接以子程序執行（系統代理）
/// - TUN 模式：透過管理員授權以 root 執行；用「哨兵檔案 + 看門狗」控制停止，
///   中斷連線或 App 結束時不需要再次輸入密碼
final class EngineManager {

    enum EngineError: LocalizedError {
        case binaryNotFound
        case checkFailed(String)
        case startFailed(String)
        case downloadFailed(String)
        case authCancelled

        var errorDescription: String? {
            switch self {
            case .binaryNotFound:
                return "找不到 sing-box 核心引擎"
            case .checkFailed(let msg):
                return "設定檔驗證失敗：\(msg)"
            case .startFailed(let msg):
                return "引擎啟動失敗：\(msg)"
            case .downloadFailed(let msg):
                return "引擎下載失敗：\(msg)"
            case .authCancelled:
                return "已取消管理員授權。TUN 模式需要管理員權限才能建立虛擬網卡。"
            }
        }
    }

    enum RunMode {
        case none
        case process
        case privileged(pid: Int32)
    }

    /// ~/Library/Application Support/ShadowSpace
    static var supportDir: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir = base.appendingPathComponent("ShadowSpace", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    static var configURL: URL { supportDir.appendingPathComponent("config.json") }
    static var workDir: URL {
        let dir = supportDir.appendingPathComponent("engine", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }
    /// root 執行時使用獨立工作目錄，避免 root 寫入的快取檔讓一般模式無法存取
    static var privilegedWorkDir: URL {
        let dir = supportDir.appendingPathComponent("engine-root", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }
    static var installedBinaryURL: URL { supportDir.appendingPathComponent("bin/sing-box") }
    static var sentinelURL: URL { supportDir.appendingPathComponent("tun.sentinel") }
    static var privilegedLogURL: URL { privilegedWorkDir.appendingPathComponent("engine.log") }
    static var helperScriptURL: URL { supportDir.appendingPathComponent("run-engine.sh") }

    private var process: Process?
    private(set) var runMode: RunMode = .none
    /// 引擎輸出的每一行 log（從背景執行緒呼叫）
    var onLog: ((String) -> Void)?
    /// 引擎意外退出時呼叫（從背景執行緒呼叫）
    var onUnexpectedExit: ((Int32) -> Void)?
    private var expectingExit = false
    private var watchTimer: DispatchSourceTimer?
    private var logTailTimer: DispatchSourceTimer?
    private var logTailOffset: UInt64 = 0

    var isRunning: Bool {
        switch runMode {
        case .none: return false
        case .process: return process?.isRunning ?? false
        case .privileged(let pid): return processAlive(pid)
        }
    }

    private func processAlive(_ pid: Int32) -> Bool {
        // root 程序无法直接 signal：EPERM 代表還活著，ESRCH 代表已結束
        kill(pid, 0) == 0 || errno == EPERM
    }

    // MARK: - 引擎二進位檔

    /// 依序尋找：App 支援目錄（自動下載處）→ App bundle → 專案 vendor/ → Homebrew
    static func findBinary() -> URL? {
        var candidates: [URL] = [installedBinaryURL]
        if let res = Bundle.main.resourceURL {
            candidates.append(res.appendingPathComponent("bin/sing-box"))
        }
        candidates.append(URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
            .appendingPathComponent("vendor/sing-box"))
        candidates.append(URL(fileURLWithPath: "/opt/homebrew/bin/sing-box"))
        candidates.append(URL(fileURLWithPath: "/usr/local/bin/sing-box"))
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0.path) }
    }

    static func version() -> String? {
        guard let bin = findBinary() else { return nil }
        let (status, output) = runProcess(bin, ["version"])
        guard status == 0 else { return nil }
        let firstLine = output.split(whereSeparator: \.isNewline).first.map(String.init) ?? output
        return firstLine.replacingOccurrences(of: "sing-box version ", with: "")
    }

    // MARK: - 一般模式啟動

    func start(configData: Data) throws {
        let bin = try prepare(configData: configData)

        let proc = Process()
        proc.executableURL = bin
        proc.arguments = ["run", "-c", Self.configURL.path, "-D", Self.workDir.path]

        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe
        var buffer = Data()
        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard !data.isEmpty else { return }
            buffer.append(data)
            while let nl = buffer.firstIndex(of: 0x0A) {
                let lineData = buffer.prefix(upTo: nl)
                buffer.removeSubrange(...nl)
                if let line = String(data: lineData, encoding: .utf8), !line.isEmpty {
                    self?.onLog?(line)
                }
            }
        }
        expectingExit = false
        proc.terminationHandler = { [weak self] p in
            pipe.fileHandleForReading.readabilityHandler = nil
            guard let self, !self.expectingExit else { return }
            self.onUnexpectedExit?(p.terminationStatus)
        }
        do {
            try proc.run()
        } catch {
            throw EngineError.startFailed(error.localizedDescription)
        }
        process = proc
        runMode = .process
    }

    // MARK: - TUN 特權模式啟動

    func startPrivileged(configData: Data) throws {
        let bin = try prepare(configData: configData)
        let work = Self.privilegedWorkDir
        let pidFile = work.appendingPathComponent("engine.pid")
        try? FileManager.default.removeItem(at: pidFile)
        try? FileManager.default.removeItem(at: Self.privilegedLogURL)
        FileManager.default.createFile(atPath: Self.privilegedLogURL.path, contents: nil)

        // 哨兵檔在 → 引擎活著；刪掉它 → root 看門狗 1 秒內把引擎收掉
        FileManager.default.createFile(atPath: Self.sentinelURL.path, contents: Data("run".utf8))
        try Self.helperScript.write(to: Self.helperScriptURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755],
                                              ofItemAtPath: Self.helperScriptURL.path)

        func shq(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }
        let cmd = [
            "/bin/sh", shq(Self.helperScriptURL.path), shq(bin.path), shq(Self.configURL.path),
            shq(work.path), shq(Self.sentinelURL.path), shq(Self.privilegedLogURL.path),
            "\(ProcessInfo.processInfo.processIdentifier)",
        ].joined(separator: " ")
        let escaped = cmd
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        let script = "do shell script \"\(escaped)\" with administrator privileges"

        let (status, output) = Self.runProcess(URL(fileURLWithPath: "/usr/bin/osascript"), ["-e", script])
        guard status == 0 else {
            try? FileManager.default.removeItem(at: Self.sentinelURL)
            if output.contains("-128") || output.localizedCaseInsensitiveContains("cancel") {
                throw EngineError.authCancelled
            }
            throw EngineError.startFailed(output.trimmingCharacters(in: .whitespacesAndNewlines))
        }

        var pid: Int32 = 0
        for _ in 0..<30 {
            if let s = try? String(contentsOf: pidFile, encoding: .utf8),
               let p = Int32(s.trimmingCharacters(in: .whitespacesAndNewlines)) {
                pid = p
                break
            }
            usleep(100_000)
        }
        guard pid > 0 else {
            try? FileManager.default.removeItem(at: Self.sentinelURL)
            throw EngineError.startFailed("無法取得引擎 PID")
        }
        runMode = .privileged(pid: pid)
        startWatch(pid: pid)
        startLogTail()
    }

    /// 共用前置：找引擎、寫設定檔、跑 sing-box check 取得明確錯誤
    private func prepare(configData: Data) throws -> URL {
        guard let bin = Self.findBinary() else { throw EngineError.binaryNotFound }
        try configData.write(to: Self.configURL)
        let (checkStatus, checkOutput) = Self.runProcess(bin, ["check", "-c", Self.configURL.path])
        guard checkStatus == 0 else {
            throw EngineError.checkFailed(checkOutput.trimmingCharacters(in: .whitespacesAndNewlines))
        }
        return bin
    }

    // MARK: - 停止

    func stop() {
        stopWatch()
        stopLogTail()
        switch runMode {
        case .none:
            break
        case .process:
            if let proc = process, proc.isRunning {
                expectingExit = true
                proc.terminate() // SIGTERM，sing-box 會優雅退出
                let deadline = Date().addingTimeInterval(3)
                while proc.isRunning && Date() < deadline {
                    usleep(50_000)
                }
                if proc.isRunning {
                    kill(proc.processIdentifier, SIGKILL)
                }
            }
            process = nil
        case .privileged(let pid):
            // 刪哨兵 → root 看門狗收掉引擎，不需再次授權
            try? FileManager.default.removeItem(at: Self.sentinelURL)
            let deadline = Date().addingTimeInterval(6)
            while processAlive(pid) && Date() < deadline {
                usleep(200_000)
            }
            if processAlive(pid) {
                onLog?("[warn] 引擎仍在執行（PID \(pid)），請手動結束 sing-box")
            }
        }
        runMode = .none
    }

    // MARK: - 特權模式：存活監看與日誌追蹤

    private func startWatch(pid: Int32) {
        let timer = DispatchSource.makeTimerSource(queue: .global())
        timer.schedule(deadline: .now() + 2, repeating: 2)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            if !self.processAlive(pid) {
                self.stopWatch()
                self.onUnexpectedExit?(-1)
            }
        }
        timer.resume()
        watchTimer = timer
    }

    private func stopWatch() {
        watchTimer?.cancel()
        watchTimer = nil
    }

    private func startLogTail() {
        logTailOffset = 0
        let timer = DispatchSource.makeTimerSource(queue: .global())
        timer.schedule(deadline: .now() + 0.5, repeating: 0.5)
        timer.setEventHandler { [weak self] in
            guard let self,
                  let handle = try? FileHandle(forReadingFrom: Self.privilegedLogURL) else { return }
            defer { try? handle.close() }
            try? handle.seek(toOffset: self.logTailOffset)
            guard let data = try? handle.readToEnd(), !data.isEmpty else { return }
            self.logTailOffset += UInt64(data.count)
            guard let text = String(data: data, encoding: .utf8) else { return }
            for line in text.split(whereSeparator: \.isNewline) where !line.isEmpty {
                self.onLog?(String(line))
            }
        }
        timer.resume()
        logTailTimer = timer
    }

    private func stopLogTail() {
        logTailTimer?.cancel()
        logTailTimer = nil
    }

    /// root 端腳本：啟動引擎、寫 PID，看門狗盯著哨兵檔與 App 本體，
    /// 任一消失就收掉引擎（App 閃退也不會留下 root 程序）
    private static let helperScript = """
    #!/bin/sh
    BIN="$1"; CFG="$2"; DIR="$3"; SEN="$4"; LOG="$5"; APP="$6"
    mkdir -p "$DIR"
    "$BIN" run -c "$CFG" -D "$DIR" >> "$LOG" 2>&1 &
    SB=$!
    echo "$SB" > "$DIR/engine.pid"
    (
      while [ -f "$SEN" ] && kill -0 "$APP" 2>/dev/null && kill -0 "$SB" 2>/dev/null; do
        sleep 1
      done
      kill "$SB" 2>/dev/null
      sleep 1
      kill -9 "$SB" 2>/dev/null
      rm -f "$DIR/engine.pid"
    ) >/dev/null 2>&1 &
    exit 0
    """

    // MARK: - 共用：執行外部指令

    @discardableResult
    static func runProcess(_ url: URL, _ args: [String]) -> (Int32, String) {
        let proc = Process()
        proc.executableURL = url
        proc.arguments = args
        let pipe = Pipe()
        proc.standardOutput = pipe
        proc.standardError = pipe
        do {
            try proc.run()
        } catch {
            return (-1, error.localizedDescription)
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        return (proc.terminationStatus, String(data: data, encoding: .utf8) ?? "")
    }
}

// MARK: - 引擎下載安裝

/// 從 GitHub Releases 抓最新的 sing-box 官方二進位檔，新手不用碰終端機。
enum EngineInstaller {

    static func archSuffix() -> String {
        #if arch(arm64)
        return "arm64"
        #else
        return "amd64"
        #endif
    }

    /// 回傳安裝後的版本字串
    static func installLatest(progress: @escaping @Sendable (String) -> Void) async throws -> String {
        progress("正在查詢最新版本…")
        var apiReq = URLRequest(url: URL(string: "https://api.github.com/repos/SagerNet/sing-box/releases/latest")!)
        apiReq.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        let (apiData, apiResp) = try await URLSession.shared.data(for: apiReq)
        guard (apiResp as? HTTPURLResponse)?.statusCode == 200,
              let release = try? JSONSerialization.jsonObject(with: apiData) as? [String: Any],
              let tag = release["tag_name"] as? String,
              let assets = release["assets"] as? [[String: Any]] else {
            throw EngineManager.EngineError.downloadFailed("無法取得版本資訊（GitHub API）")
        }

        let wantedSuffix = "darwin-\(archSuffix()).tar.gz"
        guard let asset = assets.first(where: { ($0["name"] as? String)?.hasSuffix(wantedSuffix) == true }),
              let urlString = asset["browser_download_url"] as? String,
              let url = URL(string: urlString) else {
            throw EngineManager.EngineError.downloadFailed("找不到 macOS \(archSuffix()) 版本的下載檔")
        }

        progress("正在下載 \(tag)…")
        let (tmpFile, dlResp) = try await URLSession.shared.download(from: url)
        guard (dlResp as? HTTPURLResponse)?.statusCode == 200 else {
            throw EngineManager.EngineError.downloadFailed("下載失敗（HTTP \((dlResp as? HTTPURLResponse)?.statusCode ?? -1))")
        }

        progress("正在解壓縮…")
        let extractDir = FileManager.default.temporaryDirectory
            .appendingPathComponent("shadowspace-engine-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: extractDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: extractDir) }

        let (tarStatus, tarOutput) = EngineManager.runProcess(
            URL(fileURLWithPath: "/usr/bin/tar"),
            ["-xzf", tmpFile.path, "-C", extractDir.path]
        )
        guard tarStatus == 0 else {
            throw EngineManager.EngineError.downloadFailed("解壓縮失敗：\(tarOutput)")
        }

        guard let binURL = findFile(named: "sing-box", under: extractDir) else {
            throw EngineManager.EngineError.downloadFailed("壓縮檔內找不到 sing-box 執行檔")
        }

        let dest = EngineManager.installedBinaryURL
        try FileManager.default.createDirectory(at: dest.deletingLastPathComponent(),
                                                withIntermediateDirectories: true)
        if FileManager.default.fileExists(atPath: dest.path) {
            try FileManager.default.removeItem(at: dest)
        }
        try FileManager.default.moveItem(at: binURL, to: dest)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: dest.path)
        // 清掉可能的 quarantine 屬性，避免 Gatekeeper 攔截
        EngineManager.runProcess(URL(fileURLWithPath: "/usr/bin/xattr"), ["-c", dest.path])

        progress("安裝完成")
        return EngineManager.version() ?? tag
    }

    private static func findFile(named name: String, under dir: URL) -> URL? {
        let enumerator = FileManager.default.enumerator(at: dir, includingPropertiesForKeys: nil)
        while let item = enumerator?.nextObject() as? URL {
            if item.lastPathComponent == name { return item }
        }
        return nil
    }
}
