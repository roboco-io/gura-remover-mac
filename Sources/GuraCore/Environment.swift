import Foundation
import OSLog

public struct RuntimePaths: Sendable {
    public let applicationRoots: [URL]
    public let launchAgentRoots: [URL]
    public let privilegedHelperRoots: [URL]
    public let browserRoots: [URL]
    public let preferenceRoots: [URL]
    public let cacheRoots: [URL]
    public let supportRoots: [URL]

    public static func live(fileManager: FileManager = .default) -> RuntimePaths {
        let home = fileManager.homeDirectoryForCurrentUser
        return RuntimePaths(
            applicationRoots: [
                URL(fileURLWithPath: "/Applications"),
                home.appendingPathComponent("Applications", isDirectory: true),
            ],
            launchAgentRoots: [
                home.appendingPathComponent("Library/LaunchAgents", isDirectory: true),
                URL(fileURLWithPath: "/Library/LaunchAgents"),
                URL(fileURLWithPath: "/Library/LaunchDaemons"),
            ],
            privilegedHelperRoots: [
                URL(fileURLWithPath: "/Library/PrivilegedHelperTools"),
            ],
            browserRoots: [
                home.appendingPathComponent("Library/Application Support/Google/Chrome", isDirectory: true),
                home.appendingPathComponent("Library/Safari/Extensions", isDirectory: true),
            ],
            preferenceRoots: [
                home.appendingPathComponent("Library/Preferences", isDirectory: true),
            ],
            cacheRoots: [
                home.appendingPathComponent("Library/Caches", isDirectory: true),
            ],
            supportRoots: [
                home.appendingPathComponent("Library/Application Support", isDirectory: true),
                URL(fileURLWithPath: "/Library/Application Support"),
            ]
        )
    }
}

public protocol ProcessRunning {
    func run(_ executable: String, arguments: [String]) throws -> ProcessOutput
}

public struct ProcessOutput: Sendable {
    public let status: Int32
    public let stdout: String
    public let stderr: String
}

public enum GuraError: LocalizedError {
    case signaturesUnavailable
    case noFindingsSelected
    case removalRefused(String)
    case confirmationDeclined
    case restoreSessionMissing(String)
    case releaseAssetMissing(String)
    case invalidReleasePayload

    public var errorDescription: String? {
        switch self {
        case .signaturesUnavailable:
            return "시그니처 카탈로그를 불러오지 못했습니다."
        case .noFindingsSelected:
            return "삭제할 항목이 선택되지 않았습니다."
        case let .removalRefused(message):
            return message
        case .confirmationDeclined:
            return "사용자가 삭제를 취소했습니다."
        case let .restoreSessionMissing(id):
            return "복구 세션을 찾을 수 없습니다: \(id)"
        case let .releaseAssetMissing(name):
            return "GitHub Release에서 \(name) 자산을 찾지 못했습니다."
        case .invalidReleasePayload:
            return "GitHub Release 응답을 해석하지 못했습니다."
        }
    }
}

public struct LiveProcessRunner: ProcessRunning {
    public init() {}

    public func run(_ executable: String, arguments: [String]) throws -> ProcessOutput {
        final class DataBox: @unchecked Sendable {
            var data = Data()
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        let stdout = Pipe()
        let stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr

        let group = DispatchGroup()
        let stdoutData = DataBox()
        let stderrData = DataBox()

        group.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            stdoutData.data = stdout.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }

        group.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            stderrData.data = stderr.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }

        try process.run()
        process.waitUntilExit()
        group.wait()

        let output = String(data: stdoutData.data, encoding: .utf8) ?? ""
        let error = String(data: stderrData.data, encoding: .utf8) ?? ""
        return ProcessOutput(status: process.terminationStatus, stdout: output, stderr: error)
    }
}

public struct AppEnvironment {
    public let fileManager: FileManager
    public let processRunner: ProcessRunning
    public let logger: Logger
    public let appSupportURL: URL
    public let runtimePaths: RuntimePaths

    public init(
        fileManager: FileManager = .default,
        processRunner: ProcessRunning = LiveProcessRunner(),
        appSupportURL: URL,
        runtimePaths: RuntimePaths,
        logger: Logger = Logger(subsystem: "io.roboco.gura", category: "cli")
    ) {
        self.fileManager = fileManager
        self.processRunner = processRunner
        self.appSupportURL = appSupportURL
        self.runtimePaths = runtimePaths
        self.logger = logger
    }

    public static func live(fileManager: FileManager = .default) -> AppEnvironment {
        let env = ProcessInfo.processInfo.environment
        let appSupportRoot: URL
        if let override = env["GURA_HOME"], !override.isEmpty {
            appSupportRoot = URL(fileURLWithPath: override, isDirectory: true)
        } else {
            appSupportRoot = fileManager.homeDirectoryForCurrentUser
                .appendingPathComponent("Library/Application Support/GuraCleaner", isDirectory: true)
        }

        return AppEnvironment(
            fileManager: fileManager,
            processRunner: LiveProcessRunner(),
            appSupportURL: appSupportRoot,
            runtimePaths: RuntimePaths.live(fileManager: fileManager)
        )
    }

    public var backupRootURL: URL {
        appSupportURL.appendingPathComponent("backups", isDirectory: true)
    }

    public var signatureCacheURL: URL {
        appSupportURL.appendingPathComponent("signatures/remote.json", isDirectory: false)
    }

    public func ensureDirectories() throws {
        try fileManager.createDirectory(at: backupRootURL, withIntermediateDirectories: true)
        try fileManager.createDirectory(
            at: signatureCacheURL.deletingLastPathComponent(),
            withIntermediateDirectories: true
        )
    }

    public func expand(path: String) -> String {
        (path as NSString).expandingTildeInPath
    }
}
