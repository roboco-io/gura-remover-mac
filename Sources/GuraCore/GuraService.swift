import Foundation

public struct ScanOptions: Sendable {
    public let includeLowConfidence: Bool

    public init(includeLowConfidence: Bool = true) {
        self.includeLowConfidence = includeLowConfidence
    }
}

public struct RemoveOptions: Sendable {
    public let ids: [String]
    public let removeAllSafe: Bool
    public let allowLowConfidence: Bool
    public let forceHighRisk: Bool
    public let assumeYes: Bool
    public let dryRun: Bool

    public init(
        ids: [String] = [],
        removeAllSafe: Bool = false,
        allowLowConfidence: Bool = false,
        forceHighRisk: Bool = false,
        assumeYes: Bool = false,
        dryRun: Bool = false
    ) {
        self.ids = ids
        self.removeAllSafe = removeAllSafe
        self.allowLowConfidence = allowLowConfidence
        self.forceHighRisk = forceHighRisk
        self.assumeYes = assumeYes
        self.dryRun = dryRun
    }
}

public final class GuraService {
    private let environment: AppEnvironment
    private let encoder: JSONEncoder
    private let decoder: JSONDecoder

    public init(environment: AppEnvironment = .live()) {
        self.environment = environment
        self.encoder = JSONEncoder()
        self.decoder = JSONDecoder()
        self.encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        self.encoder.dateEncodingStrategy = .iso8601
        self.decoder.dateDecodingStrategy = .iso8601
    }

    public func scan(options: ScanOptions = ScanOptions()) throws -> ScanReport {
        try environment.ensureDirectories()
        let catalog = try loadCatalog()
        var warnings: [String] = []
        var findings: [Finding] = []
        let commandSnapshot = collectCommandSnapshot(warnings: &warnings)
        let fileSnapshot = collectFileSnapshot()

        for signature in catalog.signatures {
            if signature.confidence == .low && !options.includeLowConfidence {
                continue
            }

            let artifacts = try discoverArtifacts(
                for: signature,
                commandSnapshot: commandSnapshot,
                fileSnapshot: fileSnapshot,
                warnings: &warnings
            )
            if !artifacts.isEmpty {
                findings.append(Finding(signature: signature, artifacts: artifacts))
            }
        }

        findings.sort {
            if $0.risk != $1.risk {
                return $0.risk > $1.risk
            }
            return $0.product < $1.product
        }

        return ScanReport(
            createdAt: Date(),
            signatureVersion: catalog.version,
            findings: findings,
            warnings: warnings.sorted()
        )
    }

    public func remove(options: RemoveOptions, confirm: (String) -> Bool) throws -> RemovalResult {
        let report = try scan(
            options: .init(includeLowConfidence: !options.ids.isEmpty || options.allowLowConfidence)
        )
        let selected = try selectFindings(from: report.findings, options: options)
        let plan = buildRemovalPlan(for: selected)

        if !options.assumeYes {
            let summary = selected.map { "\($0.product) [risk:\($0.risk.rawValue), confidence:\($0.confidence.rawValue)]" }
                .joined(separator: "\n")
            let allowed = confirm("다음 항목을 삭제합니다:\n\(summary)\n계속하려면 yes 를 입력하세요:")
            guard allowed else {
                throw GuraError.confirmationDeclined
            }
        }

        let sessionID = sessionIdentifier()
        let sessionRoot = environment.backupRootURL.appendingPathComponent(sessionID, isDirectory: true)
        let filesRoot = sessionRoot.appendingPathComponent("files", isDirectory: true)
        try environment.fileManager.createDirectory(at: filesRoot, withIntermediateDirectories: true)

        var actions: [BackupAction] = []
        var deletedPaths: [String] = []
        var operations: [String] = []
        var warnings = plan.warnings

        for label in plan.launchdServices {
            operations.append("launchctl remove \(label)")
            guard !options.dryRun else { continue }

            let output = try? environment.processRunner.run("/bin/launchctl", arguments: ["remove", label])
            if let output, output.status != 0 {
                let message = output.stderr.isEmpty ? output.stdout : output.stderr
                warnings.append("launchd 서비스를 제거하지 못했습니다: \(label) (\(message.trimmingCharacters(in: .whitespacesAndNewlines)))")
            }
        }

        for pid in plan.processIDs {
            operations.append("kill -TERM \(pid)")
            operations.append("kill -KILL \(pid)")
            guard !options.dryRun else { continue }

            _ = try? environment.processRunner.run("/bin/kill", arguments: ["-TERM", String(pid)])
            let killOutput = try? environment.processRunner.run("/bin/kill", arguments: ["-KILL", String(pid)])
            if let killOutput, killOutput.status != 0 {
                let message = killOutput.stderr.isEmpty ? killOutput.stdout : killOutput.stderr
                warnings.append("프로세스를 종료하지 못했습니다: \(pid) (\(message.trimmingCharacters(in: .whitespacesAndNewlines)))")
            }
        }

        for artifact in plan.removableArtifacts {
            guard let artifactPath = artifact.path else {
                continue
            }

            if !environment.fileManager.fileExists(atPath: artifactPath) {
                continue
            }

            let originalURL = URL(fileURLWithPath: artifactPath)
            let backupURL = backupURL(for: originalURL, under: filesRoot)
            try environment.fileManager.createDirectory(
                at: backupURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )

            if !options.dryRun {
                if artifact.kind == .launchdPlist {
                    _ = try? environment.processRunner.run("/bin/launchctl", arguments: ["bootout", "system", artifactPath])
                    _ = try? environment.processRunner.run("/bin/launchctl", arguments: ["bootout", "gui/\(getuid())", artifactPath])
                    if !artifact.value.isEmpty {
                        _ = try? environment.processRunner.run("/bin/launchctl", arguments: ["remove", artifact.value])
                    }
                }

                try copyPreservingDirectory(source: originalURL, destination: backupURL)
                try environment.fileManager.removeItem(at: originalURL)
            }

            actions.append(BackupAction(originalPath: artifactPath, backupPath: backupURL.path))
            deletedPaths.append(artifactPath)
        }

        for receipt in plan.packageReceipts {
            operations.append("pkgutil --forget \(receipt)")
            guard !options.dryRun else { continue }

            let output = try? environment.processRunner.run("/usr/sbin/pkgutil", arguments: ["--forget", receipt])
            if let output, output.status != 0 {
                let message = output.stderr.isEmpty ? output.stdout : output.stderr
                warnings.append("패키지 영수증을 제거하지 못했습니다: \(receipt) (\(message.trimmingCharacters(in: .whitespacesAndNewlines)))")
            }
        }

        for systemExtension in plan.systemExtensions {
            operations.append("systemextensionsctl uninstall \(systemExtension.teamID) \(systemExtension.bundleID)")
            guard !options.dryRun else { continue }

            let output = try? environment.processRunner.run(
                "/usr/bin/systemextensionsctl",
                arguments: ["uninstall", systemExtension.teamID, systemExtension.bundleID]
            )
            if let output, output.status != 0 {
                let message = output.stderr.isEmpty ? output.stdout : output.stderr
                let normalized = message.trimmingCharacters(in: .whitespacesAndNewlines)
                if normalized.localizedCaseInsensitiveContains("System Integrity Protection is enabled") {
                    warnings.append("시스템 확장을 제거하지 못했습니다: \(systemExtension.bundleID) (SIP 활성화로 차단됨. recoveryOS에서 SIP를 끄지 않으면 systemextensionsctl uninstall 이 실패할 수 있습니다.)")
                } else {
                    warnings.append("시스템 확장을 제거하지 못했습니다: \(systemExtension.bundleID) (\(normalized))")
                }
            }
        }

        let session = BackupSession(
            sessionID: sessionID,
            createdAt: Date(),
            removedFindings: selected,
            actions: actions,
            warnings: warnings
        )

        let manifestURL = sessionRoot.appendingPathComponent("manifest.json", isDirectory: false)
        try encoder.encode(session).write(to: manifestURL)

        return RemovalResult(
            session: session,
            deletedPaths: deletedPaths.sorted(),
            operations: operations.sorted(),
            warnings: warnings.sorted()
        )
    }

    public func restore(sessionID: String?) throws -> RestoreResult {
        let session = try loadSession(sessionID: sessionID)
        var restoredPaths: [String] = []
        var warnings: [String] = []

        for action in session.actions {
            let backupURL = URL(fileURLWithPath: action.backupPath)
            let originalURL = URL(fileURLWithPath: action.originalPath)
            guard environment.fileManager.fileExists(atPath: backupURL.path) else {
                warnings.append("백업 파일이 없어 복구하지 못했습니다: \(backupURL.path)")
                continue
            }

            try environment.fileManager.createDirectory(
                at: originalURL.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )

            if environment.fileManager.fileExists(atPath: originalURL.path) {
                try environment.fileManager.removeItem(at: originalURL)
            }

            try copyPreservingDirectory(source: backupURL, destination: originalURL)
            restoredPaths.append(originalURL.path)
        }

        return RestoreResult(sessionID: session.sessionID, restoredPaths: restoredPaths.sorted(), warnings: warnings.sorted())
    }

    public func history() throws -> [HistoryEntry] {
        try environment.ensureDirectories()
        let sessionDirs = try environment.fileManager.contentsOfDirectory(
            at: environment.backupRootURL,
            includingPropertiesForKeys: nil,
            options: [.skipsHiddenFiles]
        )

        return try sessionDirs.compactMap { url in
            let manifest = url.appendingPathComponent("manifest.json", isDirectory: false)
            guard environment.fileManager.fileExists(atPath: manifest.path) else {
                return nil
            }
            let session = try decoder.decode(BackupSession.self, from: Data(contentsOf: manifest))
            return HistoryEntry(
                sessionID: session.sessionID,
                createdAt: session.createdAt,
                findingCount: session.removedFindings.count,
                actionCount: session.actions.count
            )
        }
        .sorted { $0.createdAt > $1.createdAt }
    }

    public func doctor() throws -> DoctorReport {
        try environment.ensureDirectories()
        let commands = ["/bin/launchctl", "/usr/sbin/pkgutil", "/usr/bin/codesign", "/usr/bin/log", "/usr/bin/sfltool", "/usr/bin/systemextensionsctl", "/usr/bin/csrutil"]
        let availability = Dictionary(uniqueKeysWithValues: commands.map { path in
            (URL(fileURLWithPath: path).lastPathComponent, environment.fileManager.isExecutableFile(atPath: path))
        })
        let historyCount = (try? history().count) ?? 0
        let signatureSource = environment.fileManager.fileExists(atPath: environment.signatureCacheURL.path)
            ? environment.signatureCacheURL.path
            : "bundled:default.json"
        let sipEnabled = csrutilStatus()
        let report = try scan()
        let residuals = report.findings.compactMap(makeDoctorResidual)

        var warnings: [String] = []
        if geteuid() != 0 {
            warnings.append("시스템 범위 삭제를 수행하려면 sudo 로 다시 실행해야 합니다.")
        }
        if availability["systemextensionsctl"] == false {
            warnings.append("systemextensionsctl 을 찾지 못해 시스템 확장 탐지가 제한됩니다.")
        }
        if sipEnabled == true && residuals.contains(where: { !$0.systemExtensions.isEmpty }) {
            warnings.append("SIP가 활성화되어 있어 일부 시스템 확장 제거는 차단됩니다. 현재 macOS에서는 recoveryOS에서 SIP를 끄지 않으면 systemextensionsctl uninstall 이 실패할 수 있습니다.")
        }
        if residuals.contains(where: { !$0.launchdServices.isEmpty || !$0.runningProcesses.isEmpty }) {
            warnings.append("일부 항목은 파일 삭제 후에도 launchd 등록 또는 실행 프로세스가 남아 있을 수 있습니다. sudo remove 를 다시 실행하거나 재부팅 후 재확인하세요.")
        }

        return DoctorReport(
            isRoot: geteuid() == 0,
            sipEnabled: sipEnabled,
            appSupportPath: environment.appSupportURL.path,
            signatureSource: signatureSource,
            availableCommands: availability,
            backupSessionCount: historyCount,
            residuals: residuals,
            warnings: warnings
        )
    }

    public func updateSignatures(repository: String, assetName: String) throws -> SignatureUpdateResult {
        try environment.ensureDirectories()

        let url = URL(string: "https://api.github.com/repos/\(repository)/releases/latest")!
        let data = try Data(contentsOf: url)
        guard
            let payload = try JSONSerialization.jsonObject(with: data) as? [String: Any],
            let assets = payload["assets"] as? [[String: Any]]
        else {
            throw GuraError.invalidReleasePayload
        }

        guard
            let asset = assets.first(where: { ($0["name"] as? String) == assetName }),
            let downloadURLString = asset["browser_download_url"] as? String,
            let downloadURL = URL(string: downloadURLString)
        else {
            throw GuraError.releaseAssetMissing(assetName)
        }

        let downloaded = try Data(contentsOf: downloadURL)
        let catalog = try decoder.decode(SignatureCatalog.self, from: downloaded)
        try downloaded.write(to: environment.signatureCacheURL)

        return SignatureUpdateResult(
            repository: repository,
            assetName: assetName,
            downloadedTo: environment.signatureCacheURL.path,
            version: catalog.version
        )
    }

    private func loadCatalog() throws -> SignatureCatalog {
        if environment.fileManager.fileExists(atPath: environment.signatureCacheURL.path) {
            return try decoder.decode(SignatureCatalog.self, from: Data(contentsOf: environment.signatureCacheURL))
        }

        let bundledURL =
            Bundle.module.url(forResource: "default", withExtension: "json") ??
            Bundle.module.url(forResource: "default", withExtension: "json", subdirectory: "signatures")

        guard let bundledURL else {
            throw GuraError.signaturesUnavailable
        }
        return try decoder.decode(SignatureCatalog.self, from: Data(contentsOf: bundledURL))
    }

    private struct CommandSnapshot {
        let packageReceipts: [String]
        let systemExtensions: [String]
        let launchdEntries: [LaunchdEntry]
        let runningProcesses: [RunningProcess]
    }

    private struct LaunchdEntry {
        let label: String
        let pid: Int?
    }

    private struct RunningProcess {
        let pid: Int
        let executable: String
        let command: String
    }

    private struct FileSnapshotEntry {
        let root: URL
        let url: URL
        let loweredName: String
    }

    private func collectCommandSnapshot(warnings: inout [String]) -> CommandSnapshot {
        var packageReceipts: [String] = []
        var systemExtensions: [String] = []
        var launchdEntries: [LaunchdEntry] = []
        var runningProcesses: [RunningProcess] = []

        do {
            let pkgOutput = try environment.processRunner.run("/usr/sbin/pkgutil", arguments: ["--pkgs"])
            if pkgOutput.status == 0 {
                packageReceipts = pkgOutput.stdout.split(separator: "\n").map(String.init)
            } else if !pkgOutput.stderr.isEmpty {
                warnings.append("pkgutil 조회에 실패했습니다: \(pkgOutput.stderr.trimmingCharacters(in: .whitespacesAndNewlines))")
            }
        } catch {
            warnings.append("pkgutil 조회에 실패했습니다: \(error.localizedDescription)")
        }

        do {
            let dump = try environment.processRunner.run("/usr/bin/systemextensionsctl", arguments: ["list"])
            if dump.status == 0 {
                systemExtensions = dump.stdout.split(separator: "\n").map(String.init)
            } else if !dump.stderr.isEmpty {
                warnings.append("systemextensionsctl 조회에 실패했습니다: \(dump.stderr.trimmingCharacters(in: .whitespacesAndNewlines))")
            }
        } catch {
            warnings.append("systemextensionsctl 조회에 실패했습니다: \(error.localizedDescription)")
        }

        do {
            let output = try environment.processRunner.run("/bin/launchctl", arguments: ["list"])
            if output.status == 0 {
                launchdEntries = output.stdout
                    .split(separator: "\n")
                    .compactMap(parseLaunchdEntry)
            } else if !output.stderr.isEmpty {
                warnings.append("launchctl 조회에 실패했습니다: \(output.stderr.trimmingCharacters(in: .whitespacesAndNewlines))")
            }
        } catch {
            warnings.append("launchctl 조회에 실패했습니다: \(error.localizedDescription)")
        }

        do {
            let output = try environment.processRunner.run("/bin/ps", arguments: ["-Ao", "pid=,command="])
            if output.status == 0 {
                runningProcesses = output.stdout
                    .split(separator: "\n")
                    .compactMap(parseRunningProcess)
            } else if !output.stderr.isEmpty {
                warnings.append("ps 조회에 실패했습니다: \(output.stderr.trimmingCharacters(in: .whitespacesAndNewlines))")
            }
        } catch {
            warnings.append("ps 조회에 실패했습니다: \(error.localizedDescription)")
        }

        return CommandSnapshot(
            packageReceipts: packageReceipts,
            systemExtensions: systemExtensions,
            launchdEntries: launchdEntries,
            runningProcesses: runningProcesses
        )
    }

    private func collectFileSnapshot() -> [FileSnapshotEntry] {
        let roots = environment.runtimePaths.applicationRoots +
            environment.runtimePaths.privilegedHelperRoots +
            environment.runtimePaths.launchAgentRoots

        var snapshot: [FileSnapshotEntry] = []
        for root in roots where environment.fileManager.fileExists(atPath: root.path) {
            for url in walk(root: root, maxDepth: 4) where url.path != root.path {
                snapshot.append(
                    FileSnapshotEntry(
                        root: root,
                        url: url,
                        loweredName: url.lastPathComponent.lowercased()
                    )
                )
            }
        }
        return snapshot
    }

    private func discoverArtifacts(
        for signature: Signature,
        commandSnapshot: CommandSnapshot,
        fileSnapshot: [FileSnapshotEntry],
        warnings: inout [String]
    ) throws -> [Artifact] {
        var artifacts = Set<Artifact>()
        let exactPaths = signature.paths.map(environment.expand)
        let loweredExactPaths = exactPaths.map { $0.lowercased() }
        let loweredBundleIDs = signature.bundleIds.map { $0.lowercased() }

        for path in exactPaths where environment.fileManager.fileExists(atPath: path) {
            let kind: ArtifactKind = path.hasSuffix(".plist") ? .launchdPlist : (path.hasSuffix(".app") ? .appBundle : .supportFile)
            artifacts.insert(Artifact(kind: kind, value: path, path: path, requiresSudo: path.hasPrefix("/Library") || path.hasPrefix("/Applications")))
        }

        let searchTerms = Set(signature.searchTerms.map { $0.lowercased() })
        for entry in fileSnapshot where searchTerms.contains(where: { entry.loweredName.contains($0) }) {
            let kind = classify(path: entry.url.path, under: entry.root)
            artifacts.insert(Artifact(kind: kind, value: entry.url.lastPathComponent, path: entry.url.path, requiresSudo: entry.url.path.hasPrefix("/")))
        }

        if !signature.pkgReceipts.isEmpty || !searchTerms.isEmpty {
            for line in commandSnapshot.packageReceipts {
                let lower = line.lowercased()
                if signature.pkgReceipts.contains(where: { lower.contains($0.lowercased()) }) ||
                    searchTerms.contains(where: { lower.contains($0) }) {
                    artifacts.insert(Artifact(kind: .packageReceipt, value: line, path: nil, requiresSudo: true))
                }
            }
        }

        for line in commandSnapshot.systemExtensions {
            let lower = line.lowercased()
            if loweredBundleIDs.contains(where: { lower.contains($0) }) ||
                searchTerms.contains(where: { lower.contains($0) }) {
                artifacts.insert(Artifact(kind: .systemExtension, value: line, path: nil, requiresSudo: true))
            }
        }

        for label in signature.launchdLabels {
            let lowerLabel = label.lowercased()
            for entry in fileSnapshot where entry.root.path.contains("Launch") && entry.url.path.hasSuffix(".plist") {
                if entry.loweredName.contains(lowerLabel) {
                    artifacts.insert(Artifact(kind: .launchdPlist, value: label, path: entry.url.path, requiresSudo: entry.url.path.hasPrefix("/Library")))
                }
            }
            for entry in commandSnapshot.launchdEntries where entry.label.lowercased().contains(lowerLabel) {
                artifacts.insert(Artifact(kind: .launchdService, value: entry.label, path: nil, requiresSudo: true))
            }
        }

        for process in commandSnapshot.runningProcesses {
            let lowerExecutable = process.executable.lowercased()
            let matchesPath = loweredExactPaths.contains(where: { lowerExecutable.contains($0) })
            let matchesBundle = loweredBundleIDs.contains(where: { lowerExecutable.contains($0) })
            let matchesTerm = searchTerms.contains(where: { lowerExecutable.contains($0) })
            if matchesPath || matchesBundle || matchesTerm {
                artifacts.insert(
                    Artifact(
                        kind: .runningProcess,
                        value: "\(process.pid)\t\(process.command)",
                        path: nil,
                        requiresSudo: true
                    )
                )
            }
        }

        if !warnings.isEmpty {
            _ = warnings
        }

        return collapseArtifacts(Array(artifacts))
    }

    private func parseLaunchdEntry(_ line: Substring) -> LaunchdEntry? {
        let parts = line.split(separator: "\t").map(String.init)
        guard let label = parts.last, parts.count >= 3 else {
            return nil
        }

        let pid = Int(parts[0])
        return LaunchdEntry(label: label, pid: pid)
    }

    private func parseRunningProcess(_ line: Substring) -> RunningProcess? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else {
            return nil
        }

        let parts = trimmed.split(maxSplits: 1, whereSeparator: \.isWhitespace)
        guard parts.count == 2, let pid = Int(parts[0]) else {
            return nil
        }

        let command = String(parts[1])
        let executable = command.split(separator: " ").first.map(String.init) ?? command
        return RunningProcess(pid: pid, executable: executable, command: command)
    }

    private func processID(from artifact: Artifact) -> Int? {
        guard artifact.kind == .runningProcess else {
            return nil
        }

        let parts = artifact.value.split(maxSplits: 1, whereSeparator: \.isWhitespace)
        guard let first = parts.first else {
            return nil
        }
        return Int(first)
    }

    private func parseSystemExtensionReference(from artifact: Artifact) -> SystemExtensionReference? {
        guard artifact.kind == .systemExtension else {
            return nil
        }

        let tokens = artifact.value
            .split(whereSeparator: \.isWhitespace)
            .filter { $0 != "*" }
            .map(String.init)
        guard tokens.count >= 2 else {
            return nil
        }

        return SystemExtensionReference(teamID: tokens[0], bundleID: tokens[1], rawValue: artifact.value)
    }

    private func csrutilStatus() -> Bool? {
        guard environment.fileManager.isExecutableFile(atPath: "/usr/bin/csrutil") else {
            return nil
        }

        do {
            let output = try environment.processRunner.run("/usr/bin/csrutil", arguments: ["status"])
            let statusText = [output.stdout, output.stderr].joined(separator: "\n").lowercased()
            if statusText.contains("enabled") {
                return true
            }
            if statusText.contains("disabled") {
                return false
            }
        } catch {
            return nil
        }
        return nil
    }

    private func makeDoctorResidual(from finding: Finding) -> DoctorResidual? {
        let launchdServices = finding.artifacts
            .filter { $0.kind == .launchdService }
            .map(\.value)
            .sorted()
        let runningProcesses = finding.artifacts
            .filter { $0.kind == .runningProcess }
            .map(\.value)
            .sorted()
        let systemExtensions = finding.artifacts
            .filter { $0.kind == .systemExtension }
            .map(\.value)
            .sorted()
        let packageReceipts = finding.artifacts
            .filter { $0.kind == .packageReceipt }
            .map(\.value)
            .sorted()

        guard !launchdServices.isEmpty || !runningProcesses.isEmpty || !systemExtensions.isEmpty || !packageReceipts.isEmpty else {
            return nil
        }

        return DoctorResidual(
            findingID: finding.id,
            product: finding.product,
            launchdServices: launchdServices,
            runningProcesses: runningProcesses,
            systemExtensions: systemExtensions,
            packageReceipts: packageReceipts
        )
    }

    private func classify(path: String, under root: URL) -> ArtifactKind {
        if path.hasSuffix(".app") {
            return .appBundle
        }
        if path.hasSuffix(".plist") && root.path.contains("Launch") {
            return .launchdPlist
        }
        if root.path.contains("PrivilegedHelperTools") {
            return .privilegedHelper
        }
        if root.path.contains("Safari") || root.path.contains("Chrome") {
            return .browserExtension
        }
        if root.path.contains("Preferences") {
            return .preference
        }
        if root.path.contains("Caches") {
            return .cache
        }
        return .supportFile
    }

    private func walk(root: URL, maxDepth: Int) -> [URL] {
        var results: [URL] = []
        var queue: [(URL, Int)] = [(root, 0)]

        while let (current, depth) = queue.first {
            queue.removeFirst()
            guard depth <= maxDepth else { continue }

            if current.path != root.path {
                results.append(current)
            }

            var isDirectory: ObjCBool = false
            guard environment.fileManager.fileExists(atPath: current.path, isDirectory: &isDirectory), isDirectory.boolValue else {
                continue
            }

            guard let children = try? environment.fileManager.contentsOfDirectory(
                at: current,
                includingPropertiesForKeys: nil,
                options: [.skipsHiddenFiles]
            ) else {
                continue
            }

            for child in children {
                queue.append((child, depth + 1))
            }
        }

        return results
    }

    private func collapseArtifacts(_ artifacts: [Artifact]) -> [Artifact] {
        let sorted = artifacts.sorted {
            switch ($0.path, $1.path) {
            case let (lhs?, rhs?):
                if lhs.count != rhs.count {
                    return lhs.count < rhs.count
                }
                return lhs < rhs
            case (.some, .none):
                return true
            case (.none, .some):
                return false
            case (.none, .none):
                return $0.id < $1.id
            }
        }

        var kept: [Artifact] = []
        for artifact in sorted {
            guard let path = artifact.path else {
                kept.append(artifact)
                continue
            }

            let isCovered = kept.contains { keptArtifact in
                guard let keptPath = keptArtifact.path else { return false }
                if keptArtifact.kind == .launchdPlist || artifact.kind == .launchdPlist {
                    return keptPath == path
                }
                return path == keptPath || path.hasPrefix(keptPath + "/")
            }

            if !isCovered {
                kept.append(artifact)
            }
        }

        return kept.sorted { $0.id < $1.id }
    }

    private struct RemovalPlan {
        let removableArtifacts: [Artifact]
        let launchdServices: [String]
        let processIDs: [Int]
        let packageReceipts: [String]
        let systemExtensions: [SystemExtensionReference]
        let warnings: [String]
    }

    private struct SystemExtensionReference: Hashable {
        let teamID: String
        let bundleID: String
        let rawValue: String
    }

    private func buildRemovalPlan(for findings: [Finding]) -> RemovalPlan {
        let allArtifacts = findings.flatMap(\.artifacts)
        let collapsed = collapseArtifacts(allArtifacts)

        let removableKinds: Set<ArtifactKind> = [.launchdPlist, .appBundle, .supportFile, .preference, .cache, .browserExtension, .privilegedHelper]
        let removable = collapsed
            .filter { artifact in
                guard let _ = artifact.path else { return false }
                return removableKinds.contains(artifact.kind)
            }
            .sorted { lhs, rhs in
                let leftPriority = removalPriority(for: lhs.kind)
                let rightPriority = removalPriority(for: rhs.kind)
                if leftPriority != rightPriority {
                    return leftPriority < rightPriority
                }
                return (lhs.path ?? "") < (rhs.path ?? "")
            }

        let launchdServices = collapsed
            .filter { $0.kind == .launchdService }
            .map(\.value)
            .sorted()

        let processIDs = collapsed
            .filter { $0.kind == .runningProcess }
            .compactMap(processID(from:))
            .sorted()

        let packageReceipts = collapsed
            .filter { $0.kind == .packageReceipt }
            .map(\.value)
            .sorted()

        let systemExtensions = Set(
            collapsed
                .filter { $0.kind == .systemExtension }
                .compactMap(parseSystemExtensionReference(from:))
        )
        .sorted { lhs, rhs in
            if lhs.teamID != rhs.teamID {
                return lhs.teamID < rhs.teamID
            }
            return lhs.bundleID < rhs.bundleID
        }

        let warnings = collapsed.compactMap { artifact -> String? in
            guard artifact.path == nil else { return nil }
            switch artifact.kind {
            case .backgroundTask:
                return "백그라운드 태스크는 자동 삭제하지 않았습니다: \(artifact.value)"
            case .systemExtension:
                return parseSystemExtensionReference(from: artifact) == nil
                    ? "시스템 확장을 해석하지 못해 자동 삭제에서 제외했습니다: \(artifact.value)"
                    : nil
            case .launchdService, .packageReceipt, .runningProcess:
                return nil
            default:
                return "경로가 없는 \(artifact.kind.rawValue) 아티팩트는 자동 삭제하지 않았습니다: \(artifact.value)"
            }
        }

        return RemovalPlan(
            removableArtifacts: removable,
            launchdServices: launchdServices,
            processIDs: processIDs,
            packageReceipts: packageReceipts,
            systemExtensions: systemExtensions,
            warnings: warnings.sorted()
        )
    }

    private func removalPriority(for kind: ArtifactKind) -> Int {
        switch kind {
        case .launchdPlist:
            return 0
        case .launchdService:
            return 0
        case .privilegedHelper:
            return 1
        case .appBundle, .supportFile:
            return 2
        case .preference, .cache, .browserExtension:
            return 3
        case .packageReceipt, .runningProcess, .systemExtension, .backgroundTask:
            return 4
        }
    }

    private func selectFindings(from findings: [Finding], options: RemoveOptions) throws -> [Finding] {
        let selected: [Finding]
        if options.removeAllSafe {
            selected = findings.filter { $0.risk != .high }
        } else if !options.ids.isEmpty {
            let selectedIDs = Set(options.ids)
            selected = findings.filter { selectedIDs.contains($0.id) }
        } else {
            throw GuraError.noFindingsSelected
        }

        guard !selected.isEmpty else {
            throw GuraError.noFindingsSelected
        }

        let lowConfidence = selected.filter { $0.confidence == .low }
        if !lowConfidence.isEmpty && !options.allowLowConfidence {
            let ids = lowConfidence.map(\.id).joined(separator: ", ")
            throw GuraError.removalRefused("low confidence 항목은 --allow-low-confidence 없이는 삭제할 수 없습니다: \(ids)")
        }

        let highRisk = selected.filter { $0.risk == .high }
        if !highRisk.isEmpty && !options.forceHighRisk {
            let ids = highRisk.map(\.id).joined(separator: ", ")
            throw GuraError.removalRefused("high risk 항목은 --force-high-risk 없이는 삭제할 수 없습니다: \(ids)")
        }

        return selected
    }

    private func backupURL(for original: URL, under root: URL) -> URL {
        let relative = original.path.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        return root.appendingPathComponent(relative, isDirectory: false)
    }

    private func copyPreservingDirectory(source: URL, destination: URL) throws {
        if environment.fileManager.fileExists(atPath: destination.path) {
            try environment.fileManager.removeItem(at: destination)
        }
        try environment.fileManager.copyItem(at: source, to: destination)
    }

    private func loadSession(sessionID: String?) throws -> BackupSession {
        try environment.ensureDirectories()
        let targetURL: URL
        if let sessionID {
            targetURL = environment.backupRootURL.appendingPathComponent(sessionID, isDirectory: true)
        } else if let latest = try history().first {
            targetURL = environment.backupRootURL.appendingPathComponent(latest.sessionID, isDirectory: true)
        } else {
            throw GuraError.restoreSessionMissing(sessionID ?? "latest")
        }

        let manifestURL = targetURL.appendingPathComponent("manifest.json", isDirectory: false)
        guard environment.fileManager.fileExists(atPath: manifestURL.path) else {
            throw GuraError.restoreSessionMissing(sessionID ?? "latest")
        }
        return try decoder.decode(BackupSession.self, from: Data(contentsOf: manifestURL))
    }

    private func sessionIdentifier() -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withDashSeparatorInDate, .withColonSeparatorInTime]
        return formatter.string(from: Date()).replacingOccurrences(of: ":", with: "-")
    }
}
