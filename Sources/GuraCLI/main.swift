import ArgumentParser
import Foundation
import GuraCore

struct CommonOutputOptions: ParsableArguments {
    @Flag(help: "JSON 형식으로 출력합니다.")
    var json = false
}

struct ScanArguments: ParsableArguments {
    @Flag(help: "low confidence 항목을 결과에서 숨깁니다.")
    var hideLowConfidence = false
}

@main
struct GuraCLI: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "gura",
        abstract: "macOS 금융/공공 보안 모듈 탐지 및 제거 CLI",
        subcommands: [
            Scan.self,
            List.self,
            Remove.self,
            Restore.self,
            History.self,
            Doctor.self,
            Signatures.self,
        ]
    )
}

extension GuraCLI {
    struct Scan: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "현재 시스템을 스캔합니다.")

        @OptionGroup var output: CommonOutputOptions
        @OptionGroup var scan: ScanArguments

        mutating func run() throws {
            let report = try GuraService().scan(options: .init(includeLowConfidence: !scan.hideLowConfidence))
            try render(report, asJSON: output.json)
        }
    }

    struct List: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "scan 과 동일한 읽기 전용 목록을 출력합니다.")

        @OptionGroup var output: CommonOutputOptions
        @OptionGroup var scan: ScanArguments

        mutating func run() throws {
            let report = try GuraService().scan(options: .init(includeLowConfidence: !scan.hideLowConfidence))
            try render(report, asJSON: output.json)
        }
    }

    struct Remove: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "선택한 항목 또는 안전한 전체 항목을 삭제합니다.")

        @Option(name: .shortAndLong, parsing: .upToNextOption, help: "삭제할 시그니처 ID 목록")
        var id: [String] = []

        @Flag(help: "high risk 를 제외한 모든 항목을 삭제 대상으로 선택합니다.")
        var allSafe = false

        @Flag(help: "low confidence 항목 삭제를 허용합니다.")
        var allowLowConfidence = false

        @Flag(help: "high risk 항목 삭제를 허용합니다.")
        var forceHighRisk = false

        @Flag(name: .shortAndLong, help: "확인 프롬프트를 생략합니다.")
        var yes = false

        @Flag(help: "백업 및 삭제를 실제 수행하지 않고 계획만 확인합니다.")
        var dryRun = false

        @OptionGroup var output: CommonOutputOptions

        mutating func run() throws {
            let result = try GuraService().remove(
                options: .init(
                    ids: id,
                    removeAllSafe: allSafe,
                    allowLowConfidence: allowLowConfidence,
                    forceHighRisk: forceHighRisk,
                    assumeYes: yes,
                    dryRun: dryRun
                ),
                confirm: promptConfirmation
            )
            try render(result, asJSON: output.json)
        }

        private func promptConfirmation(_ message: String) -> Bool {
            print(message)
            guard let line = readLine(strippingNewline: true) else { return false }
            return line.lowercased() == "yes"
        }
    }

    struct Restore: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "백업 세션을 사용해 최근 삭제를 복구합니다.")

        @Option(name: .shortAndLong, help: "복구할 세션 ID. 생략 시 가장 최근 세션을 사용합니다.")
        var session: String?

        @OptionGroup var output: CommonOutputOptions

        mutating func run() throws {
            let result = try GuraService().restore(sessionID: session)
            try render(result, asJSON: output.json)
        }
    }

    struct History: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "삭제/복구 세션 히스토리를 출력합니다.")

        @OptionGroup var output: CommonOutputOptions

        mutating func run() throws {
            let entries = try GuraService().history()
            try render(entries, asJSON: output.json)
        }
    }

    struct Doctor: ParsableCommand {
        static let configuration = CommandConfiguration(abstract: "권한, 백업, 시그니처, 시스템 명령 상태를 점검합니다.")

        @OptionGroup var output: CommonOutputOptions

        mutating func run() throws {
            let report = try GuraService().doctor()
            try render(report, asJSON: output.json)
        }
    }

    struct Signatures: ParsableCommand {
        static let configuration = CommandConfiguration(
            abstract: "시그니처를 관리합니다.",
            subcommands: [Update.self]
        )

        struct Update: ParsableCommand {
            static let configuration = CommandConfiguration(abstract: "GitHub Release 에서 최신 시그니처 번들을 내려받습니다.")

            @Option(name: .shortAndLong, help: "owner/repo 형식의 GitHub 저장소")
            var repo = "roboco-io/gura-remover-mac"

            @Option(name: .shortAndLong, help: "내려받을 자산 파일명")
            var asset = "signatures.json"

            @OptionGroup var output: CommonOutputOptions

            mutating func run() throws {
                let result = try GuraService().updateSignatures(repository: repo, assetName: asset)
                try render(result, asJSON: output.json)
            }
        }
    }
}

private func render<T: Encodable>(_ value: T, asJSON: Bool) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    encoder.dateEncodingStrategy = .iso8601

    if asJSON {
        let data = try encoder.encode(value)
        if let text = String(data: data, encoding: .utf8) {
            print(text)
        }
        return
    }

    switch value {
    case let report as ScanReport:
        render(report)
    case let result as RemovalResult:
        render(result)
    case let result as RestoreResult:
        render(result)
    case let history as [HistoryEntry]:
        render(history)
    case let doctor as DoctorReport:
        render(doctor)
    case let update as SignatureUpdateResult:
        render(update)
    default:
        let data = try encoder.encode(value)
        if let text = String(data: data, encoding: .utf8) {
            print(text)
        }
    }
}

private func render(_ report: ScanReport) {
    print("Scanned at: \(report.createdAt.ISO8601Format())")
    print("Signature version: \(report.signatureVersion)")
    print("Findings: \(report.findings.count)")
    for finding in report.findings {
        print("- \(finding.id) | \(finding.product) | risk=\(finding.risk.rawValue) | confidence=\(finding.confidence.rawValue)")
        for artifact in finding.artifacts.prefix(5) {
            print("  • \(artifact.kind.rawValue): \(artifact.path ?? artifact.value)")
        }
    }
    if !report.warnings.isEmpty {
        print("Warnings:")
        for warning in report.warnings {
            print("- \(warning)")
        }
    }
}

private func render(_ result: RemovalResult) {
    print("Session: \(result.session.sessionID)")
    print("Deleted paths: \(result.deletedPaths.count)")
    for path in result.deletedPaths {
        print("- \(path)")
    }
    if !result.warnings.isEmpty {
        print("Warnings:")
        for warning in result.warnings {
            print("- \(warning)")
        }
    }
}

private func render(_ result: RestoreResult) {
    print("Restored session: \(result.sessionID)")
    print("Restored paths: \(result.restoredPaths.count)")
    for path in result.restoredPaths {
        print("- \(path)")
    }
    if !result.warnings.isEmpty {
        print("Warnings:")
        for warning in result.warnings {
            print("- \(warning)")
        }
    }
}

private func render(_ history: [HistoryEntry]) {
    if history.isEmpty {
        print("No backup history.")
        return
    }

    for entry in history {
        print("- \(entry.sessionID) | \(entry.createdAt.ISO8601Format()) | findings=\(entry.findingCount) | actions=\(entry.actionCount)")
    }
}

private func render(_ report: DoctorReport) {
    print("Root: \(report.isRoot ? "yes" : "no")")
    print("App support: \(report.appSupportPath)")
    print("Signatures: \(report.signatureSource)")
    print("Backups: \(report.backupSessionCount)")
    print("Commands:")
    for key in report.availableCommands.keys.sorted() {
        print("- \(key): \(report.availableCommands[key] == true ? "ok" : "missing")")
    }
    if !report.warnings.isEmpty {
        print("Warnings:")
        for warning in report.warnings {
            print("- \(warning)")
        }
    }
}

private func render(_ result: SignatureUpdateResult) {
    print("Repository: \(result.repository)")
    print("Asset: \(result.assetName)")
    print("Version: \(result.version)")
    print("Saved to: \(result.downloadedTo)")
}

