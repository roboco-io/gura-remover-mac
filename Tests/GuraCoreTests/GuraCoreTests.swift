import Foundation
import Testing
@testable import GuraCore

struct StubProcessRunner: ProcessRunning {
    var outputs: [String: ProcessOutput]

    func run(_ executable: String, arguments: [String]) throws -> ProcessOutput {
        let key = ([executable] + arguments).joined(separator: " ")
        return outputs[key] ?? ProcessOutput(status: 0, stdout: "", stderr: "")
    }
}

final class RecordingProcessRunner: ProcessRunning {
    var outputs: [String: ProcessOutput]
    private(set) var invocations: [String] = []

    init(outputs: [String: ProcessOutput]) {
        self.outputs = outputs
    }

    func run(_ executable: String, arguments: [String]) throws -> ProcessOutput {
        let key = ([executable] + arguments).joined(separator: " ")
        invocations.append(key)
        return outputs[key] ?? ProcessOutput(status: 0, stdout: "", stderr: "")
    }
}

struct GuraCoreTests {
    @Test
    func scanFindsConfiguredArtifacts() throws {
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temp) }

        let fakeApp = temp.appendingPathComponent("Applications/TouchEn nxKey.app", isDirectory: true)
        let fakeSupport = temp.appendingPathComponent("Library/Application Support/TouchEn", isDirectory: true)
        try FileManager.default.createDirectory(at: fakeApp, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: fakeSupport, withIntermediateDirectories: true)

        let env = AppEnvironment(
            fileManager: .default,
            processRunner: StubProcessRunner(outputs: [:]),
            appSupportURL: temp.appendingPathComponent("State", isDirectory: true),
            runtimePaths: RuntimePaths(
                applicationRoots: [temp.appendingPathComponent("Applications", isDirectory: true)],
                launchAgentRoots: [],
                privilegedHelperRoots: [],
                browserRoots: [],
                preferenceRoots: [],
                cacheRoots: [],
                supportRoots: [temp.appendingPathComponent("Library/Application Support", isDirectory: true)]
            )
        )

        let service = GuraService(environment: env)
        let report = try service.scan()

        #expect(report.findings.contains(where: { $0.id == "raon.touchennxkey" }))
    }

    @Test
    func scanFindsAhnLabAndNProtectArtifacts() throws {
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temp) }

        let ahnRoot = temp.appendingPathComponent("Applications/AhnLab/ASTx", isDirectory: true)
        let nProtectRoot = temp.appendingPathComponent("Applications/nProtect/nProtect Online Security V1", isDirectory: true)
        let launchAgents = temp.appendingPathComponent("Library/LaunchAgents", isDirectory: true)
        let launchDaemons = temp.appendingPathComponent("Library/LaunchDaemons", isDirectory: true)

        try FileManager.default.createDirectory(at: ahnRoot, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: nProtectRoot, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: launchAgents, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: launchDaemons, withIntermediateDirectories: true)
        try Data().write(to: launchAgents.appendingPathComponent("com.ahnlab.astxagent.plist"))
        try Data().write(to: launchDaemons.appendingPathComponent("com.nprotect.nosintgdmn.plist"))

        let env = AppEnvironment(
            fileManager: .default,
            processRunner: StubProcessRunner(outputs: [
                "/usr/sbin/pkgutil --pkgs": ProcessOutput(
                    status: 0,
                    stdout: """
                    com.ahnlab.astxagent.pkg
                    com.nprotect.nprotectOnlineSecurityV1.install.pkg
                    """,
                    stderr: ""
                ),
                "/bin/launchctl list": ProcessOutput(
                    status: 0,
                    stdout: """
                    321\t0\tcom.astx.firewall.Agent
                    654\t0\tcom.nprotect.nosintgdmn
                    """,
                    stderr: ""
                ),
                "/bin/ps -Ao pid=,command=": ProcessOutput(
                    status: 0,
                    stdout: """
                    321 /Applications/AhnLab/ASTx/astxAgent.app/Contents/MacOS/astxAgent
                    654 /Applications/nProtect/nProtect Online Security V1/nosintgdmn
                    """,
                    stderr: ""
                ),
                "/usr/bin/systemextensionsctl list": ProcessOutput(
                    status: 0,
                    stdout: """
                    * R2PBZJ465V com.nprotect.nosfw (1.0/1) nosfw [activated enabled]
                    """,
                    stderr: ""
                )
            ]),
            appSupportURL: temp.appendingPathComponent("State", isDirectory: true),
            runtimePaths: RuntimePaths(
                applicationRoots: [temp.appendingPathComponent("Applications", isDirectory: true)],
                launchAgentRoots: [launchAgents, launchDaemons],
                privilegedHelperRoots: [],
                browserRoots: [],
                preferenceRoots: [],
                cacheRoots: [],
                supportRoots: [temp.appendingPathComponent("Library/Application Support", isDirectory: true)]
            )
        )

        let service = GuraService(environment: env)
        let report = try service.scan()

        #expect(report.findings.contains(where: { $0.id == "ahnlab.astx" }))
        #expect(report.findings.contains(where: { $0.id == "inca.nprotectonlinesecurity" }))
        let ahnlab = try #require(report.findings.first(where: { $0.id == "ahnlab.astx" }))
        #expect(ahnlab.artifacts.contains(where: { $0.kind == .launchdService }))
        #expect(ahnlab.artifacts.contains(where: { $0.kind == .runningProcess }))
        let nProtect = try #require(report.findings.first(where: { $0.id == "inca.nprotectonlinesecurity" }))
        #expect(nProtect.artifacts.contains(where: { $0.kind == .systemExtension }))
    }

    @Test
    func scanFindsDelfinoArtifacts() throws {
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temp) }

        let delfinoRoot = temp.appendingPathComponent("Applications/Delfino", isDirectory: true)
        let wizveraSupport = temp.appendingPathComponent("Library/Application Support/wizvera/delfino", isDirectory: true)
        let launchAgents = temp.appendingPathComponent("Library/LaunchAgents", isDirectory: true)

        try FileManager.default.createDirectory(at: delfinoRoot, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: wizveraSupport, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: launchAgents, withIntermediateDirectories: true)
        try Data().write(to: launchAgents.appendingPathComponent("com.wizvera.delfino.plist"))

        let env = AppEnvironment(
            fileManager: .default,
            processRunner: StubProcessRunner(outputs: [
                "/usr/sbin/pkgutil --pkgs": ProcessOutput(
                    status: 0,
                    stdout: "com.wizvera.delfino\n",
                    stderr: ""
                )
            ]),
            appSupportURL: temp.appendingPathComponent("State", isDirectory: true),
            runtimePaths: RuntimePaths(
                applicationRoots: [temp.appendingPathComponent("Applications", isDirectory: true)],
                launchAgentRoots: [launchAgents],
                privilegedHelperRoots: [],
                browserRoots: [],
                preferenceRoots: [],
                cacheRoots: [],
                supportRoots: [temp.appendingPathComponent("Library/Application Support", isDirectory: true)]
            )
        )

        let service = GuraService(environment: env)
        let report = try service.scan()

        #expect(report.findings.contains(where: { $0.id == "wizvera.delfino" }))
    }

    @Test
    func removeRejectsLowConfidenceWithoutFlag() throws {
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temp) }

        let fakeApp = temp.appendingPathComponent("Applications/AnySign4PC.app", isDirectory: true)
        try FileManager.default.createDirectory(at: fakeApp, withIntermediateDirectories: true)

        let env = AppEnvironment(
            fileManager: .default,
            processRunner: StubProcessRunner(outputs: [:]),
            appSupportURL: temp.appendingPathComponent("State", isDirectory: true),
            runtimePaths: RuntimePaths(
                applicationRoots: [temp.appendingPathComponent("Applications", isDirectory: true)],
                launchAgentRoots: [],
                privilegedHelperRoots: [],
                browserRoots: [],
                preferenceRoots: [],
                cacheRoots: [],
                supportRoots: []
            )
        )

        let service = GuraService(environment: env)

        do {
            _ = try service.remove(
                options: .init(ids: ["anysign.anysign4pc"], allowLowConfidence: false, assumeYes: true),
                confirm: { _ in true }
            )
            Issue.record("expected low confidence refusal")
        } catch let error as GuraError {
            #expect(error.localizedDescription.contains("--allow-low-confidence"))
        }
    }

    @Test
    func removeCreatesBackupAndRestoreRecoversFile() throws {
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temp) }

        let applicationsRoot = temp.appendingPathComponent("Applications", isDirectory: true)
        let target = applicationsRoot.appendingPathComponent("TouchEn nxKey.app/Contents/Info.plist", isDirectory: false)
        try FileManager.default.createDirectory(at: target.deletingLastPathComponent(), withIntermediateDirectories: true)
        try "payload".data(using: .utf8)?.write(to: target)

        let env = AppEnvironment(
            fileManager: .default,
            processRunner: StubProcessRunner(outputs: [:]),
            appSupportURL: temp.appendingPathComponent("State", isDirectory: true),
            runtimePaths: RuntimePaths(
                applicationRoots: [applicationsRoot],
                launchAgentRoots: [],
                privilegedHelperRoots: [],
                browserRoots: [],
                preferenceRoots: [],
                cacheRoots: [],
                supportRoots: []
            )
        )

        let service = GuraService(environment: env)
        let removal = try service.remove(
            options: .init(ids: ["raon.touchennxkey"], allowLowConfidence: true, assumeYes: true),
            confirm: { _ in true }
        )

        #expect(FileManager.default.fileExists(atPath: target.path) == false)
        let restore = try service.restore(sessionID: removal.session.sessionID)
        #expect(restore.restoredPaths.contains(where: { $0.hasSuffix("/Applications/TouchEn nxKey.app") }))
        #expect(FileManager.default.fileExists(atPath: target.path))
    }

    @Test
    func removeKillsProcessesForgetsReceiptsAndUninstallsSystemExtensions() throws {
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temp) }

        let applicationsRoot = temp.appendingPathComponent("Applications", isDirectory: true)
        let launchDaemons = temp.appendingPathComponent("Library/LaunchDaemons", isDirectory: true)
        let nProtectRoot = applicationsRoot.appendingPathComponent("nProtect/nProtect Online Security V1", isDirectory: true)
        let plist = launchDaemons.appendingPathComponent("com.nprotect.nosintgdmn.plist")

        try FileManager.default.createDirectory(at: nProtectRoot, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: launchDaemons, withIntermediateDirectories: true)
        try Data().write(to: plist)

        let runner = RecordingProcessRunner(outputs: [
            "/usr/sbin/pkgutil --pkgs": ProcessOutput(
                status: 0,
                stdout: "com.nprotect.nprotectOnlineSecurityV1.install.pkg\n",
                stderr: ""
            ),
            "/usr/bin/systemextensionsctl list": ProcessOutput(
                status: 0,
                stdout: "* R2PBZJ465V com.nprotect.nosfw (1.0/1) nosfw [activated enabled]\n",
                stderr: ""
            ),
            "/bin/launchctl list": ProcessOutput(
                status: 0,
                stdout: "654\t0\tcom.nprotect.nosintgdmn\n",
                stderr: ""
            ),
            "/bin/ps -Ao pid=,command=": ProcessOutput(
                status: 0,
                stdout: "654 /Applications/nProtect/nProtect Online Security V1/nosintgdmn\n",
                stderr: ""
            ),
        ])

        let env = AppEnvironment(
            fileManager: .default,
            processRunner: runner,
            appSupportURL: temp.appendingPathComponent("State", isDirectory: true),
            runtimePaths: RuntimePaths(
                applicationRoots: [applicationsRoot],
                launchAgentRoots: [launchDaemons],
                privilegedHelperRoots: [],
                browserRoots: [],
                preferenceRoots: [],
                cacheRoots: [],
                supportRoots: []
            )
        )

        let service = GuraService(environment: env)
        let removal = try service.remove(
            options: .init(ids: ["inca.nprotectonlinesecurity"], forceHighRisk: true, assumeYes: true),
            confirm: { _ in true }
        )

        #expect(removal.operations.contains("launchctl remove com.nprotect.nosintgdmn"))
        #expect(removal.operations.contains("kill -TERM 654"))
        #expect(removal.operations.contains("kill -KILL 654"))
        #expect(removal.operations.contains("pkgutil --forget com.nprotect.nprotectOnlineSecurityV1.install.pkg"))
        #expect(removal.operations.contains("systemextensionsctl uninstall R2PBZJ465V com.nprotect.nosfw"))
        #expect(runner.invocations.contains("/bin/launchctl remove com.nprotect.nosintgdmn"))
        #expect(runner.invocations.contains("/bin/kill -TERM 654"))
        #expect(runner.invocations.contains("/bin/kill -KILL 654"))
        #expect(runner.invocations.contains("/usr/sbin/pkgutil --forget com.nprotect.nprotectOnlineSecurityV1.install.pkg"))
        #expect(runner.invocations.contains("/usr/bin/systemextensionsctl uninstall R2PBZJ465V com.nprotect.nosfw"))
    }

    @Test
    func doctorReportsSipBlockedSystemExtensionResiduals() throws {
        let temp = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: temp) }

        let runner = StubProcessRunner(outputs: [
            "/usr/sbin/pkgutil --pkgs": ProcessOutput(
                status: 0,
                stdout: "com.nprotect.nprotectOnlineSecurityV1.install.pkg\n",
                stderr: ""
            ),
            "/usr/bin/systemextensionsctl list": ProcessOutput(
                status: 0,
                stdout: "* R2PBZJ465V com.nprotect.nosfw (1.0/1) nosfw [activated enabled]\n",
                stderr: ""
            ),
            "/bin/launchctl list": ProcessOutput(status: 0, stdout: "", stderr: ""),
            "/bin/ps -Ao pid=,command=": ProcessOutput(status: 0, stdout: "", stderr: ""),
            "/usr/bin/csrutil status": ProcessOutput(
                status: 0,
                stdout: "System Integrity Protection status: enabled.\n",
                stderr: ""
            ),
        ])

        let env = AppEnvironment(
            fileManager: .default,
            processRunner: runner,
            appSupportURL: temp.appendingPathComponent("State", isDirectory: true),
            runtimePaths: RuntimePaths(
                applicationRoots: [],
                launchAgentRoots: [],
                privilegedHelperRoots: [],
                browserRoots: [],
                preferenceRoots: [],
                cacheRoots: [],
                supportRoots: []
            )
        )

        let doctor = try GuraService(environment: env).doctor()

        #expect(doctor.sipEnabled == true)
        #expect(doctor.residuals.contains(where: { $0.findingID == "inca.nprotectonlinesecurity" }))
        #expect(doctor.warnings.contains(where: { $0.contains("SIP") }))
    }
}
