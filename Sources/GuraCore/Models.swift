import Foundation

public enum RiskLevel: String, Codable, CaseIterable, Comparable, Sendable {
    case low
    case medium
    case high

    private var weight: Int {
        switch self {
        case .low: 0
        case .medium: 1
        case .high: 2
        }
    }

    public static func < (lhs: RiskLevel, rhs: RiskLevel) -> Bool {
        lhs.weight < rhs.weight
    }
}

public enum ConfidenceLevel: String, Codable, CaseIterable, Comparable, Sendable {
    case low
    case medium
    case high

    private var weight: Int {
        switch self {
        case .low: 0
        case .medium: 1
        case .high: 2
        }
    }

    public static func < (lhs: ConfidenceLevel, rhs: ConfidenceLevel) -> Bool {
        lhs.weight < rhs.weight
    }
}

public enum ArtifactKind: String, Codable, Sendable {
    case appBundle
    case launchdPlist
    case packageReceipt
    case privilegedHelper
    case systemExtension
    case browserExtension
    case backgroundTask
    case preference
    case cache
    case supportFile
}

public struct Signature: Codable, Sendable {
    public let id: String
    public let vendor: String
    public let product: String
    public let paths: [String]
    public let bundleIds: [String]
    public let launchdLabels: [String]
    public let pkgReceipts: [String]
    public let searchTerms: [String]
    public let risk: RiskLevel
    public let confidence: ConfidenceLevel
}

public struct SignatureCatalog: Codable, Sendable {
    public let version: String
    public let generatedAt: String
    public let signatures: [Signature]
}

public struct Artifact: Codable, Identifiable, Hashable, Sendable {
    public let id: String
    public let kind: ArtifactKind
    public let value: String
    public let path: String?
    public let requiresSudo: Bool

    public init(kind: ArtifactKind, value: String, path: String?, requiresSudo: Bool) {
        self.id = [kind.rawValue, path ?? value].joined(separator: ":")
        self.kind = kind
        self.value = value
        self.path = path
        self.requiresSudo = requiresSudo
    }

    public static func == (lhs: Artifact, rhs: Artifact) -> Bool {
        lhs.id == rhs.id
    }

    public func hash(into hasher: inout Hasher) {
        hasher.combine(id)
    }
}

public struct Finding: Codable, Identifiable, Sendable {
    public let id: String
    public let signatureID: String
    public let vendor: String
    public let product: String
    public let risk: RiskLevel
    public let confidence: ConfidenceLevel
    public let artifacts: [Artifact]

    public init(signature: Signature, artifacts: [Artifact]) {
        self.id = signature.id
        self.signatureID = signature.id
        self.vendor = signature.vendor
        self.product = signature.product
        self.risk = signature.risk
        self.confidence = signature.confidence
        self.artifacts = artifacts.sorted { $0.id < $1.id }
    }
}

public struct ScanReport: Codable, Sendable {
    public let createdAt: Date
    public let signatureVersion: String
    public let findings: [Finding]
    public let warnings: [String]
}

public struct BackupAction: Codable, Sendable {
    public let originalPath: String
    public let backupPath: String
}

public struct BackupSession: Codable, Sendable {
    public let sessionID: String
    public let createdAt: Date
    public let removedFindings: [Finding]
    public let actions: [BackupAction]
    public let warnings: [String]
}

public struct RemovalResult: Codable, Sendable {
    public let session: BackupSession
    public let deletedPaths: [String]
    public let warnings: [String]
}

public struct RestoreResult: Codable, Sendable {
    public let sessionID: String
    public let restoredPaths: [String]
    public let warnings: [String]
}

public struct HistoryEntry: Codable, Sendable {
    public let sessionID: String
    public let createdAt: Date
    public let findingCount: Int
    public let actionCount: Int
}

public struct DoctorReport: Codable, Sendable {
    public let isRoot: Bool
    public let appSupportPath: String
    public let signatureSource: String
    public let availableCommands: [String: Bool]
    public let backupSessionCount: Int
    public let warnings: [String]
}

public struct SignatureUpdateResult: Codable, Sendable {
    public let repository: String
    public let assetName: String
    public let downloadedTo: String
    public let version: String
}
