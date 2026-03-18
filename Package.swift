// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "gura-remover-mac",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .executable(name: "gura", targets: ["GuraCLI"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.5.0"),
    ],
    targets: [
        .target(
            name: "GuraCore",
            resources: [
                .process("Resources"),
            ]
        ),
        .executableTarget(
            name: "GuraCLI",
            dependencies: [
                "GuraCore",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
            ]
        ),
        .testTarget(
            name: "GuraCoreTests",
            dependencies: ["GuraCore"]
        ),
    ]
)
