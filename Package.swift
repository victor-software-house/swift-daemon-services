// swift-tools-version: 6.4
import PackageDescription

// The compiler settings every target of this package shares.
// A target passes swiftSettings: sharedSwiftSettings, or appends its own settings to it.
let sharedSwiftSettings: [SwiftSetting] = [
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
    .enableUpcomingFeature("InferIsolatedConformances"),
    .enableUpcomingFeature("ExistentialAny"),
    .enableUpcomingFeature("MemberImportVisibility"),
    .treatAllWarnings(as: .error),
]

let package = Package(
    name: "swift-daemon-services",
    platforms: [.macOS(.v27)],
    products: [
        .library(name: "KeychainIdentity", targets: ["KeychainIdentity"]),
        .library(name: "KeychainIdentityNIOSSL", targets: ["KeychainIdentityNIOSSL"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.21.2"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.7.5"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.37.7"),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.105.2"),
    ],
    targets: [
        .target(
            name: "KeychainIdentity",
            dependencies: [
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ],
            swiftSettings: sharedSwiftSettings
        ),
        .target(
            name: "KeychainIdentityNIOSSL",
            dependencies: [
                "KeychainIdentity",
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "NIOCore", package: "swift-nio"),
            ],
            swiftSettings: sharedSwiftSettings
        ),
        .testTarget(
            name: "KeychainIdentityTests",
            dependencies: [
                "KeychainIdentity",
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ],
            swiftSettings: sharedSwiftSettings
        ),
        .testTarget(
            name: "KeychainIdentityNIOSSLTests",
            dependencies: [
                "KeychainIdentity",
                "KeychainIdentityNIOSSL",
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOConcurrencyHelpers", package: "swift-nio"),
            ],
            swiftSettings: sharedSwiftSettings
        ),
    ]
)
