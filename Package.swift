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
