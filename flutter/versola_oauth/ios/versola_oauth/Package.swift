// swift-tools-version: 5.9
// The iOS half of the versola_oauth plugin: glue over the VersolaOAuth product of this
// repository's package (Package.swift at the repository root), resolved by path. Swift Package
// Manager only: the SDK is not on CocoaPods (release.yml keeps `pod trunk push` dormant), so
// there is no podspec here and an app with SwiftPM disabled cannot use the plugin.
import PackageDescription

let package = Package(
    name: "versola_oauth",
    platforms: [
        // The SDK's floor (ios-swift.md): https callbacks in ASWebAuthenticationSession.
        .iOS("17.4")
    ],
    products: [
        .library(name: "versola-oauth", targets: ["versola_oauth"])
    ],
    dependencies: [
        .package(name: "FlutterFramework", path: "../FlutterFramework"),
        .package(name: "Versola", path: "../../../.."),
    ],
    targets: [
        .target(
            name: "versola_oauth",
            dependencies: [
                .product(name: "FlutterFramework", package: "FlutterFramework"),
                .product(name: "VersolaOAuth", package: "Versola"),
            ],
            resources: [
                .process("PrivacyInfo.xcprivacy")
            ]
        )
    ]
)
