// swift-tools-version: 5.9
// The iOS half of the versola plugin: glue over the VersolaSDK product of this
// repository's package (Package.swift at the repository root), resolved by path. Swift Package
// Manager only: the SDK is not on CocoaPods (release.yml keeps `pod trunk push` dormant), so
// there is no podspec here and an app with SwiftPM disabled cannot use the plugin.
import Foundation
import PackageDescription

// repository-root:begin
// The repository root, found from this file's real location. Flutter does not build the plugin
// where it lives: it symlinks this directory into the app (ios/Flutter/ephemeral/Packages/.packages),
// and SwiftPM resolves a relative `path:` against the symlink, not its target, so "../../../.."
// pointed into the app's own tree. Following the symlink first makes the same manifest work in a
// checkout (the example app), in a path dependency on a checkout and in a git dependency (the pub
// cache holds a clone of the whole repository). tools/flutter-prepare-publish.sh does this
// rewrite for versola_oauth only (it replaces the block and the dependency with the release tag by
// URL for pub.dev, where no repository root exists); publishing this plugin needs the same, so
// keep the two markers.
let repositoryRoot = URL(fileURLWithPath: #filePath)
    .resolvingSymlinksInPath()
    .deletingLastPathComponent()  // versola (this directory)
    .deletingLastPathComponent()  // ios
    .deletingLastPathComponent()  // flutter/versola
    .deletingLastPathComponent()  // flutter
    .deletingLastPathComponent()  // repository root
    .path
// repository-root:end

let package = Package(
    name: "versola",
    platforms: [
        // The SDK's floor (ios-swift.md): https callbacks in ASWebAuthenticationSession.
        .iOS("17.4")
    ],
    products: [
        .library(name: "versola", targets: ["versola"])
    ],
    dependencies: [
        .package(name: "FlutterFramework", path: "../FlutterFramework"),
        .package(name: "Versola", path: repositoryRoot),
    ],
    targets: [
        .target(
            name: "versola",
            dependencies: [
                .product(name: "FlutterFramework", package: "FlutterFramework"),
                .product(name: "VersolaSDK", package: "Versola"),
            ],
            resources: [
                .process("PrivacyInfo.xcprivacy")
            ]
        )
    ]
)
