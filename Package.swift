// swift-tools-version:5.9
// At the repo root because SPM cannot resolve a manifest from a subdirectory (#1 §3,
// #4). Targets point their path: into ios/ so Xcode still sees a normal ios/ tree.
import PackageDescription

let package = Package(
    name: "Versola",
    platforms: [
        .iOS(.v16) // Floor per #1 §4.
    ],
    products: [
        .library(name: "VersolaCore", targets: ["VersolaCore"]),
        .library(name: "VersolaDPoP", targets: ["VersolaDPoP"]),
        .library(name: "VersolaStorage", targets: ["VersolaStorage"]),
        .library(name: "VersolaBrowser", targets: ["VersolaBrowser"]),
        .library(name: "VersolaURLSession", targets: ["VersolaURLSession"]),
    ],
    targets: [
        // Protocol core: state machine, error taxonomy, discovery, token/authorization
        // requests. No Versola-specific URLs or routing (see #4's licence decision).
        .target(name: "VersolaCore", path: "ios/Sources/VersolaCore"),
        .testTarget(
            name: "VersolaCoreTests",
            dependencies: ["VersolaCore"],
            path: "ios/Tests/VersolaCoreTests"
        ),

        // DPoP proof generation: hardware-backed EC P-256 keys (Secure Enclave), proof
        // signing, nonce handling. See #1 §4 — the possession-factor key.
        .target(name: "VersolaDPoP", dependencies: ["VersolaCore"], path: "ios/Sources/VersolaDPoP"),
        .testTarget(
            name: "VersolaDPoPTests",
            dependencies: ["VersolaDPoP"],
            path: "ios/Tests/VersolaDPoPTests"
        ),

        // Encrypted persistence: refresh token, raw ID token, pending authorization
        // request, DPoP key reference. See spec/state-machine.md's persistence summary.
        .target(name: "VersolaStorage", dependencies: ["VersolaCore"], path: "ios/Sources/VersolaStorage"),
        .testTarget(
            name: "VersolaStorageTests",
            dependencies: ["VersolaStorage"],
            path: "ios/Tests/VersolaStorageTests"
        ),

        // System browser launch: ASWebAuthenticationSession. Embedded WebView is
        // deliberately unreachable from this module's public API (#1 §4).
        .target(name: "VersolaBrowser", dependencies: ["VersolaCore"], path: "ios/Sources/VersolaBrowser"),
        .testTarget(
            name: "VersolaBrowserTests",
            dependencies: ["VersolaBrowser"],
            path: "ios/Tests/VersolaBrowserTests"
        ),

        // The authenticated HTTP client: attaches DPoP proofs (or bearer, per
        // discovery), single-flight refresh, nonce retry. See #1 §2.
        .target(
            name: "VersolaURLSession",
            dependencies: ["VersolaCore", "VersolaDPoP"],
            path: "ios/Sources/VersolaURLSession"
        ),
        .testTarget(
            name: "VersolaURLSessionTests",
            dependencies: ["VersolaURLSession"],
            path: "ios/Tests/VersolaURLSessionTests"
        ),
    ]
)
