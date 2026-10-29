// swift-tools-version:6.0
// At the repo root because SPM cannot resolve a manifest from a subdirectory (#1 §3,
// #4). Targets point their path: into ios/ so Xcode still sees a normal ios/ tree.
//
// Tools 6.0 for `swiftLanguageMode(.v6)` per target (strict concurrency is part of the
// language mode); the floor is iOS 17.4 (issue #46 decision 6: https callbacks in
// ASWebAuthenticationSession, architecture review F11) and macOS 14.4 so that `swift test`
// on a host compiles the same AuthenticationServices API.
import PackageDescription

let package = Package(
    name: "Versola",
    platforms: [
        .iOS("17.4"),
        .macOS("14.4"),
    ],
    products: [
        // The generic facade (issue #46, spec/oauth-sdk-api.md): what an app imports.
        .library(name: "VersolaOAuth", targets: ["OAuthClient"]),
        .library(name: "VersolaCore", targets: ["VersolaCore"]),
        .library(name: "VersolaDPoP", targets: ["VersolaDPoP"]),
        .library(name: "VersolaStorage", targets: ["VersolaStorage"]),
        .library(name: "VersolaBrowser", targets: ["VersolaBrowser"]),
        .library(name: "VersolaURLSession", targets: ["VersolaURLSession"]),
    ],
    targets: [
        // The protocol engine of the generic OAuth SDK (ADR 0001, Android's :oauth-core):
        // discovery, PKCE, the authorization flow, the token client, ID-token validation, the
        // session coordinator, the error taxonomy. Foundation, CryptoKit and Security only;
        // nothing Versola-specific, no UI, no Keychain, no browser.
        .target(
            name: "OAuthCore",
            path: "ios/Sources/OAuthCore",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "OAuthCoreTests",
            dependencies: ["OAuthCore"],
            path: "ios/Tests/OAuthCoreTests",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),

        // The generic facade: OAuthConfiguration, OAuthClient, and the platform halves it
        // wires (Keychain stores, ASWebAuthenticationSession, the authenticated URLSession,
        // the Secure Enclave DPoP key). Published as VersolaOAuth.
        .target(
            name: "OAuthClient",
            dependencies: ["OAuthCore"],
            path: "ios/Sources/OAuthClient",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "OAuthClientTests",
            dependencies: ["OAuthClient"],
            path: "ios/Tests/OAuthClientTests",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        // The generic facade's conformance driver (conformance/README.md, "Providers"; the
        // twin of android/conformance-oauth): scenarios 24 to 32 against a provider container,
        // through an in-process proxy, with the provider's login form driven over HTTP. Every
        // test is skipped unless OAUTH_CONFORMANCE_ISSUER is set.
        .testTarget(
            name: "OAuthConformanceTests",
            dependencies: ["OAuthClient"],
            path: "ios/Tests/OAuthConformanceTests",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),

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
