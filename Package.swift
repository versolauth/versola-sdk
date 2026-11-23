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
        // The Versola facade (spec/versola-sdk-api.md, ADR 0002): a session through a deployment's
        // edge. The module is VersolaSDK and the type is Versola, so that a qualified name can tell
        // the two apart.
        .library(name: "VersolaSDK", targets: ["VersolaSDK"]),
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
            // The privacy manifest declares the file-timestamp API FileCaches reads (App Store
            // privacy manifest requirement); it ships inside the package with the code.
            resources: [.process("PrivacyInfo.xcprivacy")],
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "OAuthClientTests",
            dependencies: ["OAuthClient"],
            path: "ios/Tests/OAuthClientTests",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        // Versola's edge back channel (`/native/start|complete|token|revoke`), Android's `:core`:
        // the starter that has edge build and push the request, the token client that redeems and
        // refreshes through edge, and the metadata the core reads, stated instead of discovered.
        // Foundation and OAuthCore only. Internal: a target and no product; `package` access.
        .target(
            name: "VersolaEdge",
            dependencies: ["OAuthCore"],
            path: "ios/Sources/VersolaEdge",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "VersolaEdgeTests",
            dependencies: ["VersolaEdge", "OAuthCore"],
            path: "ios/Tests/VersolaEdgeTests",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        // The Versola facade: VersolaConfiguration, Versola, and the wiring of the edge channel
        // over the platform halves OAuthClient already has (Keychain stores,
        // ASWebAuthenticationSession, the authenticated URLSession, the Secure Enclave DPoP key),
        // which it reaches through `package` access rather than a second copy of them.
        .target(
            name: "VersolaSDK",
            dependencies: ["OAuthCore", "OAuthClient", "VersolaEdge"],
            path: "ios/Sources/VersolaSDK",
            swiftSettings: [.swiftLanguageMode(.v6)]
        ),
        .testTarget(
            name: "VersolaSDKTests",
            dependencies: ["VersolaSDK", "VersolaEdge", "OAuthClient", "OAuthCore"],
            path: "ios/Tests/VersolaSDKTests",
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
    ]
)
