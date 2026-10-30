# iOS

The iOS SDK of this repository: the generic OAuth 2.0 / OpenID Connect client, Swift 6, product
`VersolaOAuth`. Documentation: the SDK documentation will be hosted at <https://docs.versola.kz>;
until then this README, [`spec/oauth-sdk-api.md`](../spec/oauth-sdk-api.md) and the doc comments are
the source. The `Versola` facade is not built on iOS.

## Targets and product

The manifest is `Package.swift` at the repository root, not in this directory: Swift Package
Manager cannot resolve a manifest from a subdirectory. Its targets point into `ios/Sources` and
`ios/Tests`.

| Target | Role |
|---|---|
| `OAuthCore` | The protocol engine: discovery, PKCE, the authorization flow, the token client, ID-token validation, the session coordinator, the error taxonomy. Foundation, CryptoKit and Security only; no UI, no Keychain, no browser |
| `OAuthClient` | The generic facade and the platform halves it wires: the Keychain stores, `ASWebAuthenticationSession`, the authenticated `URLSession` wrapper, the Secure Enclave DPoP key. Re-exports `OAuthCore` |
| `VersolaCore`, `VersolaDPoP`, `VersolaStorage`, `VersolaBrowser`, `VersolaURLSession` | Placeholders for the Versola facade, which does not exist on iOS. They are listed as products but contain nothing to use |

An app depends on the product `VersolaOAuth` (the library over the `OAuthClient` target) and
imports the module `OAuthClient`, which also exports `OAuthCore`. The package is source, not a
binary framework.

## Installation

Not published: no release tag exists, so there is no version to pin; the first will be 0.1.0. The
repository is private, so the machine that resolves the package needs Git access to it. Consume it
today by URL, on a branch or a commit, or by path:

```swift
// Package.swift of the app
dependencies: [
    .package(url: "https://github.com/versolauth/versola-sdk.git", branch: "main"),
    // or, from a local checkout:
    // .package(path: "../versola-sdk"),
],
targets: [
    .target(
        name: "App",
        dependencies: [.product(name: "VersolaOAuth", package: "versola-sdk")]
    ),
]
```

In Xcode, use File > Add Package Dependencies with the same URL and add `VersolaOAuth` to the
app target. The `package:` value is the dependency's identity (the last path component of the URL,
or the directory name for a path dependency); if your checkout lives under another name, use the
name Xcode or SwiftPM reports. This snippet has not been built against the private URL, only the
repository's own `swift package resolve` step proves the manifest resolves
(`.github/workflows/ios.yml`).

CocoaPods is not supported.

## Platform floor

The SDK targets iOS 17.4 and later. The reason is the browser leg: `ASWebAuthenticationSession`
accepts an `https` callback (a Universal Link) only through `Callback.https(host:path:)`, which
Apple makes available from iOS 17.4, and a Universal Link is the redirect the SDK prefers
([architecture review](../docs/reviews/architecture-review-2026-10-12.md), finding F11).

`Package.swift` also lists macOS 14.4, and that is only a test host: it lets `swift test` compile
the same AuthenticationServices, Keychain and CryptoKit APIs on a Mac. macOS is not a supported
platform: there is no CI run on it, no device tier and no promise.

## Usage

```swift
import OAuthClient
import UIKit

let configuration = try OAuthConfiguration(
    issuer: "https://id.example.com",
    clientId: "example-app",
    redirectUri: "https://app.example.com/oauth",
    postLogoutRedirectUri: "https://app.example.com/signed-out",
    scopes: ["openid", "profile", "offline_access"],
    protectedOrigins: ["https://api.example.com"]
)

let oauth = try await OAuthClient.create(
    configuration: configuration,
    presentationAnchor: { window }          // a UIWindow the app owns
)
```

`OAuthConfiguration` validates eagerly: a bad value throws
`OAuthError.configuration(.invalidConfiguration)` from the initializer, not later behind a sign-in
screen. It has no `clientSecret` parameter, on purpose. `create` is static and `async`: it returns
the existing client for the same issuer and client id, and refuses a different configuration for
the same pair. It does no network I/O and generates no key.

```swift
// Observe: one stream per call; the first value is the restored state.
Task {
    for await state in await oauth.sessionStates() { render(state) }
}

do {
    try await oauth.login()
    let session = try oauth.authenticatedSession()         // origins default to protectedOrigins
    let request = URLRequest(url: URL(string: "https://api.example.com/me")!)
    let (data, response) = try await session.data(for: request)
    let claims = await oauth.claims                        // the validated ID token's claims
    let outcome = await oauth.logout()                     // sessionEnded, tokenRevoked
} catch let error as OAuthError {
    switch error {
    case .recoverable(let cause): retryOrAskAgain(cause)
    case .reauthenticate(let reason): showSignIn(reason)
    case .stepUp(let acrValues, let maxAge):
        try await oauth.stepUp(acrValues: acrValues, maxAge: maxAge)   // then repeat the call
    case .configuration: throw error
    }
}
```

`AuthenticatedSession.data(for:)` attaches the token only to requests for the protected origins,
refreshes once and replays once on a 401, retries once on a DPoP nonce challenge, raises
`stepUp` on an RFC 9470 challenge, never follows redirects, and passes every other request through
untouched. `oauth.accessToken()` returns the token as a value for other HTTP stacks; a token handed
to app code is one the app can log.

### `presentationAnchor`

The browser sheet is presented from a window the app supplies. The SDK never looks for one itself
(no `UIApplication.shared.keyWindow`). The closure is `@escaping @MainActor @Sendable` and returns
an `ASPresentationAnchor`, which is a `UIWindow` on iOS.

### Universal Link and `handleRedirect`

`ASWebAuthenticationSession` returns its own redirect, so in the normal flow the app writes no
redirect code. Two things are needed for an `https` redirect URI:

- The app's `webcredentials` associated domain for the redirect URI's host, with the matching
  `apple-app-site-association` file served on that host. `applinks` alone is not enough for the
  `https` callback of `ASWebAuthenticationSession`
  ([review](../docs/reviews/architecture-review-2026-10-12.md), finding F11;
  [`REVIEW.md`](../REVIEW.md)). This repository contains no iOS sample app that demonstrates the
  entitlement, so the exact setup is not shown or proven here.
- Register the exact redirect URI with the provider.

For an authorization that outlives the process that started it, the app hands the link it received
to the client from its URL handler and resumes:

```swift
// In the handler for a Universal Link (for example onOpenURL or application(_:continue:)).
let handled = await oauth.handleRedirect(url)   // true when the URL was this client's redirect

// On launch, when the restored state is .authorizing.
try await oauth.resumePendingAuthorization()
```

`handleRedirect` matches the URL by scheme, host and path against the configured redirect URI. The
spec describes cold-start completion without an explicit resume call
([`spec/oauth-sdk-api.md`](../spec/oauth-sdk-api.md), section 4), whereas this iOS API exposes
`resumePendingAuthorization()` and a cold-start redirect needs it; the difference is not yet
recorded as a deviation in the spec.

A private-use scheme redirect is accepted with a logged warning on every `create`, because any app
on the device can register the same scheme. A cleartext `http` redirect cannot be received by
`ASWebAuthenticationSession` and is refused.

`LoginOptions(ephemeralBrowser: true)` maps to `prefersEphemeralWebBrowserSession`. It is off by
default because it breaks passkeys and single sign-on.

## Storage and keys

- The refresh token, the raw ID token and the pending request are Keychain items with
  `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and `kSecAttrSynchronizable = false`: usable by
  a background refresh after the first unlock, never restored onto another device, never in iCloud
  Keychain. Under `unlockPolicy: .onAppUnlock` the items use
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` instead.
- The DPoP key is opt-in (`tokenBinding: .dpop()`) and applies when the provider advertises `ES256`.
  It is a Secure Enclave P-256 key whose encrypted `dataRepresentation` is persisted in the Keychain
  as `AfterFirstUnlockThisDeviceOnly`, not synchronizable, whatever the unlock policy; it is not gated on user presence, because a proof is signed on
  every request. A device without a Secure Enclave, and the simulator, get a software key, and
  `try await oauth.keyAttestation()` reports which tier the loaded key is (`secureEnclave` or
  `software`). `.dpop(required: true)` fails with `providerUnsupported("dpop")` when the provider
  does not advertise DPoP instead of falling back to bearer.
- Caches (discovery metadata, JWKS) are files under Application Support, excluded from backup.
- Nothing credential-shaped is logged. The default logger, `OSLogLogger`, emits warnings only.

## Concurrency model

The package builds in Swift 6 language mode, so a concurrency diagnostic is a compile error.
`OAuthClient` is a `Sendable` final class; configuration, state, errors and tokens are `Sendable`
values. Mutable state lives in actors: one session coordinator, so a refresh is single-flight and
callers coalesce on its result. `sessionStates()` creates a stream per call, so several observers
do not starve one another. Every public operation is `async` or `async throws`; there are no
completion-handler APIs. Cancelling the calling task dismisses the browser sheet, but a token that
already came back from the provider is still persisted. The SDK schedules no background work: the
app owns `BGAppRefreshTask`, and a refresh started from one can be cancelled.

## Errors and states

`OAuthError` has the four categories of [`spec/errors.md`](../spec/errors.md) as enum cases:
`.recoverable`, `.reauthenticate`, `.stepUp(acrValues:maxAge:)` and `.configuration`, each with a
payload naming the case. `SessionState` has the seven states of
[`spec/state-machine.md`](../spec/state-machine.md). The category tells the app what to do:
recoverable means retry or ask again, reauthenticate means send the user through `login()`, step-up
means call `stepUp` and repeat the call, and configuration means fix a deployment mistake.

## Tests

From the repository root. The simulator name is whatever your Xcode ships; list yours with
`xcrun simctl list devices available`.

```bash
swift package resolve
swift test                         # macOS host: the fast loop
xcodebuild test -scheme Versola-Package -destination "platform=iOS Simulator,name=iPhone 17"
```

`xcodebuild` on a simulator is what `ios.yml` runs and is the run to report. The Keychain round
trip against the real Keychain runs only with `OAUTH_KEYCHAIN_TESTS=1`, and neither run exercises
the Secure Enclave or a real Keychain access group: that is the device tier, which is not run.

The conformance target, `OAuthConformanceTests`, runs scenarios 24 to 32 against Keycloak or Ory
Hydra in Docker and is skipped without `OAUTH_CONFORMANCE_ISSUER`; it has no CI job, because the
macOS runners have no Docker daemon. Commands are in [`develop.md`](../develop.md), and what that
tier does and does not prove is in [`conformance/README.md`](../conformance/README.md).
