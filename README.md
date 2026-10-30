# Versola OAuth SDK for Android, iOS and Flutter

**An OAuth 2.0 and OpenID Connect (OIDC) client library for native mobile apps.** It signs a user in
with the authorization code flow and PKCE in the system browser, validates the ID token, keeps the
session in the platform's secure storage (Android Keystore, iOS Keychain), refreshes tokens without
races, and attaches the access token to API calls. It is written in Kotlin for Android and Swift 6
for iOS, with a Flutter (Dart) binding, and works with any standards-conforming OpenID provider such
as Keycloak or Ory Hydra. If you use AppAuth today, it is an alternative that also does token
refresh coordination, secure storage and ID-token signature validation for you.

Documentation: <https://docs.versola.io>.

## Quick facts

| | |
|---|---|
| What it is | An OAuth 2.0 / OpenID Connect client SDK for native apps (public clients) |
| Platforms | Android (Kotlin, `minSdk` 26), iOS (Swift 6, iOS 17.4 and later), Flutter (Dart 3.13, Flutter 3.47) |
| Names | Android `io.versola:oauth-android` (package `versola.oauth`), iOS product `VersolaOAuth`, Dart `package:versola_oauth` |
| Flow | Authorization code with PKCE `S256`, in the system browser only (Auth Tab or Custom Tabs, `ASWebAuthenticationSession`); no web view |
| Providers | Any OpenID provider that meets the [contract](spec/providers.md); run in the SDK's tests against Keycloak 26.4 and Ory Hydra v26.2.0 |
| Optional | DPoP (RFC 9449), pushed authorization requests (RFC 9126), refresh-token rotation, RP-initiated logout, token revocation |
| Licence | Apache-2.0 |
| Stability | The API is production ready. The major version is still 0, and interfaces change only when a change is required |

## Features

- **Safe by default.** PKCE `S256`, a fresh `state` and `nonce` per request, `iss` checked on the
  redirect, and the ID token validated (signature, `iss`, `aud`, `exp`, `nonce`) before anything is
  stored. None of these can be switched off.
- **Secure storage.** Refresh tokens live in a Keystore-wrapped file on Android and in the Keychain
  (`AfterFirstUnlockThisDeviceOnly`, no iCloud sync) on iOS. Keys are non-exportable and
  hardware-backed where the device has hardware.
- **Refresh that does not race.** Concurrent callers share one token request, and a rotated refresh
  token is stored before the old one is forgotten.
- **Typed errors.** Four categories on every platform: `Recoverable`, `Reauthenticate`, `StepUp`,
  `Configuration`.
- **One session model.** Seven session states, observed as a `Flow` (Kotlin), `AsyncStream` (Swift)
  or `Stream` (Dart).
- **No client secret.** A native app cannot keep one, so the configuration has no field for it.
- **Calls with the token attached.** An OkHttp interceptor on Android and an authenticated
  `URLSession` wrapper on iOS send the token only to the origins you list.

## Quick start

The examples use placeholder values on `example.com`. Register the redirect URI with your provider;
use a verified link the app owns (an Android App Link, an iOS Universal Link). The SDK never adds
`offline_access` to the scopes, so put it in `scopes` if your provider needs it for a refresh
token.

### Install

The current version is on the [Releases](https://github.com/versolauth/versola-sdk/releases) page;
write it where `<version>` stands.

- **Android:** `implementation("io.versola:oauth-android:<version>")` from `mavenCentral()` (and
  `google()`), with `minSdk` 26 and the `compileSdk` described under Flutter below (OkHttp's; the
  SDK's own AARs ask for less).
- **iOS:** Swift Package Manager, `.package(url: "https://github.com/versolauth/versola-sdk", from: "<version>")`,
  product `VersolaOAuth`.
- **Flutter:** a git dependency in `pubspec.yaml` (below), with Swift Package Manager integration
  enabled for iOS.

```yaml
dependencies:
  versola_oauth:
    git:
      url: https://github.com/versolauth/versola-sdk.git
      path: flutter/versola_oauth
      ref: <version>
```

A Flutter app needs `compileSdk` 37 and `minSdk` 26 in `android/app/build.gradle.kts` and an iOS
deployment target of 17.4; a lower value fails the build with a message that names the minimum.
The 37 is OkHttp's: its AAR declares it, and the SDK's own AARs ask for less, so the number follows
the OkHttp release the SDK depends on, not a choice of ours.

### Android (Kotlin)

```kotlin
import okhttp3.Request
import versola.oauth.OAuthClient
import versola.oauth.OAuthConfiguration
import versola.oauth.core.SessionState
import versola.oauth.core.VersolaError

val oauth = OAuthClient.create(
    applicationContext,
    OAuthConfiguration(
        issuer = "https://id.example.com",
        clientId = "example-app",
        redirectUri = "https://app.example.com/oauth",
        scopes = setOf("openid", "profile", "offline_access"),
        protectedOrigins = setOf("https://api.example.com"),
    ),
)

// Observe: a cold Flow whose first emission is the restored state.
lifecycleScope.launch {
    oauth.sessionState.collect { state: SessionState -> render(state) }
}

try {
    oauth.login()                                   // opens the system browser
    val request = Request.Builder().url("https://api.example.com/me").build()
    oauth.call(request).use { response -> /* the token was attached for you */ }
    val token = oauth.accessToken().value           // the escape hatch, for other HTTP stacks
    oauth.logout()
} catch (e: VersolaError) {
    when (e) {
        is VersolaError.Recoverable -> retryOrAskAgain(e.reason)
        is VersolaError.Reauthenticate -> showSignIn(e.reason)
        is VersolaError.StepUp -> oauth.stepUp(e)   // then repeat the refused call
        is VersolaError.Configuration -> throw e    // a deployment mistake, not a user problem
    }
}
```

### iOS (Swift)

```swift
import OAuthClient
import UIKit

let configuration = try OAuthConfiguration(
    issuer: "https://id.example.com",
    clientId: "example-app",
    redirectUri: "https://app.example.com/oauth",
    scopes: ["openid", "profile", "offline_access"],
    protectedOrigins: ["https://api.example.com"]
)
// The window the browser sheet is presented from comes from the app; the SDK never looks for one.
let oauth = try await OAuthClient.create(
    configuration: configuration,
    presentationAnchor: { window }          // a UIWindow the app owns
)

Task {
    for await state in await oauth.sessionStates() { render(state) }   // one stream per observer
}

do {
    try await oauth.login()                                           // opens ASWebAuthenticationSession
    let session = try oauth.authenticatedSession()                    // uses protectedOrigins
    let (data, response) = try await session.data(for: URLRequest(url: URL(string: "https://api.example.com/me")!))
    let token = try await oauth.accessToken().value                   // the escape hatch
    _ = await oauth.logout()
} catch let error as OAuthError {
    switch error {
    case .recoverable(let cause): retryOrAskAgain(cause)
    case .reauthenticate(let reason): showSignIn(reason)
    case .stepUp(let acrValues, let maxAge): try await oauth.stepUp(acrValues: acrValues, maxAge: maxAge)
    case .configuration: throw error
    }
}
```

The Swift package product is `VersolaOAuth`; the module you import is `OAuthClient`.

iOS notes for integrators:

- **Scenes.** Whether the app is in the background when the browser sheet is cancelled is read from
  the scene of the `presentationAnchor` window (`UIApplication.shared` is unavailable to app
  extensions). A window attached to no scene, as in an app that has not adopted UIScene, counts as
  foreground: a system cancel while backgrounded is then read as the user's, and the pending
  request is dropped instead of kept. Adopt UIScene, or expect the user to start the sign-in again.
- **Reinstall.** The Keychain outlives the app, so on the first launch of a fresh install the SDK
  deletes the Keychain items of the client from the app's own access group. An app upgraded from
  0.1.0 keeps its session. The check does not run inside an app extension.
- **Extensions.** The package builds with `-application-extension`. The SDK configures no Keychain
  access group, so an extension has Keychain items of its own unless you share a group yourself.

### Flutter (Dart)

```dart
import 'package:versola_oauth/versola_oauth.dart';

final client = await OAuthClient.create(const OAuthConfiguration(
  issuer: 'https://id.example.com',
  clientId: 'example-app',
  redirectUri: 'https://app.example.com/oauth',
  scopes: {'openid', 'profile', 'offline_access'},
));

client.sessionStates().listen((state) => render(state)); // any number of listeners

try {
  await client.login();
  final api = client.httpClient(); // a package:http Client: the SDK attaches and refreshes the token
  final response = await api.get(Uri.https('api.example.com', '/items'));
  await client.logout();
} on StepUpError catch (e) {
  await client.stepUp(e);
} on ReauthenticateError {
  // show the sign-in screen
} on RecoverableError {
  // retry, or ask the user again
} on ConfigurationError {
  // a deployment mistake: fix the configuration
}
```

## Supported OpenID providers

`OAuthClient` needs four things from a provider: OpenID discovery (or explicit endpoints), the
authorization code flow with PKCE `S256` for a public client, an ID token signed with an asymmetric
algorithm, and an `iss` claim equal to the discovered issuer. Everything else (PAR, DPoP,
revocation, an end-session endpoint, UserInfo) is used when the provider advertises it.

| Provider | Status |
|---|---|
| Keycloak 26.4 | Run in the SDK's tests (container) |
| Ory Hydra v26.2.0 | Run in the SDK's tests (container) |
| Any other conforming provider | Works by the contract in [`spec/providers.md`](spec/providers.md) |

## Standards implemented

| Standard | Used for |
|---|---|
| [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749), [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) | OAuth 2.0 authorization code flow, PKCE |
| [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252) | OAuth 2.0 for native apps: system browser, redirect URIs |
| [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207) | `iss` in the authorization response |
| [RFC 9126](https://www.rfc-editor.org/rfc/rfc9126) | Pushed authorization requests |
| [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) | DPoP (sender-constrained tokens), opt-in |
| [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) | Token revocation |
| [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470) | Step-up authentication challenge |
| [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) | Resource indicators |
| [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html), Discovery 1.0, RP-Initiated Logout 1.0 | ID token, discovery, UserInfo, sign-out |
| [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515), [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) | JWS and JWK for ID-token signatures |

## Frequently asked questions

### What is the Versola OAuth SDK?

An OAuth 2.0 and OpenID Connect client library for Android (Kotlin), iOS (Swift) and Flutter (Dart).
It handles sign-in, token storage, refresh and sign-out in a native app so the app does not assemble
those pieces itself.

### Which OAuth flow does it use?

The authorization code flow with PKCE (`S256`) in the system browser, as RFC 8252 recommends for
native apps. It does not implement the implicit flow or the password grant, and it supports public
clients only.

### Does it work with Keycloak and Ory Hydra?

Yes. The SDK's tests run against Keycloak 26.4 and Ory Hydra v26.2.0 containers. Any other provider
that meets the contract in [`spec/providers.md`](spec/providers.md) should work the same way.

### Does it use a WebView?

No. The browser step runs in an Auth Tab or Custom Tab on Android and in
`ASWebAuthenticationSession` on iOS. A web view cannot be passed in.

### Where are tokens stored?

In the Android Keystore-wrapped store and the iOS Keychain, never in preferences or files in the
clear. On Flutter, the refresh token never leaves the native side; Dart receives only the
short-lived access token when you ask for it.

### Does it support DPoP and PAR?

Yes, both as opt-in or when the provider advertises them: DPoP (RFC 9449) with a hardware-backed
key, and pushed authorization requests (RFC 9126).

### Can it replace AppAuth?

For public clients that use the system browser, yes. It adds ID-token signature validation, secure
storage and refresh coordination, and drops client secrets and embedded browsers. The migration
guide is on the documentation website.

### Is the API production ready?

Yes. The Versola OAuth SDK treats its public API as production ready on Android, iOS and Flutter,
even though the major version is still 0. We won't change an interface unless a change is
required. When one is, the pull request that makes it says so and carries the regenerated API
dump, and the minor version goes up; compatible additions and fixes raise only the patch version.

### How do I add it to my project?

On Android, add `io.versola:oauth-android` from Maven Central. On iOS, add the Swift package
`https://github.com/versolauth/versola-sdk` and use the `VersolaOAuth` product. On Flutter, add
`versola_oauth` as a git dependency from the same repository. The [Install](#install) section has
the coordinates.

### What licence is it under?

Apache-2.0. See [LICENSE](LICENSE).

## Documentation

- The SDK documentation at <https://docs.versola.io>: platform guides, provider guides (Keycloak,
  Ory Hydra) and the AppAuth migration guide.
- [`spec/`](spec/): the specification the three implementations follow
  ([API](spec/oauth-sdk-api.md), [state machine](spec/state-machine.md),
  [errors](spec/errors.md), [retry policy](spec/retry-policy.md),
  [providers](spec/providers.md)).
- [`develop.md`](develop.md): toolchains and commands for contributors; [`AGENTS.md`](AGENTS.md)
  and [`REVIEW.md`](REVIEW.md): the working policy and what a pull request is reviewed against.

## Security

- Fail closed: a check that cannot complete refuses the operation with a typed error, and no check
  can be switched off.
- Tokens and keys never go into logs, error messages or analytics; the refresh token never leaves
  the platform store.
- Report a vulnerability privately through the repository's Security tab, never in a public issue;
  [`SECURITY.md`](SECURITY.md) has the process.

## Repository layout

```text
spec/            the specification: state machine, errors, retry policy, providers, API
android/         Gradle multi-project (module :oauth is the SDK; :oauth-core is the protocol engine)
ios/             Swift sources and tests; the manifest is Package.swift at the repository root
flutter/         versola_oauth: the Flutter binding (Pigeon), with an example app
conformance/     test harness and the provider containers (Keycloak, Ory Hydra)
docs/            decision records and reviews, and the release runbook
```

## Licence

Apache-2.0. See [LICENSE](LICENSE).
