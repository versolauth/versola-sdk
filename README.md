# Versola mobile SDKs

Native OAuth 2.0 / OpenID Connect SDKs for Android (Kotlin), iOS (Swift 6) and Flutter (a binding
over the two native SDKs), in one repository. They sign a user in through the system browser with
PKCE, validate the ID token, keep the session in the platform's secure storage, refresh it without
racing, and attach the token to API calls, so that an app does not assemble those pieces from
parts. The protocol logic is written once per native platform against a shared specification
(`spec/`) and checked by shared conformance scenarios, not by shared code.

Documentation: the SDK documentation will be hosted at <https://docs.versola.kz> (today that site
documents the Versola server and has no SDK section yet). Until then this repository is the
source: `docs/`, `spec/` and the per-platform READMEs listed under [Documentation](#documentation).

Two facades sit over one protocol core:

- **`OAuthClient`, the generic facade**, for any provider that meets the contract in
  [`spec/providers.md`](spec/providers.md). It sends only what a standard defines: bearer tokens by
  default, no `offline_access` added for you, PAR when the provider advertises it. API:
  [`spec/oauth-sdk-api.md`](spec/oauth-sdk-api.md). Android `kz.versola:oauth-android` (package
  `versola.oauth`), iOS product `VersolaOAuth`, Dart `package:versola_oauth`.
- **`Versola`, the facade for the Versola server**: edge back channel, FAPI 2.0 security profiles,
  DPoP by default. Android only today; see [The Versola facade](#the-versola-facade).

Nothing is published. There is no Maven Central artefact, no pub.dev package and no release tag;
the first version will be 0.1.0. The repository is private. Each install section below says how to
consume it from a checkout today.

## Status

What is implemented, and what has been shown to work where. "Conformance" means scenarios 24 to 32
of [`spec/conformance/`](spec/conformance/) run against a real provider in Docker (Keycloak 26.4
and Ory Hydra v26.2.0); [`conformance/README.md`](conformance/README.md) is the authority on what
that tier does and does not prove.

| Platform | Generic `OAuthClient` | Proven by | Not proven |
|---|---|---|---|
| Android (`android/`) | Implemented on `main`: `:oauth` over `:oauth-core`, `:storage`, `:browser`, `:dpop`, `:okhttp` | JVM and Robolectric unit tests; Keystore tests on an emulator for `:storage` and `:dpop` (API 36, `android.yml`); an instrumented smoke test in the sample app (not run in CI); conformance against Keycloak and Hydra in the `providers` job of `conformance.yml` | The browser leg in conformance (it is an HTTP login conversation, so Auth Tab, Custom Tabs and App Link delivery are not driven against a real provider); the DPoP case of scenario 32; any hosted provider |
| iOS (`ios/`, `Package.swift`) | Implemented on `main`: product `VersolaOAuth` (targets `OAuthCore` and `OAuthClient`) | XCTest unit tests (`ios.yml`, iOS simulator); conformance against Keycloak and Hydra, run locally only (the macOS runners have no Docker daemon) | `ASWebAuthenticationSession` against a real provider; Secure Enclave and a real Keychain on a device; the Keychain round trip runs only with `OAUTH_KEYCHAIN_TESTS=1`; any hosted provider |
| Flutter (`flutter/versola_oauth`) | Implemented on `main`: a Pigeon bridge over the two native facades | Dart tests against a mocked channel; the native glue's unit tests; scenarios 24 to 32 through the bridge as native tests in the example app, against Keycloak and Hydra, run locally | No CI workflow runs any Flutter job; the authenticated-client and origin-matching assertions of scenario 32 have no bridge equivalent (Flutter exposes `accessToken()` only); any hosted provider |

The `Versola` facade has no iOS or Flutter implementation. The `Versola*` Swift targets other than
`VersolaOAuth` are placeholders.

Auth0, Microsoft Entra ID, Okta and Amazon Cognito are described in `spec/providers.md` from vendor
documentation and have not been run against. The matrix marks each cell as documented, reported,
unverified or not found.

## Quick start

All three examples configure the same client with placeholder values on `example.com`. The
redirect URI must be registered with the provider, and it should be a verified link that the app
owns (an Android App Link, an iOS Universal Link); each platform README shows the setup. The
configuration puts `offline_access` in `scopes` because the SDK never adds it; providers differ in
whether they need it for a refresh token ([`spec/providers.md`](spec/providers.md), section 3).

### Android

Install: from 0.1.0, not yet published, as `kz.versola:oauth-android`. Today, include this
repository as a composite build; [`android/README.md`](android/README.md) has the snippet.

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

`VersolaError` is the error type on Android; the rename to `OAuthError` is deferred
([ADR 0001](docs/adr/0001-generic-sdk-naming-and-layering.md)).

### iOS

Install: from 0.1.0, not yet published. Today, add the repository to Swift Package Manager by URL
or path and depend on the product `VersolaOAuth`; [`ios/README.md`](ios/README.md) has the
manifest. The module you import is `OAuthClient`.

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

### Flutter

Install: from 0.1.0, not yet published to pub.dev. Today, use a path or git dependency;
[`flutter/versola_oauth/README.md`](flutter/versola_oauth/README.md) has both, the native setup and
the caveat about the plugin's iOS package path.

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
  final token = await client.accessToken(); // call your API with dio or http; no authenticated client
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

### The four error categories

The category is the contract, on every platform ([`spec/errors.md`](spec/errors.md)); the payload
says which case within it. A session is one of seven states
([`spec/state-machine.md`](spec/state-machine.md)).

| Category | Meaning | The app |
|---|---|---|
| Recoverable | Transient or user-driven (cancelled browser, network after the retry budget, device locked) | Retry, or ask the user again; do not sign out |
| Reauthenticate | The grant is gone (denied, `invalid_grant`, no refresh token and the access token expired) | Send the user through `login()`; the SDK never opens the browser by itself |
| StepUp | The resource server asked for a stronger authentication context (RFC 9470) | Call `stepUp()`, then repeat the refused call |
| Configuration | A deployment or integration mistake (state or `iss` mismatch, a rejected ID token, a capability the provider lacks) | Fix it; catching it in production hides the problem |

## What you get without writing it

Each item is a rule of [`spec/oauth-sdk-api.md`](spec/oauth-sdk-api.md), and none has an off
switch.

- PKCE with `S256`, a fresh `state` and `nonce` per request from the platform CSPRNG, and the
  redirect checked (`state`, then `iss` per RFC 9207 when the provider advertises or sends it, then `code`)
  before any network call.
- ID-token validation before anything is stored: signature against the provider's keys, `iss`,
  `aud` and `azp`, `exp` and `iat` with a bounded clock-skew tolerance, `nonce`, and `auth_time`
  under `max_age`.
- Single-flight refresh: concurrent callers share one token request, and a rotated refresh token is
  persisted before the old one is forgotten.
- Secure storage: Keystore-wrapped files under `noBackupFilesDir` on Android, the Keychain with
  `AfterFirstUnlockThisDeviceOnly` and no iCloud sync on iOS.
- The system browser only: an Auth Tab or Custom Tab on Android, `ASWebAuthenticationSession` on
  iOS. No web view can be passed in.
- A token is attached only to the origins the app lists in `protectedOrigins`; a request to any
  other origin passes through untouched. Redirects are not followed on protected requests.
- DPoP (RFC 9449) when the app opts in and the provider advertises `ES256`, with a hardware-backed
  non-exportable key; bearer otherwise, with a logged warning, or an error if the app made DPoP
  required.
- Pushed authorization requests (RFC 9126) when the provider advertises an endpoint for them.
- No client secret can be configured: a native app cannot keep one.

## Supported providers

The contract a provider must meet, the capability matrix and the documented limits are in
[`spec/providers.md`](spec/providers.md). Setup guides per provider are in
[`docs/providers/`](docs/providers/), and coming from AppAuth is covered in
[`docs/migrating-from-appauth.md`](docs/migrating-from-appauth.md). Proven in conformance:
Keycloak 26.4 and Ory Hydra v26.2.0. Researched but not run against: Auth0, Microsoft Entra ID,
Okta, Amazon Cognito. Versola's own server is a plain OpenID provider on a `standard` tenant, but
the generic facade has not been run against it in conformance (not proven); a `fapi2` tenant
refuses public clients and needs the Versola facade.

## The Versola facade

`Versola` is for apps whose backend is a Versola server. Android is complete; iOS and Flutter are
not built. DPoP, nonce handling, refresh coordination and secure storage are the SDK's job, and so
is `offline_access`: `login()` asks for it whatever scopes it is given, because a session with no
refresh token is not one this facade can keep. It is not part of the generic API and the two are
not held to each other.

```kotlin
val versola = Versola.configure(
    context,
    issuer      = "https://id.example.com",
    clientId    = "mobile-app",
    redirectUri = "https://app.example.com/oauth",
    // Separate configuration: edge's address is not in the OAuth metadata.
    edgeBaseUrl = "https://edge.example.com",
)

versola.login(scopes = setOf("openid", "profile"))
val response = versola.call(request)
versola.logout()
```

A client on a FAPI 2.0 tenant, which is the server's default for a new tenant, cannot be a public
client of auth. Add `backChannel = BackChannel.Edge` and the SDK authorizes through edge's native
endpoints with the same API and the same key-bound tokens; this needs an https App Link as the
redirect URI, DPoP and `edgeBaseUrl`. What is proven against a staged Versola stack is in
[`conformance/README.md`](conformance/README.md); what the server does today is in
[`spec/server-dependencies.md`](spec/server-dependencies.md).

## Repository layout

```text
spec/            normative: state machine, errors, retry policy, conformance scenarios,
                 the generic API (oauth-sdk-api.md) and the provider matrix (providers.md)
android/         Gradle multi-project; see android/README.md
                 oauth-core   the protocol engine, plain JVM, package versola.oauth.core
                 core, sdk    the Versola facade and its edge back channel (versola.sdk)
                 oauth        the generic OAuthClient facade (versola.oauth)
                 dpop, storage, browser, okhttp   platform halves the facades share
                 conformance-android, conformance-oauth   test drivers, nothing published
                 samples/oauth   a minified sample app over the generic facade
ios/             Sources/ and Tests/ of the Swift targets; the manifest is Package.swift at the
                 repository root, because SPM cannot resolve a manifest from a subdirectory
flutter/         versola_oauth: the Flutter binding (Pigeon), with an example app
conformance/     the harness and the provider containers (providers/keycloak, providers/hydra)
docs/            decision records and reviews; docs/README.md is the index
tools/           validate-scenarios.py
```

## Security model

- Fail closed: a check that cannot complete refuses the operation with a typed error; no security
  check can be switched off, and none is loosened to make a provider work.
- Keys are non-exportable and stay in hardware where the device has it. Tokens and keys never go
  into logs, error messages or analytics, and the refresh token never leaves the platform store.
- Authorization runs in the system browser, redirect URIs are verified links where possible, and a
  private-use scheme is accepted with a logged warning.
- No client secret is representable, and the access token is the only credential that crosses the
  Flutter bridge.
- Report a vulnerability privately through the repository's Security tab, never in a public issue;
  [`SECURITY.md`](SECURITY.md) has the process and what is in scope.

## Documentation

- The SDK documentation will be hosted at <https://docs.versola.kz>; until it is there, the files
  below are the source.
- [`spec/`](spec/): [`oauth-sdk-api.md`](spec/oauth-sdk-api.md),
  [`providers.md`](spec/providers.md), [`state-machine.md`](spec/state-machine.md),
  [`errors.md`](spec/errors.md), [`retry-policy.md`](spec/retry-policy.md),
  [`server-dependencies.md`](spec/server-dependencies.md) and the scenarios in
  [`spec/conformance/`](spec/conformance/).
- [`docs/README.md`](docs/README.md): decision records, reviews, provider guides and the AppAuth
  migration guide.
- Per platform: [`android/README.md`](android/README.md), [`ios/README.md`](ios/README.md),
  [`flutter/versola_oauth/README.md`](flutter/versola_oauth/README.md).
- [`conformance/README.md`](conformance/README.md): what each test tier proves.
- [`develop.md`](develop.md): toolchains and the commands for every tier.
- [`AGENTS.md`](AGENTS.md): the working policy for contributors and coding agents.
- [`REVIEW.md`](REVIEW.md): what a pull request is reviewed against.
- Design discussion and the plan for the generic SDK:
  <https://github.com/versolauth/versola-sdk/issues/46>.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
