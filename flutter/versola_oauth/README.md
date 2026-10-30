# versola_oauth

The Versola OAuth 2.0 / OpenID Connect SDK for Flutter: a binding over the native
Android (`kz.versola:oauth-android`) and iOS (`VersolaOAuth`) SDKs of this repository. The API is
`spec/oauth-sdk-api.md` section 13 in Dart; the behaviour is the native SDKs', covered by the same
conformance scenarios. No protocol logic runs in Dart (`.claude/rules/flutter.md`).

Documentation: the SDK documentation will be hosted at <https://docs.versola.kz>; until then this
README, [`spec/oauth-sdk-api.md`](../../spec/oauth-sdk-api.md) and the dartdoc are the source.

## Status and installation

Not published: there is no pub.dev package and no release tag; the first version will be 0.1.0.
The repository is private. Requirements today: Flutter 3.47 and Dart 3.13 (the
ranges in `pubspec.yaml`, toolchain pinned in `flutter/.fvmrc`), Android `minSdk` 26, iOS 17.4,
and on iOS Swift Package Manager integration enabled (the plugin has no podspec and the SDK is not
on CocoaPods).

Until it is published, depend on it by path or by git:

```yaml
# pubspec.yaml of the app
dependencies:
  versola_oauth:
    path: ../versola-sdk/flutter/versola_oauth
  # or, from git:
  # versola_oauth:
  #   git:
  #     url: https://github.com/versolauth/versola-sdk.git
  #     path: flutter/versola_oauth
```

The plugin's native halves are consumed as this repository's own builds, which constrains both
ways of depending on it:

- **Android:** the plugin depends on `kz.versola:oauth-android:0.1.0`, which is not on Maven
  Central. The app's `android/settings.gradle.kts` must include this repository's `android/` build
  and substitute the artefact with the `:oauth` project, as the example does
  (`example/android/settings.gradle.kts`); see [`android/README.md`](../../android/README.md) for the
  block. The AGP and Kotlin plugin versions of the app must match `android/build.gradle.kts`, since
  an included build cannot load a second version of either.
- **iOS:** the plugin's Swift package (`ios/versola_oauth/Package.swift`) depends on this
  repository's root `Package.swift` by a relative path (`../../../..`). That works when the plugin
  sits at `flutter/versola_oauth` inside a full checkout, which is what a path dependency on a
  checkout gives. A git dependency fetches the whole repository into the pub cache, which keeps
  the path valid; copying only the plugin directory, or a future pub.dev package, would break it,
  and changing it is a change to the plugin's package manifest.

For the git dependency the Android composite build still needs a checkout of `android/` to point
at, so a path dependency on a checkout is the route that needs no extra setup.

## Usage

```dart
import 'package:versola_oauth/versola_oauth.dart';

final client = await OAuthClient.create(const OAuthConfiguration(
  issuer: 'https://id.example.com',
  clientId: 'example-app',
  redirectUri: 'https://app.example.com/oauth',
  scopes: {'openid', 'profile', 'offline_access'},
  protectedOrigins: {'https://api.example.com'},
));

// Any number of listeners over one native subscription; the seven states of
// spec/state-machine.md. A late listener first gets the latest state.
client.sessionStates().listen((state) => print(state));

try {
  await client.login();
  final token = await client.accessToken(); // the one credential that crosses the bridge
  // Call your API with dio or http: Authorization: ${token.tokenType} ${token.value}
} on StepUpError catch (e) {
  await client.stepUp(e);
} on ReauthenticateError {
  // sign in again
} on RecoverableError {
  // retry, or ask the user again
} on ConfigurationError {
  // a deployment mistake: fix it, do not catch it in production
}
```

`create` validates the configuration natively and throws a `ConfigurationError` for a bad value; it
does no network I/O. The SDK never adds `offline_access`: put it in `scopes` when the provider needs
it for a refresh token ([`spec/providers.md`](../../spec/providers.md), section 3).

### The API

| Call | Result |
|---|---|
| `OAuthClient.create(configuration)` | The client for that issuer and client id; a second call for the same pair reaches the same native client |
| `sessionStates()` | `Stream<SessionState>` shared by every listener: one native subscription, ended when the last listener cancels |
| `currentSessionState()` | `Future<SessionState>`, asked of native every time |
| `claims()` | `Future<IdTokenClaims?>` of the validated ID token, null with no session. A method, not a getter, because the claims stay native and the answer is asynchronous |
| `login([options])` | `Future<void>`; the session is observable through `sessionStates()` |
| `stepUp(error, [options])` | `Future<void>`; re-authorizes at the `StepUpError`'s `acrValues` and `maxAge`, then the app repeats the refused call |
| `logout([options])` | `Future<LogoutOutcome>` with `sessionEnded` and `tokenRevoked`; the local wipe is unconditional |
| `accessToken()` | `Future<AccessToken>` (`value`, `tokenType`), refreshed natively first if needed |
| `refresh()` | `Future<void>` |
| `userInfo()` | `Future<UserInfo>` |
| `keyAttestation()` | `Future<String?>`: the DPoP key tier (`secureEnclave`, `strongBox`, `trustedEnvironment`, `software`), null under bearer |

`login` while an authorization is in progress is refused; observe `sessionStates()` first. A
redirect that reaches the app is handed to the native client; on iOS see Platform setup for the
cold-start path.

### Errors

Every call throws an `OAuthError` and nothing else. It is a sealed class with the four categories of
[`spec/errors.md`](../../spec/errors.md); the category is the contract and the payload is the native
case. Switch on the category first:

```dart
try {
  final token = await client.accessToken();
  // use token.value
} on OAuthError catch (error) {
  switch (error) {
    case RecoverableError(:final cause):
      // userCancelled, systemCancelled, pendingRequestExpired, network, unlockRequired, nonceLoop.
      // Retry or ask again; do not sign out. `unknown` is a native cause this version does not
      // know: do not loop on it.
      if (cause == RecoverableCause.network) scheduleRetry();
    case ReauthenticateError(:final reason):
      // authorizationDenied, interactionRequired, credentialsInvalidated, grantRejected,
      // sessionRejected, sessionExpired: the session is over, so show the sign-in screen.
      showSignIn(reason);
    case final StepUpError challenge:
      await client.stepUp(challenge);
      // then repeat the call that was refused
    case ConfigurationError(:final detail):
      // stateMismatch, issuerMismatch, idTokenRejected, providerUnsupported, invalidConfiguration...
      // A deployment or integration mistake; no retry fixes it.
      reportMisconfiguration(detail);
  }
}
```

A native case this version of the binding does not know arrives as `unknown` with its name in
`detail` or `text`, never as a different real case. Errors carry nothing credential-shaped, and
`AccessToken`, `IdTokenClaims` and `UserInfo` redact themselves in `toString`.

## What crosses the bridge, and what is not available

The access token is the only credential that crosses the bridge, and only as the reply of
`accessToken()`. The refresh token, the ID token's raw form, key material, the pending request, the
PKCE verifier and `state` stay native, and the Dart side keeps no copy of the access token: it asks
native every time, so single-flight refresh stays in one place.

There is no authenticated HTTP client in Flutter, and no `protectedOrigins` enforcement on your
requests: `protectedOrigins` is accepted in the configuration (the native client validates it) but
nothing in Dart sends a request for you. Use the token with `dio` or `http`, and send it only to the
origins you intend. Passing the token to an HTTP stack is the app's decision, and a token the app
holds is one it can log. A `dio` interceptor helper in a separate package is a later possibility
([`spec/oauth-sdk-api.md`](../../spec/oauth-sdk-api.md), section 10), not part of this package.

DPoP can be selected (`TokenBinding.dpop`, `TokenBinding.dpopRequireHardware`) and the native client
signs proofs, but the proofs are made only for requests the native SDK sends itself; a DPoP-bound
token used from Dart needs a proof the app cannot obtain here. Use bearer (the default) unless the
native side is what calls your API.

## Platform setup

- **Android:** declare the redirect URI on `versola.sdk.browser.VersolaRedirectActivity` in the app
  manifest (`example/android/app/src/main/AndroidManifest.xml` shows the verified App Link snippet;
  [`android/README.md`](../../android/README.md) explains it, including `assetlinks.json`).
  `minSdk` must be 26, above Flutter's default.
- **iOS:** Swift Package Manager only. iOS 17.4 or newer. The browser sheet is presented from a
  window the plugin supplies: by default the key window of the foreground scene. An app with its
  own window handling sets the hook once, in `AppDelegate`, before the first `create`:

  ```swift
  VersolaOAuthPlugin.presentationAnchor = { myWindow }   // () -> ASPresentationAnchor, main actor
  ```

  The plugin forwards Universal Links (application and scene lifecycles, including the link that
  launched the app) to the native client's `handleRedirect`. An `https` redirect URI needs the
  app's `webcredentials` associated domain for its host; see [`ios/README.md`](../../ios/README.md).
  The plugin does not call the native `resumePendingAuthorization()`; a Universal Link that
  launches the app reaches the native client through `handleRedirect`.

## Developing

Run from this directory with the pinned toolchain (`flutter/.fvmrc`):

```bash
fvm dart run pigeon --input pigeons/messages.dart   # after a change to the bridge contract
fvm dart format --set-exit-if-changed .
fvm flutter analyze
fvm flutter test
cd example && fvm flutter build apk --debug
cd example && fvm flutter build ios --no-codesign
cd example/ios && xcodebuild test -workspace Runner.xcworkspace -scheme Runner \
  -destination "platform=iOS Simulator,name=iPhone 17" -only-testing:RunnerTests   # Swift glue
cd example/android && ./gradlew :versola_oauth:testDebugUnitTest                  # Kotlin glue
```

Never hand-edit the generated bridge files (`lib/src/messages.g.dart` and the generated Kotlin and
Swift); change `pigeons/messages.dart` and regenerate.

### Testing tiers

- `flutter test` covers the Dart mapping and the error categories against a mocked channel.
- The Kotlin and Swift unit tests cover the wire mapping of the native half.
- The example builds compile the bridge against both native SDKs.
- The bridge conformance tests run scenarios 24 to 32 through the plugin's host API as native tests
  in the example app (`example/android/app/src/test`, `example/ios/RunnerTests`), against Keycloak
  and Ory Hydra in Docker; they run when `OAUTH_CONFORMANCE_ISSUER` is set. The commands are in
  [`develop.md`](../../develop.md), and [`conformance/README.md`](../../conformance/README.md)
  ("Through the Flutter bridge") describes them.
- The native behaviour itself is covered by the SDKs' own tiers (`conformance/README.md`).
