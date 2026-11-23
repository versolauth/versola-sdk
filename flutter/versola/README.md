# Versola SDK for Flutter

`versola` is the Flutter binding of the native `Versola` facade (`spec/versola-sdk-api.md` in
[versolauth/versola-sdk](https://github.com/versolauth/versola-sdk)): it signs a native app in to a
Versola deployment through its edge, and calls the deployment's APIs through that edge, on Android
and iOS. It is a binding over the Kotlin and Swift SDKs; no OAuth protocol logic runs in Dart.

The device holds a DPoP key (RFC 9449) in the Android Keystore or the Secure Enclave, every token is
bound to it, and **nothing credential-shaped crosses to Dart, the access token included**: there is
no `accessToken()`. Apps call their API through `Versola.httpClient()`, a `package:http` client that
executes the request natively with the token and a proof for that exact request. Its scope is the
edge's origin and cannot be widened. An app that talks to a provider directly uses `versola_oauth`
instead; the two plugins can live in one app.

Requires Flutter 3.47 and Dart 3.13, Android `minSdk` 26 and iOS 17.4, with Swift Package Manager
integration enabled on iOS. Licensed under Apache-2.0. The API is pre-1.0.

The Android artefact `io.versola:versola-android` and this package are not published yet; the
example app builds against this repository.

## Use

```dart
final versola = await Versola.create(const VersolaConfiguration(
  edgeUrl: 'https://id.example.com',
  clientId: 'example-app',
  redirectUri: 'https://app.example.com/oauth',
));

versola.sessionStates().listen((state) { /* unauthenticated, authenticated, ... */ });

try {
  await versola.login();
} on ReauthenticateError catch (e) {
  // sign in again
} on ConfigurationError catch (e) {
  // e.sdkCode, e.g. 'configuration.edge_client_unknown' when the edge does not know the client id
}

final response = await versola.httpClient().get(Uri.https('id.example.com', '/resources/items'));
```

The shared types (`SessionState`, the `OAuthError` hierarchy, `IdTokenClaims`, `LogoutOptions`,
`LogoutOutcome`, `RetryPolicy`, `UnlockPolicy`, `Prompt`) come from `package:versola_oauth` and are
re-exported by `package:versola/versola.dart`. `VersolaConfiguration` and `LoginOptions` are this
package's own; an app that imports both packages hides one `LoginOptions`.

A step-up (`StepUpError` from the client, or a challenge on `httpClient()`) is answered with
`stepUp(challenge)`, which re-authorizes with the scopes the session was granted. A step-up that
comes back as another user is `RecoverableError(accountMismatch)`.

## Platform setup

Android: declare `versola.sdk.browser.VersolaRedirectActivity` in the app manifest with an `https`
App Link intent filter for the redirect URI (see `example/android/app/src/main/AndroidManifest.xml`).
iOS: add the redirect URI's host as an Associated Domain and enable
`flutter config --enable-swift-package-manager`. A private-use scheme or a loopback redirect is
refused: an edge-fronted client registers an `https` link only.
