# versola_oauth

OAuth 2.0 and OpenID Connect (OIDC) sign-in for Flutter apps on Android and iOS: authorization code
flow with PKCE in the system browser, ID-token validation, secure token storage and refresh,
through the native Versola OAuth SDKs. The Dart API holds no protocol logic: it forwards to the
Android (Kotlin) and iOS (Swift) SDKs, and only the short-lived access token ever reaches Dart.

Works with any OpenID provider that supports the authorization code flow with PKCE for public
clients, such as Keycloak and Ory Hydra. Requires Flutter 3.47 and Dart 3.13, Android `minSdk` 26
and iOS 17.4, with Swift Package Manager integration enabled on iOS.

The API is production ready. The major version is still 0, and interfaces change only when a
change is required; a change to a public symbol is stated in its pull request and raises the minor
version.

Documentation: <https://docs.versola.io>. Overview, quick starts for all platforms and the
frequently asked questions are in the
[repository README](https://github.com/versolauth/versola-sdk#readme).

## Install

Add the plugin to `pubspec.yaml` as a git dependency on the repository, with the current version from the
[Releases](https://github.com/versolauth/versola-sdk/releases) page as `ref`:

```yaml
dependencies:
  versola_oauth:
    git:
      url: https://github.com/versolauth/versola-sdk.git
      path: flutter/versola_oauth
      ref: <version>
```

The app needs `compileSdk` 37 and `minSdk` 26 in `android/app/build.gradle.kts` and an iOS
deployment target of 17.4; a lower value fails the build with a message that names the minimum.
The 37 is OkHttp's: its AAR declares it, and the SDK's own AARs ask for less, so the number follows
the OkHttp release the SDK depends on, not a choice of ours.

## Usage

```dart
import 'package:versola_oauth/versola_oauth.dart';

final client = await OAuthClient.create(const OAuthConfiguration(
  issuer: 'https://id.example.com',
  clientId: 'example-app',
  redirectUri: 'https://app.example.com/oauth',
  scopes: {'openid', 'profile', 'offline_access'},
));

client.sessionStates().listen((state) => print(state));

try {
  await client.login();
  final token = await client.accessToken(); // call your API with dio or http
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

Errors are four categories (`RecoverableError`, `ReauthenticateError`, `StepUpError`,
`ConfigurationError`). Declare the redirect URI in the app's Android manifest and iOS associated
domains, as the provider and the platform guides describe.

## Developing

Run from this directory with the toolchain pinned in `flutter/.fvmrc`:

```bash
fvm dart run pigeon --input pigeons/messages.dart   # after a change to pigeons/messages.dart
fvm dart format --set-exit-if-changed .
fvm flutter analyze
fvm flutter test
```

## Licence

Apache-2.0.
