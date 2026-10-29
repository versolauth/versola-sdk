# versola_oauth

The Versola generic OAuth 2.0 / OpenID Connect SDK for Flutter: a binding over the native
Android (`kz.versola:oauth-android`) and iOS (`VersolaOAuth`) SDKs of this repository. The API is
`spec/oauth-sdk-api.md` section 13 in Dart; the behaviour is the native SDKs', proven by the same
conformance scenarios. No protocol logic runs in Dart (`.claude/rules/flutter.md`).

## Usage

```dart
import 'package:versola_oauth/versola_oauth.dart';

final client = await OAuthClient.create(const OAuthConfiguration(
  issuer: 'https://id.example.com',
  clientId: 'example-app',
  redirectUri: 'https://app.example.com/oauth',
  scopes: {'openid', 'profile'},
));

// Any number of listeners; the seven states of spec/state-machine.md, and a redirect that
// finishes an authorization in a cold-started process arrives here too.
client.sessionStates().listen((state) => print(state));

try {
  await client.login();
  final token = await client.accessToken(); // the one credential that crosses the bridge
} on StepUpError catch (e) {
  await client.stepUp(e);
} on ReauthenticateError {
  // sign in again
} on RecoverableError {
  // retry, or ask the user again
} on ConfigurationError catch (e) {
  // a deployment mistake: fix it, do not catch it in production
}
```

Errors are the four categories of `spec/errors.md` as a sealed hierarchy (`RecoverableError`,
`ReauthenticateError`, `StepUpError`, `ConfigurationError`); the category is the contract, the
payload is the native case.

## Platform setup

- **Android**: declare the redirect URI on `versola.sdk.browser.VersolaRedirectActivity` in the
  app manifest (`example/android/app/src/main/AndroidManifest.xml` shows the verified App Link
  snippet). `minSdk` 26. Until `kz.versola:oauth-android` is published, the app's
  `settings.gradle.kts` includes this repository's `android/` build with a dependency
  substitution, as the example does.
- **iOS**: Swift Package Manager only (the SDK is not on CocoaPods). iOS 17.4 or newer. The
  browser sheet is presented from the key window of the foreground scene; an app with its own
  window handling sets `VersolaOAuthPlugin.presentationAnchor` before the first `create`.

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

`flutter test` proves the Dart mapping and the error categories against a mocked channel; the
Kotlin and Swift unit tests prove the wire mapping of the native half; the example builds prove the
bridge compiles against both native SDKs. The native behaviour is
proven by the SDKs' own tiers (`conformance/README.md`).
