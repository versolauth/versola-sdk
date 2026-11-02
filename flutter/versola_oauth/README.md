# Versola OAuth SDK for Flutter

`versola_oauth` is an open-source OAuth 2.0 and OpenID Connect (OIDC) authentication SDK for Flutter
apps on Android and iOS. It handles browser-based sign-in with PKCE, ID-token validation, secure
token storage, automatic token refresh and sign-out through the native Versola OAuth SDKs.

The SDK is tested against Keycloak and Ory Hydra and works with other OpenID providers that meet
its [provider contract](https://github.com/versolauth/versola-sdk/blob/main/spec/providers.md). You do not need to run the Versola
authentication server. DPoP (RFC 9449) is optional, and pushed authorization requests (PAR, RFC 9126)
are used when the provider advertises support.

Flutter calls the Kotlin SDK on Android and the Swift SDK on iOS through a native bridge; no OAuth
protocol logic runs in Dart. Refresh tokens stay on the native side in Android Keystore-wrapped
storage or the iOS Keychain. Only the short-lived access token is available to Dart when requested.

Requires Flutter 3.47 and Dart 3.13, Android `minSdk` 26 and iOS 17.4, with Swift Package Manager
integration enabled on iOS. Licensed under Apache-2.0.

The API is pre-1.0. A change to a public symbol is stated in its pull request and raises the minor
version.

Documentation: <https://docs.versola.io/sdk/flutter/>. Overview, quick starts for all platforms and the
frequently asked questions are in the
[repository README](https://github.com/versolauth/versola-sdk#readme).

## Alternative to flutter_appauth and AppAuth

If you are evaluating AppAuth alternatives for a Flutter mobile app, `versola_oauth` provides
browser-based OAuth 2.0 and OpenID Connect sign-in through its own Kotlin and Swift SDKs.
It does not wrap AppAuth. It is an alternative for public clients using the authorization code
flow with PKCE, including apps backed by Keycloak or Ory Hydra.

The SDK handles ID-token signature validation, native secure token storage, concurrent refresh
coordination and authenticated API calls. Optional DPoP binds tokens to a device key when the
provider supports it. Flutter exposes the same session states and typed error categories as the
native SDKs.

Migration requires code and configuration changes: this is not a drop-in replacement for
`flutter_appauth`, AppAuth-Android or AppAuth-iOS. Check the platform requirements above and your
provider's capabilities first. The Flutter plugin supports Android and iOS only, requires Swift
Package Manager on iOS, and does not support client secrets, the implicit flow or the password
grant. Its API is pre-1.0.

The [AppAuth migration guide](https://docs.versola.io/sdk/migrating-from-appauth/) maps concepts,
explains behavior changes and provides before-and-after code for Flutter, Android and iOS.

## Install

Add the plugin from pub.dev to `pubspec.yaml`:

```yaml
dependencies:
  versola_oauth: ^0.3.0
```

The app needs `compileSdk` 37 and `minSdk` 26 in `android/app/build.gradle.kts` and an iOS
deployment target of 17.4; a lower value fails the build with a message that names the minimum.
The 37 is OkHttp's: its AAR declares it, and the SDK's own AARs ask for less, so the number follows
the OkHttp release the SDK depends on, not a choice of ours.

## Platform setup

Once per app, before the first `OAuthClient.create`.

**Flutter.** The plugin is a Swift package on iOS (no CocoaPods), so turn Swift Package Manager
integration on once per machine:

```bash
flutter config --enable-swift-package-manager
```

Call `WidgetsFlutterBinding.ensureInitialized()` first in `main()` when you create the client
before `runApp`: the plugin talks to the native side over platform channels.

**Android.** Merge the SDK's redirect activity into `android/app/src/main/AndroidManifest.xml`
with the HTTPS redirect URI you registered at the provider (a verified App Link; add the
`assetlinks.json` for the host). Replace the host and path with your own:

```xml
<activity
    android:name="versola.sdk.browser.VersolaRedirectActivity"
    android:exported="true"
    tools:node="merge">
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" android:host="app.example.com" android:path="/oauth" />
    </intent-filter>
</activity>
```

(`xmlns:tools="http://schemas.android.com/tools"` on the `<manifest>` element.)

**iOS.** In Xcode, Signing & Capabilities, add the Associated Domains capability with both
`applinks:app.example.com` and `webcredentials:app.example.com` for the host of your redirect
URI, and serve `apple-app-site-association` from that host. `applinks` alone is not enough for
`ASWebAuthenticationSession`.

## Usage

```dart
import 'package:versola_oauth/versola_oauth.dart';

final client = await OAuthClient.create(OAuthConfiguration(
  issuer: 'https://id.example.com',
  clientId: 'example-app',
  redirectUri: 'https://app.example.com/oauth',
  scopes: {'openid', 'profile', 'offline_access'},
));

client.sessionStates().listen((state) => print(state));

try {
  await client.login();
  final response = await client.httpClient().get(Uri.https('api.example.com', '/items'));
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

### Calling your API

`client.httpClient()` returns a `package:http` `Client` that runs each request **natively**, through
the SDK's own authenticated client: the access token, the DPoP key and its proofs, the refresh on a
401 and the origin allow-list (`protectedOrigins`) stay native, so a DPoP-bound token works from Dart
and no token reaches your code. Add `http` (`>=1.6.0 <2.0.0`) to your own `pubspec.yaml` to import it.
A request to an origin outside `protectedOrigins` goes out untouched; a 3xx is returned, not followed;
a 403, 429 or 5xx comes back as the response; a step-up challenge throws `StepUpError`, which you
answer with `client.stepUp(e)` and then repeat the request.

`httpClient(origins: {...})` **replaces** the configuration's `protectedOrigins` for that client rather
than narrowing them, as the native clients' `origins` parameter does: name only origins you mean to
send the token to.

Add your own interceptors by wrapping the client, with ours innermost: the DPoP proof depends on the
final method and URL, so authentication must run after every rewrite of yours.

```dart
import 'package:http/http.dart' as http;
import 'package:http/retry.dart';

class RequestId extends http.BaseClient {
  RequestId(this._inner);
  final http.Client _inner;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) {
    request.headers['x-request-id'] = newId(); // your header, URL or logging changes go here
    return _inner.send(request);
  }
}

// The SDK never repeats your request on a status (it cannot know the call was idempotent), so a
// retry is your decision: only methods that are safe to repeat, never a POST.
final api = RetryClient(
  RequestId(client.httpClient()),
  when: (r) => r.statusCode == 503 && const {'GET', 'HEAD'}.contains(r.request?.method),
);
```

For `dio`, a small adapter makes this client its transport; it is in the dartdoc of
`OAuthClient.httpClient`. Things to know: bodies are buffered in memory in both directions (no
streaming of large files); timeouts are the native client's own; there is no cancellation
(`Abortable` is not honoured); a call with no HTTP response is a `ClientException`; an
`Authorization` header you set for a protected origin is replaced by the SDK's, never sent beside it.
`client.accessToken()` remains as an escape hatch for code that needs the raw value (a DPoP-bound token
cannot be presented with it: use `httpClient()`).

Errors are four categories (`RecoverableError`, `ReauthenticateError`, `StepUpError`,
`ConfigurationError`). Declare the redirect URI in the app's Android manifest and iOS associated
domains, as the provider and the platform guides describe.

- **Logging and branching on an error:** every `OAuthError` has `sdkCode`, a stable string for the case
  (`recoverable.network`, `configuration.state_mismatch`, `step_up`; the list is in `spec/errors.md`).
  It never contains a payload. `ConfigurationError.code` and `ReauthenticateError.code` are different:
  they are the provider's own OAuth error code (`invalid_scope`).
- **A double-tapped sign-in button is not an error:** a second `login()` that asks for the same thing
  while one is in flight joins it, so both futures complete with the one result and one browser opens.
  One that asks for something else (other scopes, other `acr_values`) throws `ConfigurationError`.
  `currentSessionState()` gives the state now, after the restore, for choosing between a sign-in screen
  and a home screen.
- **Testing your code:** `OAuthClient` is an interface; fake it with `implements OAuthClient` (or the
  smaller `OAuthApi` for the calls your code makes). `OAuthConfiguration` and `LoginOptions` are not
  `const` (they copy the collections you pass), and a duration the bridge cannot carry exactly (a
  `clockSkewTolerance` below a second, a retry duration below a millisecond) is an `ArgumentError`.
  `OAuthClient.create` throws `UnsupportedError` off Android and iOS.

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
