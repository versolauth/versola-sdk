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
and no token reaches your code. Add `http` (`>=1.6.0 <1.7.0`) to your own `pubspec.yaml` to import it.
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
