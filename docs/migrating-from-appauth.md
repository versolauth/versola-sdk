# Migrating from AppAuth

For integrators moving an app from [AppAuth-Android](https://github.com/openid/AppAuth-Android),
[AppAuth-iOS](https://github.com/openid/AppAuth-iOS) or `flutter_appauth` (which wraps them) to the
generic `OAuthClient` of this SDK. It maps the concepts, lists what you stop doing, what changes in
behaviour, and, honestly, what AppAuth does that this SDK does not. The target API is
[`spec/oauth-sdk-api.md`](../spec/oauth-sdk-api.md); provider setup is in [providers/](providers/README.md).

AppAuth facts come from the AppAuth READMEs and API documentation and from `pub.dev`, fetched and
read on 2026-10-30 (see Sources). Where a page could not be read, the AppAuth side of that row says
**unverified** instead of guessing. This SDK is not published yet, so the build setup is in
`develop.md`; nothing here pins a version.

## 1. The short version

- Your app stops holding authentication state. There is no `AuthState` to serialize and no refresh
  token in your hands. `OAuthClient` owns storage, refresh and sign-out; you observe a session.
- Sign-in is one call, `login()`. PKCE, `state`, `nonce`, redirect validation, the code exchange and
  ID-token validation happen inside it and cannot be switched off.
- Each stored token is protected by the Android Keystore or the iOS Keychain, by the SDK.
- Users sign in once after the update: **existing refresh tokens cannot be imported** (section 6).
- It is for public clients with the system browser only. If your AppAuth setup uses a client secret,
  a custom client authentication method, dynamic registration or an embedded browser, read section 5
  before you start.

## 2. Concept mapping

Kotlin names are from `versola.oauth` (and `versola.oauth.core` for the error and state types), Swift
names from the module `OAuthClient` (package product `VersolaOAuth`), Dart names from
`package:versola_oauth/versola_oauth.dart`.

| AppAuth concept | AppAuth names | This SDK |
|---|---|---|
| Provider configuration by discovery | Android `AuthorizationServiceConfiguration.fetchFromIssuer`; iOS `OIDAuthorizationService.discoverConfiguration(forIssuer:)`; Flutter `issuer` or `discoveryUrl` | `OAuthConfiguration(issuer = ...)`. Discovery runs lazily on the first operation, is cached on disk and refetched after 24 hours or on a failure a changed endpoint could explain. |
| Provider configuration by endpoints | Android `new AuthorizationServiceConfiguration(authorizationEndpoint, tokenEndpoint)`; iOS `OIDServiceConfiguration(authorizationEndpoint:tokenEndpoint:)`; Flutter `serviceConfiguration` | `OAuthConfiguration(endpoints = ProviderEndpoints(...))`: `issuer`, `authorizationEndpoint`, `tokenEndpoint` and `jwksUri` are required, because an ID token that cannot be verified is refused. Exclusive with `issuer`. |
| Discovery at a non-standard URL | Android `fetchFromUrl` | No equivalent. Give explicit endpoints. |
| The request | Android `AuthorizationRequest.Builder`; iOS `OIDAuthorizationRequest`; Flutter `AuthorizationTokenRequest` | Not an object you build. `clientId`, `redirectUri` and `scopes` live in `OAuthConfiguration`; per-login choices are `LoginOptions` (`scopes`, `prompt`, `loginHint`, `uiLocales`, `acrValues`, `maxAge`, `resources`, `extraParameters`, `ephemeralBrowser`). |
| Running the flow | Android `AuthorizationService.performAuthorizationRequest` or `getAuthorizationRequestIntent`, then `performTokenRequest`; iOS `OIDAuthState.authState(byPresenting:presenting:)`; Flutter `authorizeAndExchangeCode` | `client.login(options)`: one suspending call that runs the browser, validates the redirect, exchanges the code and validates the ID token. |
| The service object | Android `AuthorizationService`; iOS `OIDAuthorizationService` | `OAuthClient`, from `OAuthClient.create(...)`. One instance per configuration per process. |
| Session state | `AuthState` (Android), `OIDAuthState` (iOS), the response objects (Flutter) | Not exposed. Observe `client.sessionState` (Kotlin, a `Flow`), `client.sessionStates()` (Swift `AsyncStream`, Dart `Stream`), or ask for the current value. Seven states, `spec/state-machine.md`. |
| Persisting the state | You: `AuthState.jsonSerializeString()` to `SharedPreferences` (Android README); archive `OIDAuthState` (iOS README says it is the only object to serialize); store the response (Flutter) | The SDK: refresh token and ID token in a Keystore- or Keychain-wrapped store, never in a place you can read. No API to export or import it. |
| Fresh tokens | Android `authState.performActionWithFreshTokens(service, action)` with `execute(accessToken, idToken, ex)`; iOS `authState.performAction { accessToken, idToken, error in }`; Flutter `token(TokenRequest(... refreshToken ...))` | `client.accessToken()` (refreshes first if needed, one refresh in flight however many callers); or `client.interceptor(origins)` / `client.authenticatedClient(origins)` / `client.call(request)` (Kotlin), `client.authenticatedSession(origins:)` (Swift) which attach the token themselves. Flutter: `accessToken()` only. |
| Forcing a refresh | AppAuth refreshes when the token is expiring; the README does not describe a forced-refresh call (unverified) | `client.refresh()` spends the stored refresh token once now. |
| ID token | `AuthState` carries it; Android validates a few claims, iOS exposes `OIDIDToken` | `client.claims` (typed `IdTokenClaims`), never the raw token. `userInfo()` is separate. |
| End session | Android `EndSessionRequest.Builder(...).setIdTokenHint(...).setPostLogoutRedirectUri(...)`, `performEndSessionRequest`; iOS `OIDEndSessionRequest` (class exists in the API index; the README shows no usage: unverified); Flutter `endSession(EndSessionRequest(idTokenHint, postLogoutRedirectUrl))` | `client.logout(LogoutOptions)`: revokes the refresh token when the provider advertises revocation, ends the provider session in the system browser when it advertises an end-session endpoint, and wipes local state. `postLogoutRedirectUri` is configuration. Returns `LogoutOutcome(sessionEnded, tokenRevoked)`. |
| Redirect, Android | Manifest placeholder `appAuthRedirectScheme`, or an intent filter on `net.openid.appauth.RedirectUriReceiverActivity` | An intent filter on `versola.sdk.browser.VersolaRedirectActivity`, preferably a verified App Link. Under an Auth Tab the browser returns the redirect to the SDK directly. |
| Redirect, iOS | App delegate `application(_:open:options:)` calls `resumeExternalUserAgentFlow(...)` on a stored `currentAuthorizationFlow` | Nothing for the normal case: `ASWebAuthenticationSession` returns the redirect to the SDK. For a Universal Link received while the app was cold, call `await client.handleRedirect(url)`. |
| Redirect, Flutter | Android placeholder or filter; iOS `CFBundleURLSchemes` in `Info.plist` | The same native setup as the Android and iOS rows, in the host app. |
| Browser choice | Android `BrowserAllowList`, `BrowserDenyList`, `VersionedBrowserMatcher`; iOS `OIDExternalUserAgentIOSCustomBrowser` | None. The SDK picks an Auth Tab where the device's Custom Tabs provider supports it, a Custom Tab otherwise, any browser last; iOS uses `ASWebAuthenticationSession`. |
| Ephemeral session | Flutter `preferEphemeralSession` | `LoginOptions.ephemeralBrowser` (best effort; off by default because it breaks passkeys and single sign-on). |
| Custom HTTP | Android `AppAuthConfiguration` with `setConnectionBuilder`; iOS `OIDURLSessionProvider` | `OAuthConfiguration.httpClient` (OkHttp) or `urlSession` (Swift). Redirects are switched off on the SDK's own requests whatever your client does. |
| Cancellation and errors | Android `AuthorizationException`; iOS `NSError` codes; Flutter `FlutterAppAuthUserCancelledException` and `FlutterAppAuthPlatformException` | Four categories (`spec/errors.md`): `Recoverable`, `Reauthenticate`, `StepUp`, `Configuration`. A user cancel is `Recoverable(UserCancelled)`. |

## 3. What you stop doing

- **Persisting `AuthState`.** No serialization, no `SharedPreferences` or Keychain code for tokens, no
  `AuthStateManager` of your own. After a restart `create()` restores `Authenticated` (or
  `Authorizing`, if the app was killed mid-browser) without network I/O.
- **Coordinating refresh.** Concurrent callers coalesce onto one refresh; a rotated refresh token is
  stored before the old one is forgotten and is never spent twice; `invalid_grant` is
  `Reauthenticate(GrantRejected)`, not a retry.
- **PKCE, `state`, `nonce`.** Generated from the platform's secure random source, persisted before the
  browser opens, validated on return. You do not pass them, store them or compare them.
- **ID-token validation.** Done before the grant is persisted (section 4). You do not need an
  additional JWT library for it.
- **Handing a redirect to the library.** On Android the SDK's activity receives it (or the Auth Tab
  returns it); on iOS the system session returns it. Only a cold-start Universal Link needs
  `handleRedirect`.
- **Attaching tokens.** The interceptor or authenticated session adds `Authorization` to requests for
  the origins you named, refreshes once on a 401 and replays once.

## 4. What changes in behaviour

The SDK is stricter than AppAuth in the places below. Several of them make a provider that worked
with AppAuth fail loudly with a `Configuration` error; that is the intended trade.

| Area | AppAuth | This SDK |
|---|---|---|
| ID token | Android `IdToken.validate` checks `iss`, `aud`/`azp`, `exp`, `iat` and the `nonce` for the code grant, and its source says it relies on TLS instead of verifying the signature. iOS `OIDIDToken` parses the token and, per its documentation, does not verify the signature. | The signature is verified against `jwks_uri` with a closed set of asymmetric algorithms (`none` and HMAC refused), then `iss`, `aud`/`azp`, `exp`, `iat`, `nonce`, `auth_time` under `maxAge` and `at_hash` are checked, before anything is persisted. A refusal is `Configuration(IdTokenRejected(reason))`. The same rules apply to an ID token on a refresh response. |
| `iss` | Android checks the ID token's issuer against discovery when a discovery document is present. | The discovery document's `issuer` must equal the configured one (one trailing slash ignored), the ID token's `iss` must equal the discovered value byte for byte, and the redirect's `iss` is checked (RFC 9207) when present, and required when discovery advertises it. A templated issuer is unsupported. |
| PKCE | The iOS README says PKCE is used if the server supports it. | Always `S256`, never `plain`, never off. A provider that lists `code_challenge_methods_supported` without `S256` is `ProviderUnsupported("S256")`. |
| Client type | A client secret can be supplied (Android `ClientSecretBasic`, `ClientSecretPost`; the iOS README's sample passes a `clientSecret`). | Public clients only. No `clientSecret` exists in any configuration type. |
| Browser | System browser; WebView not supported. | System browser only, and a web view is unrepresentable in the public API. |
| Token storage | Your code. | The Keystore (Android) or Keychain (iOS, `AfterFirstUnlockThisDeviceOnly`, not synchronized) by the SDK; files under `noBackupFilesDir`, so a backup cannot replay them on another device. |
| Errors | Platform exception types and codes. | Four categories; `error_description` is attached for logging and never matched on. |
| Opening the browser | The app calls it. | Same, and the SDK never opens it on its own: `Reauthenticate` is a diagnosis, you decide when `login()` runs. `login()` while `Authorizing` is refused with `InvalidConfiguration`. |
| Cold-start redirect | Not described on the pages read (unverified). `spec/state-machine.md` records a process-death failure of `flutter_appauth` in an earlier demo of this project. | A redirect that reaches a cold-started process completes the pending request (kept for up to 10 minutes) and publishes `Authenticated` on `sessionState`. |
| Tokens and origins | Whatever your code does with the token. | The authenticated client attaches a token only to the `protectedOrigins` you configured; any other request passes untouched. |
| Issuer scheme | Android allows `setSkipIssuerHttpsCheck(true)` for testing. | `https` only, with `http` accepted on a loopback host only. No flag. |
| Platform floor | AppAuth-Android README: API 16+, App Links API 23+. AppAuth-iOS README: iOS 15+, HTTPS redirects iOS 17.4+. | `minSdk` 26 on Android; iOS 17.4 for the package. |
| Redirect URI | A custom scheme is the README's recommendation on Android; HTTPS is supported. | An `https` verified link is preferred; a private-use scheme works and logs a warning on every `create()`; cleartext non-loopback `http` is refused. |
| Flutter data | `flutter_appauth` returns access, refresh and ID tokens to Dart. | Dart gets the short-lived access token from `accessToken()` and nothing else credential-shaped. |

## 5. Things AppAuth does that this SDK does not

Checked against [`spec/oauth-sdk-api.md`](../spec/oauth-sdk-api.md) and the public declarations of all
three platforms. "Absent" means no public symbol exists; it does not mean it is planned.

- **Client secrets and confidential clients.** Absent by design (RFC 8252 section 8.5, `security.md`).
  If your provider client uses a secret, register a secret-less public client for the app. A provider
  that insists on a secret from a native app is unsupported.
- **Other client authentication at the token endpoint** (AppAuth-Android has a `ClientAuthentication`
  type). Absent: the token request carries `client_id` only.
- **Dynamic client registration** (AppAuth `RegistrationRequest` / `OIDRegistrationRequest`). Absent.
- **Embedded user agents.** Absent, and AppAuth does not support them either.
- **Choosing the browser.** Absent: no allow list, deny list, custom browser or custom Custom Tabs
  intent.
- **Discovery at a custom URL** (`fetchFromUrl`). Absent; use explicit endpoints.
- **Splitting the flow.** Flutter's `authorize` followed by `token(code)`, or a manual
  `performTokenRequest`, is absent. `login()` is atomic, and no authorization code, verifier or
  nonce is ever handed to the app.
- **Reading or injecting the refresh token.** Absent. Your backend cannot receive the app's refresh
  token, and `token(TokenRequest(... refreshToken: ...))` has no counterpart. `refresh()` spends the
  stored token.
- **The raw ID token.** Absent. `claims` exposes the typed claims of the validated token; the raw
  token is kept encrypted for `id_token_hint` only. If a backend needs the ID token itself, this SDK
  cannot supply it.
- **Turning off checks.** `setNonce(null)` and `setSkipIssuerHttpsCheck(true)` (AppAuth-Android),
  Flutter's `allowInsecureConnections` (not described on the page read: unverified), a non-`https`
  issuer, a missing `iss`, an unverified ID token: absent. A provider that needs one of them is
  listed as a documented limit, not given a flag.
- **Several accounts at once.** Not in the first release: one session per configuration.
- **Device authorization, CIBA and token exchange.** Not in the first release.
- **macOS, tvOS and desktop.** AppAuth-iOS documents macOS and tvOS support; desktop and web are out of
  scope for this SDK's first release.
- **A parameter on the token request.** `extraParameters` goes on the authorization request. The
  token request carries what the SDK builds, plus `resource` when you gave `resources`. No hook adds
  anything else.
- **Custom user-agent or request interception beyond the HTTP client.** `httpClient` / `urlSession`
  is the only seam.

## 6. Data migration

**Existing refresh tokens cannot be imported, so every user signs in once after the update.** This is
checked in the code, not assumed. The public declarations of the three platforms
(`android/oauth/api/oauth.api`, the Swift `public` surface of `ios/Sources/OAuthClient`, the Dart
exports of `lib/versola_oauth.dart`) contain no call that accepts a refresh token, an ID token or a
serialized state, and the configuration types have no field for one. The credential stores that hold
them are internal wiring behind `@VersolaInternalApi` on Android and `package` access on iOS, and are
not an integration point. The first `create()` finds nothing and reports `Unauthenticated`.

Plan the rollout around that:

1. **Ship the SDK in the app update, and treat the first launch as signed out.** Show your sign-in
   screen; `login()` completes with the user's existing provider session in most cases (no password
   entry if the browser is still signed in).
2. **Delete the old state.** After the first successful `login()`, remove the persisted AppAuth state:
   the `AuthState` JSON in `SharedPreferences` or wherever your own manager put it, the archived
   `OIDAuthState` in the Keychain or defaults, and the tokens `flutter_appauth` returned if you kept
   them (for example in a secure-storage plugin). A leftover refresh token is a credential nobody
   uses and nobody guards.
3. **Optionally revoke the old refresh token** at the provider before deleting it, if the provider has
   a revocation endpoint (RFC 7009: `client_id` and `token`, no secret for a public client). The SDK
   cannot do it for you, because it never sees that token.
4. **Keep the old redirect URI registered while old app versions are in use.** If you move from a
   custom scheme to an `https` App Link or Universal Link, add the new URI; do not replace the old one
   until the old versions are gone.
5. **If the old client used a secret,** the SDK needs a different provider client, registered as public.
   Register it alongside the old one and move the app over.
6. **The same `clientId` and redirect URI can stay.** The SDK keys its storage by issuer and
   `clientId`; it does not read AppAuth's.

## 7. Android, step by step

The AppAuth side below is abridged from the README's examples; the SDK side is the target API.

### Before (AppAuth-Android)

```kotlin
// build.gradle: manifestPlaceholders = ['appAuthRedirectScheme': 'com.example.app']
AuthorizationServiceConfiguration.fetchFromIssuer(Uri.parse("https://id.example.com")) { config, ex ->
    val request = AuthorizationRequest.Builder(
        config!!, "example-app", ResponseTypeValues.CODE, Uri.parse("com.example.app:/oauth"),
    ).setScope("openid profile").build()
    // performAuthorizationRequest(request, completionIntent, cancelIntent), then in the
    // completion activity: AuthorizationResponse.fromIntent(intent), AuthState.update(...),
    // authService.performTokenRequest(resp.createTokenExchangeRequest(), callback)
}

// Later, with state restored from AuthState.jsonDeserialize(json):
authState.performActionWithFreshTokens(authService) { accessToken, idToken, ex ->
    // write the updated AuthState back, then call the API with accessToken
}
```

### After (this SDK)

1. **Dependency.** Remove `net.openid:appauth`. Add the generic SDK module `kz.versola:oauth-android`
   (build setup in `develop.md`). `minSdk` becomes 26.
2. **Manifest.** Remove the `appAuthRedirectScheme` placeholder and any
   `net.openid.appauth.RedirectUriReceiverActivity` filter. Add the filter on the SDK's activity for
   your redirect URI, the snippet in [the provider index](providers/README.md#android-app-links).
   For a verified App Link, also serve `assetlinks.json` on the host.
3. **Create the client once**, with the same issuer, client id and scopes. Use an `https` redirect URI
   if you can register one with the provider.

   ```kotlin
   val client = OAuthClient.create(
       context,
       OAuthConfiguration(
           issuer = "https://id.example.com",
           clientId = "example-app",
           redirectUri = "https://app.example.com/oauth",
           postLogoutRedirectUri = "https://app.example.com/signed-out",
           scopes = setOf("openid", "profile"),
           protectedOrigins = setOf("https://api.example.com"),
       ),
   )
   ```

4. **Sign in.** Replace the request, the redirect activity and the token exchange with one call:

   ```kotlin
   scope.launch {
       try {
           client.login()
       } catch (e: VersolaError) {
           // Recoverable, Reauthenticate, StepUp or Configuration
       }
   }
   ```

5. **Call your API.** Replace `performActionWithFreshTokens` and the `AuthState` write-back with the
   interceptor on your own `OkHttpClient`, or with `client.call(request)`:

   ```kotlin
   val http = OkHttpClient.Builder()
       .addInterceptor(client.interceptor())
       .build()
   ```

   If you need the value, `client.accessToken()` returns an `AccessToken`; it is the escape hatch, and
   a token handed to your code is one you can log.
6. **Observe the session** instead of reading your stored state: collect `client.sessionState`.
7. **Sign out** with `client.logout()`; it returns `LogoutOutcome(sessionEnded, tokenRevoked)`.
8. **Delete** the old `AuthState` storage (section 6).

## 8. iOS, step by step

### Before (AppAuth-iOS)

```swift
OIDAuthorizationService.discoverConfiguration(forIssuer: issuer) { configuration, error in
    guard let configuration else { return }
    let request = OIDAuthorizationRequest(
        configuration: configuration, clientId: clientID,
        clientSecret: clientSecret,  // the README's sample passes a secret; a public client has none
        scopes: [OIDScopeOpenID, OIDScopeProfile], redirectURL: redirectURI,
        responseType: OIDResponseTypeCode, additionalParameters: nil)
    appDelegate.currentAuthorizationFlow =
        OIDAuthState.authState(byPresenting: request, presenting: self) { authState, error in
            // keep authState
        }
}

func application(_ app: UIApplication, open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    if let flow = self.currentAuthorizationFlow {
        try? flow.resumeExternalUserAgentFlow(url)  // abridged: the README also handles the error
        self.currentAuthorizationFlow = nil
        return true
    }
    return false
}

authState?.performAction { accessToken, idToken, error in
    // call the API with accessToken
}
```

### After (this SDK)

1. **Dependency.** Remove AppAuth from Swift Package Manager (or CocoaPods, which AppAuth-iOS is
   deprecating). Add the `VersolaOAuth` package product and `import OAuthClient`. iOS 17.4.
2. **Entitlements** for an `https` redirect: Associated Domains for the host, and the
   `apple-app-site-association` file, per [the provider index](providers/README.md#ios-universal-links).
   A private-use scheme needs none of that, and logs a warning.
3. **Create the client** (async, once):

   ```swift
   let configuration = try OAuthConfiguration(
       issuer: "https://id.example.com",
       clientId: "example-app",
       redirectUri: "https://app.example.com/oauth",
       postLogoutRedirectUri: "https://app.example.com/signed-out",
       scopes: ["openid", "profile"],
       protectedOrigins: ["https://api.example.com"]
   )
   let client = try await OAuthClient.create(
       configuration: configuration,
       presentationAnchor: appKeyWindow
   )
   ```

4. **Sign in.** Delete `currentAuthorizationFlow` and the `application(_:open:options:)` plumbing:

   ```swift
   do {
       try await client.login()
   } catch let error as OAuthError {
       // .recoverable, .reauthenticate, .stepUp or .configuration
   }
   ```

   Keep one handler only for Universal Links that arrive while the app is cold:

   ```swift
   .onOpenURL { url in
       Task { _ = await client.handleRedirect(url) }
   }
   ```

5. **Call your API** with the authenticated session instead of `performAction`:

   ```swift
   let session = try client.authenticatedSession()
   let (data, response) = try await session.data(for: URLRequest(url: apiURL))
   ```

   Or `try await client.accessToken()` where you need the value.
6. **Observe** with `for await state in await client.sessionStates() { ... }`.
7. **Sign out** with `await client.logout()`, which returns a `LogoutOutcome`.
8. **Delete** the archived `OIDAuthState` (section 6).

## 9. Flutter, step by step

### Before (`flutter_appauth`)

```dart
final appAuth = FlutterAppAuth();
final result = await appAuth.authorizeAndExchangeCode(
  AuthorizationTokenRequest(
    '<client_id>',
    '<redirect_url>',
    issuer: '<issuer>',
    scopes: ['openid', 'profile', 'offline_access'],
  ),
);
// You store result's tokens, and later refresh with
// appAuth.token(TokenRequest('<client_id>', '<redirect_url>', refreshToken: ..., ...)).
await appAuth.endSession(EndSessionRequest(
  idTokenHint: '<idToken>',
  postLogoutRedirectUrl: '<postLogoutRedirectUrl>',
  issuer: '<issuer>',
));
```

### After (`versola_oauth`)

1. **Dependency.** Replace `flutter_appauth` in `pubspec.yaml` with `versola_oauth` (not published
   yet; see its README for how a local checkout is wired). Remove the plugin's setup:
   `appAuthRedirectScheme` on Android and the `CFBundleURLTypes` custom scheme on iOS, unless you keep
   a custom-scheme redirect.
2. **Native setup in the host app.** Android: the `VersolaRedirectActivity` intent filter. iOS: iOS
   17.4 or newer, Associated Domains for an `https` redirect, and `VersolaOAuthPlugin.presentationAnchor`
   if the app has its own window handling. See [the provider index](providers/README.md).
3. **Create and use:**

   ```dart
   final client = await OAuthClient.create(const OAuthConfiguration(
     issuer: 'https://id.example.com',
     clientId: 'example-app',
     redirectUri: 'https://app.example.com/oauth',
     postLogoutRedirectUri: 'https://app.example.com/signed-out',
     scopes: {'openid', 'profile'},
   ));

   client.sessionStates().listen((state) => print(state));

   try {
     await client.login();
     final token = await client.accessToken(); // the only credential that crosses the bridge
   } on StepUpError catch (e) {
     await client.stepUp(e);
   } on ReauthenticateError {
     // sign in again
   } on RecoverableError {
     // retry, or ask the user again
   } on ConfigurationError {
     // a deployment mistake
   }
   ```

4. **Remove your token storage.** Nothing credential-shaped is kept in Dart: delete the code that
   stores and refreshes tokens. `accessToken()` refreshes natively.
5. **Sign out** with `client.logout()`; it returns a `LogoutOutcome`.
6. **Errors**: `FlutterAppAuthUserCancelledException` becomes `RecoverableError`; the platform
   exception becomes the matching category.

Dart has no authenticated HTTP client (`spec/oauth-sdk-api.md` section 10): call your API with the
value `accessToken()` returns, and call it again for each request or batch rather than caching it.

## 10. Checklist

- [ ] The provider client is public and has PKCE `S256`; no secret is used anywhere.
- [ ] The configured `issuer` equals the discovery document's `issuer` member.
- [ ] `offline_access` is in `scopes` if the provider needs it for a refresh token
      ([providers/](providers/README.md)).
- [ ] The redirect URI is registered with the provider exactly as configured, and (for `https`) the
      app's `assetlinks.json` / `apple-app-site-association` are served.
- [ ] `postLogoutRedirectUri` is registered with the provider.
- [ ] No code reads, writes or sends a refresh token or a raw ID token.
- [ ] The old `AuthState` (or archived `OIDAuthState`, or Dart token storage) is deleted after the
      first successful `login()`.
- [ ] Your sign-in screen handles the four error categories; a `Configuration` error is not caught
      silently in production.

## Sources

All fetched and read on 2026-10-30. The fetch tool returns a summary of long pages, so exact
signatures should be rechecked against the page or the Javadoc before you rely on them.

- AppAuth-Android README: <https://github.com/openid/AppAuth-Android>. Used for configuration and
  discovery, the request and intents, the redirect (`appAuthRedirectScheme`,
  `RedirectUriReceiverActivity`), `AuthState` persistence and `performActionWithFreshTokens`,
  `EndSessionRequest`, client secrets and dynamic registration, browser allow and deny lists, the
  WebView statement, PKCE, the API levels, `setNonce(null)` and `setSkipIssuerHttpsCheck`. The
  README links no wiki. Its Javadoc (<https://javadoc.io/doc/net.openid/appauth>) returned only
  navigation, so the Javadoc was not read: method signatures beyond the README's examples are
  unverified.
- AppAuth-Android `IdToken.java`, the ID-token checks and the statement that the signature is not
  verified:
  <https://raw.githubusercontent.com/openid/AppAuth-Android/master/library/java/net/openid/appauth/IdToken.java>
- AppAuth-iOS README: <https://github.com/openid/AppAuth-iOS> and
  <https://raw.githubusercontent.com/openid/AppAuth-iOS/master/README.md>. Used for discovery,
  `OIDAuthorizationRequest`, `OIDAuthState.authState(byPresenting:presenting:)`,
  `resumeExternalUserAgentFlow`, `performAction`, user agents, WebView, PKCE, HTTPS redirects and the
  `webcredentials` requirement, OS floors. The README does not cover end-session usage or `OIDAuthState`
  persistence beyond saying it is the only object to serialize.
- AppAuth-iOS API index, class list (end session, registration, token request classes):
  <https://openid.github.io/AppAuth-iOS/docs/latest/annotated.html>, and `OIDIDToken`:
  <https://openid.github.io/AppAuth-iOS/docs/latest/interface_o_i_d_i_d_token.html>
- `flutter_appauth` on pub.dev (version 12.1.0 at the time of reading):
  <https://pub.dev/packages/flutter_appauth>, and its README:
  <https://raw.githubusercontent.com/MaikuB/flutter_appauth/master/flutter_appauth/README.md>. The
  pages do not mention `clientSecret`, `allowInsecureConnections`, `promptValues` or `externalUserAgent`,
  so those are unverified for this guide.
- This repository: [`spec/oauth-sdk-api.md`](../spec/oauth-sdk-api.md),
  [`spec/errors.md`](../spec/errors.md), [`spec/state-machine.md`](../spec/state-machine.md),
  [`.claude/rules/security.md`](../.claude/rules/security.md), and the public declarations in
  `android/oauth/`, `ios/Sources/OAuthClient/` and `flutter/versola_oauth/lib/`.
