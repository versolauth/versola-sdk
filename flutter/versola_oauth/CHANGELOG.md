## 0.2.0

Server errors are now handled by the SDK itself, Flutter apps can call their API with a DPoP-bound token, iOS finishes an interrupted sign-in on its own, and the session survives a lot of situations that used to end it. The API stays production ready; the interfaces below changed because they had to.

### What's new

- **Server errors, `429` and `Retry-After`.** A provider that answers 408, 429, 500, 502, 503 or 504 is retried where a repeat is safe, within one retry budget per call. `Retry-After` (seconds or an HTTP date) is honoured and never shortened; when it doesn't fit the budget, the SDK stops, pauses requests to that origin and hands your app one error that carries the wait. New cause `Recoverable.Server(status, retryAfterMillis, attempts, elapsedMillis)` (`.server(...)` on iOS, `RecoverableCause.server` on Flutter). The minimal handler is still one `catch` of `Recoverable` and a retry button.
- **Flutter: `OAuthClient.httpClient()`.** A `package:http` client that sends your request through the native SDK with the token attached, so DPoP-bound tokens work from Dart and no token or proof crosses the bridge. Wrap it with your own interceptors or retry clients; a `dio` adapter is in the docs. The plugin now depends on `package:http` (`>=1.6.0 <2.0.0`).
- **iOS: a sign-in interrupted by process death finishes on its own.** `OAuthClient.create` resumes a pending authorization when the redirect arrives; `resumePendingAuthorization()` stays but is optional.
- **Redirects.** A redirect whose `state` is not the awaited one is ignored while a login waits, so another app or a stale link can no longer cancel the user's sign-in. `login()`, `stepUp()` and `logout()` end a resume that is only waiting for a redirect, and a live `login()` is bounded by the request's ten minutes. The Android redirect activity ignores intents for other URIs and no longer raises the app over the browser tab.
- **Android: `minCompileSdk` per module.** Each AAR now declares what it really needs (14 to 31, not 37). An app still needs `compileSdk` 37 today, because OkHttp's own AAR declares it.

### Fixes that keep users signed in

- A refresh stores the rotated refresh token before the ID token is judged; a rejected ID token on refresh is a `Configuration` error and the session stays `Authenticated`. An unreachable key set no longer drops the rotation.
- A missing grant no longer wipes a pending authorization or the DPoP key.
- Android: a storage fault or a cancelled caller no longer signs the user out; a permanently invalidated storage key replaces itself; the pending request survives a locked key; StrongBox gets one retry before falling back to the TEE.
- iOS: a locked device gives `unlockRequired` instead of a raw CryptoKit error; DPoP learns the server clock from `Date` (a phone with a wrong clock keeps its session); a sign-in without a refresh token keeps the DPoP key; a refresh keeps the stored ID token; a reinstalled app opens signed out.
- A blocked SDK call no longer starves `Dispatchers.IO`: the SDK's own blocking work runs on its own dispatcher, so an app can call `execute()` from IO coroutines.

### Hardening

- Discovered endpoints must be `https` (plain `http` only for `localhost`, `127.0.0.1` and `[::1]` in local development); the RFC 9207 `iss` is compared byte for byte; secrets no longer appear in error messages or `toString`.
- Discovery and key-set caches expire (5 minutes to 24 hours, from `Cache-Control`); iOS caps response bodies at 1 MiB, gives each request a deadline derived from the remaining budget, and bypasses the URL cache for these fetches.
- After an ID token is rejected at login, the issued refresh token is revoked (best effort).
- Release builds: signed artefacts, Gradle dependency verification, build provenance attestation.

### Upgrading

- **Exhaustive `when` and `switch` break.** `Recoverable.Cause.Server` (Kotlin), `.server` (Swift) and `RecoverableCause.server` (Dart) are new cases: add a branch, or let your default branch take them.
- **Android: the on-disk format changes in one direction.** Stored secrets are bound to their slot; 0.1.0 data is read and upgraded on first use. Rolling an app back to 0.1.0 afterwards signs users out.
- **Android: new default methods on `CredentialStore`** (`replaceRefreshToken`, `saveIdToken`) and on `ProviderMetadataCache`; existing implementations keep working.
- **Swift Package Manager: five empty products are gone** (`VersolaCore`, `VersolaDPoP`, `VersolaStorage`, `VersolaBrowser`, `VersolaURLSession`). `VersolaOAuth` is the only product; a dependency that names one of the others no longer resolves.
- **Cached discovery and key-set files** from 0.1.0 are fetched once more on first use.
- **Flutter plugin:** the iOS git dependency now builds through Flutter's symlinked plugin path; the example and docs use `httpClient()`.

### Requirements

Android `minSdk` 26, `compileSdk` 37 (OkHttp's requirement); iOS 17.4; Flutter 3.47.x and Dart 3.13.x.

## 0.1.0

- Initial binding of the generic OAuth SDK (issue #46, B6): `OAuthClient` with `login`,
  `stepUp`, `logout`, `accessToken`, `refresh`, `claims()`, `currentSessionState()`,
  `userInfo`, `keyAttestation` and `sessionStates()`, over a Pigeon bridge to the Android and
  iOS facades.
