# Generic OAuth 2.0 / OIDC SDK: public API

Normative for the generic facade on every platform (issue #46, part B). The `Versola` facade is
a separate public API that shares this document's protocol core and may differ where Versola chose
something for its users (edge back channel, security profiles, DPoP by default); it is documented
by `README.md` and the existing spec. The state machine (`state-machine.md`), the error taxonomy
(`errors.md`) and the retry policy (`retry-policy.md`) apply to both facades unchanged; this
document only adds what the generic facade exposes and how it decides defaults.

The platforms expose one API in three languages. Names follow each language's convention;
semantics, states, error categories, defaults and validation rules do not diverge. A platform that
cannot express a rule records the deviation here.

## 1. What the SDK is

A public client for native apps (RFC 8252, OAuth 2.1) against any conforming OpenID Provider,
configured from discovery (OpenID Connect Discovery 1.0, RFC 8414) or from explicit endpoints,
owning the whole lifecycle: browser sign-in with PKCE, ID-token validation, secure storage,
single-flight refresh, authenticated HTTP, sign-out. The integrator sees a session, not tokens.

Not in the first release: device authorization, CIBA, token exchange, native passkey APIs,
multiple simultaneous accounts, desktop and web. None of them is precluded by the shapes below.

## 2. Design rules

Each rule exists because a widely used library got it wrong; the SDK is judged against them.

1. **The type carries the app's action.** Errors are the four categories of `errors.md`; a
   state is one of the seven of `state-machine.md`. No integer codes, no strings to match on.
2. **Nothing that must happen is optional.** PKCE S256, `state`, `nonce`, `iss` when advertised,
   ID-token validation, redirect validation before any network call: none has an off switch.
3. **Misuse is unrepresentable, not documented.** No `clientSecret` parameter exists. No web view
   can be passed. Reserved authorization parameters cannot be overridden through the extras map.
4. **The SDK owns persistence.** The pending request is persisted before the browser opens; the
   token response is persisted before it is returned; the app never serialises session state.
5. **One refresh in flight.** Concurrent callers coalesce; a rotated refresh token is never
   spent twice; a replayed one is `Reauthenticate`, not a retry.
6. **The SDK never opens the browser on its own.** `Reauthenticate` is a diagnosis; the app
   decides when `login()` runs.
7. **Tokens go only where the app said.** The authenticated client attaches a token only to the
   origins it was configured for; every other request passes untouched.
8. **Provider differences are capabilities, not branches.** Behaviour follows the discovered
   metadata and `providers.md`; the core never branches on an issuer string or a product name.
9. **The surface can only shrink before 1.0.** Wiring is `internal` or behind the opt-in marker;
   every public symbol is a semver promise held by `apiCheck`, the Swift public API and the Dart
   API.

## 3. Configuration

One value type, validated eagerly: a bad value is `Configuration(InvalidConfiguration)` at
construction, never behind a login screen.

| Field | Type | Default | Rules |
|---|---|---|---|
| `issuer` | URL | required unless `endpoints` is given | `https` only, host present, no query or fragment (RFC 8414 section 2). The discovery document is fetched at the issuer's well-known path and its `issuer` member must equal the configured value, where a single trailing slash is ignored for that comparison only (Auth0 announces its issuer with one); `DiscoveryIssuerMismatch` otherwise, with no per-provider exception. The ID token's `iss` is then compared to the discovered `issuer` byte for byte. A metadata document whose `issuer` is a template (Entra's `common` endpoint) is therefore unsupported; `providers.md` says what to configure instead |
| `endpoints` | `ProviderEndpoints` | none | for a provider without discovery: `authorizationEndpoint`, `tokenEndpoint`, `issuer`, optional `jwksUri`, `userinfoEndpoint`, `revocationEndpoint`, `endSessionEndpoint`, `pushedAuthorizationRequestEndpoint`, `idTokenSigningAlgValuesSupported`; all `https`; mutually exclusive with discovery, and the SDK then treats unlisted capabilities as absent |
| `clientId` | string | required | non-blank |
| `redirectUri` | URI | required | absolute, no fragment; `https` (verified link, preferred), loopback, or a private-use scheme (accepted with a logged warning on every `create()`); cleartext `http` to a non-loopback host refused |
| `postLogoutRedirectUri` | URI | none | same rules as `redirectUri`; when absent `post_logout_redirect_uri` is not sent. Android, under Auth Tab: the tab intercepts this URI, so an `https` host must be a verified App Link of the app like `redirectUri`'s, or the tab closes unverified and `logout()` reports `sessionEnded = false` (a Custom Tab would have shown the page instead) |
| `scopes` | set of strings | `{"openid"}` | the default scope set for `login()`; `openid` is added if missing (this is an OIDC SDK); nothing else is added silently, including `offline_access` (see section 8) |
| `tokenBinding` | `Bearer` or `Dpop(required: Boolean = false)` | `Bearer` | section 9 |
| `pushedAuthorization` | `Never`, `WhenAdvertised`, `Required` | `WhenAdvertised` | section 7 |
| `endSessionEndpoint` | URL | none | overrides the discovered `end_session_endpoint`, or supplies one when discovery has none; `https`; the parameters the SDK sends stay those of RP-Initiated Logout 1.0 (section 12). The only endpoint that may be overridden alongside `issuer`: vendors commonly place sign-out at a non-standard URL, and no other endpoint is safe to redirect by configuration |
| `protectedOrigins` | set of origins | empty | `scheme://host[:port]`, `https`, or `http` on a loopback host only (`127.0.0.1`, `localhost`, `[::1]`: a resource on the developer's machine under `adb reverse`, the same allowance the issuer has; never a remote host); the only origins the authenticated client sends a token to; may also be given per client (section 10) |
| `retryPolicy` | `RetryPolicy` | `Default` | bounds and maxima of `retry-policy.md`; a value above a maximum is `InvalidConfiguration` |
| `unlockPolicy` | `UnlockPolicy` | `None` | `state-machine.md`'s `Locked` state is reachable only under `OnAppUnlock` |
| `clockSkewTolerance` | duration | 60 s | tolerance for `exp`, `iat`, `nbf` in ID-token validation; maximum 5 minutes |
| `logger` | `Logger` | platform default | section 12 |
| `httpClient` | platform HTTP client | platform default | OkHttp `OkHttpClient` / `URLSession` configuration; redirects are switched off on the SDK's own requests whatever the client does |

Explicit endpoints are the escape hatch for providers that do not publish discovery or publish it
at a non-standard path. They are not a way to override a discovered value: a configuration with both
`issuer` and `endpoints` is refused.

## 4. Entry point and lifecycle

```kotlin
val oauth = OAuthClient.create(context, configuration)
```

- One instance per configuration per process; a second `create()` with the same configuration
  returns the same instance (two stores over one file is a known failure). A different
  configuration in the same process is a different instance with its own storage, keyed by a hash
  of `issuer` (or the endpoints) and `clientId`, so a later multi-account feature needs no
  migration.
- `create()` does no network I/O and no key generation. It restores persisted state: a stored
  grant yields `Authenticated`; a pending authorization request younger than ten minutes yields
  `Authorizing`; otherwise `Unauthenticated`. Discovery runs lazily on the first operation that
  needs it and is cached on disk; the cache is refetched when it is older than 24 hours or when a
  request fails in a way a changed endpoint could explain.
- `sessionState` is the source of truth. Every operation below publishes through it, including an
  authorization that finishes in a process other than the one that started it.
- The redirect reaches the SDK without app code on Android (the SDK's redirect activity, declared
  by the app with its intent filter as the Versola facade does today) and through
  `handleRedirect(url)` on iOS, which the app calls from its URL handler and which returns whether
  the URL was one the SDK was waiting for. The Flutter plugin wires both natively.
- There is no `resumePendingAuthorization()` on Android: a redirect delivered to a cold-started
  process completes the pending request and publishes `Authenticated` or an error state
  transition on its own. `create()` starts that work on a scope the SDK owns, when the restored
  state is `Authorizing`; it runs the tail of `login()` (redirect validation, code exchange,
  ID-token validation, persistence, then `Authenticated`), with `max_age` taken from the restored
  request. An app that wants to await it observes `sessionState`.
- **iOS:** the same: a restore that finds `Authorizing` starts that work (`create()` performs the
  restore; if the Keychain cannot be read at launch, the next call that restores does), and the
  session completes on its own once the redirect arrives. The only difference is how the redirect
  reaches the SDK: the app's URL handler is the only thing the system calls, so the app passes the
  URL to `handleRedirect(url)` (the Flutter plugin does it natively). `resumePendingAuthorization()`
  stays on the iOS `OAuthClient` and is optional: an app that wants to await the outcome calls it,
  and calling it while the resume `create()` started is running joins that resume instead of making
  a second attempt (the code is single-use). It also finishes a pending request the automatic
  resume did not see, one a system cancel left in the running process. Observing `sessionState`
  works as on Android.
- On both platforms the typed error of the background resume is only logged (the log line holds
  the error's own text or only its type, never a secret), because no caller awaits it. A failure
  after the redirect arrived settles the state as `login()` does; one before it (the store or the
  provider's discovery cannot be read) leaves `Authorizing` and the pending request in place.
- `logout()` ends a resume that is still waiting for its redirect, then proceeds: the resume
  holds the authorization lock that the end-session step needs, and the pending request is
  abandoned by the local wipe.
- **Order.** While the state is `Authorizing` no grant is stored. An app that calls an
  authenticated operation (`accessToken()`, `refresh()`, `userInfo()`, a request through the
  authenticated client or session) before the resume has left `Authorizing` gets the
  no-grant `Reauthenticate` error, and on iOS today that error wipes local
  state, including the pending request and the DPoP key the code exchange is bound to
  (`dpop_jkt`), so the sign-in can no longer finish. Observe `sessionState` until it has left
  `Authorizing` before touching those operations. A known gap, tracked separately: a missing
  grant should not wipe anything.

## 5. Operations

| Operation | Suspends until | Result | Errors |
|---|---|---|---|
| `login(options)` | the redirect is validated and the code exchanged, or the browser is dismissed | nothing (the session is observable); `Authenticated` published after the grant is durably stored | `Recoverable(UserCancelled, SystemCancelled, Network, PendingRequestExpired)`, `Reauthenticate(AuthorizationDenied, InteractionRequired)`, `Configuration(...)` |
| `logout(options)` | the local wipe is done; server-side steps are best effort | `LogoutOutcome(sessionEnded: Boolean, tokenRevoked: Boolean)`; `Unauthenticated` published unconditionally | never throws for a server-side failure; `Configuration` only for a misuse |
| `accessToken()` | a token not within its refresh skew is available, refreshing once if needed (single-flight) | `AccessToken(value, type: Bearer or DPoP, expiresAt, scopes)` | `Reauthenticate(GrantRejected, SessionExpired)`, `Recoverable(Network, UnlockRequired)` |
| `refresh()` | the refresh completed | nothing | as `accessToken()` |
| `claims` | — (property, memory) | `IdTokenClaims?` of the last validated ID token; null when unauthenticated. After a cold start the stored ID token is read back by the first operation (`accessToken()`, `userInfo()`, a refresh), without re-verifying it: it was validated before it was stored | — |
| `userInfo()` | the UserInfo response is validated | `UserInfo` (the standard claims typed, the rest as a read-only map); `sub` must equal the ID token's `sub` (OIDC Core 5.3.2) | `Configuration(ProviderUnsupported)` when no endpoint, `Recoverable`, `Reauthenticate` |
| `stepUp(challenge, options)` | as `login()` | re-authorizes with the challenge's `acr_values` and `max_age` and the configured scopes (or the options'); the app re-issues the refused call | as `login()` |
| `metadata()` | discovery is cached | `ProviderMetadata` | `Configuration(Discovery*)`, `Recoverable(Network or Server)` |
| `authenticatedClient(origins)` / `interceptor(origins)` / `authenticatedSession(origins)` | — | section 10 | — |
| `keyAttestation()` | the DPoP key exists | `KeyAttestation?` (null under `Bearer`) | — |

`login()` while `Authenticated` starts a new authorization and, on success, replaces the stored
grant; on cancel or failure the existing session stays (`state-machine.md`, settle on
`Authenticated`). `login()` while `Authorizing` is refused with
`Configuration(InvalidConfiguration("an authorization is already in progress"))`; the app observes
the state before asking.

## 6. `login()` options

| Option | Maps to | Rules |
|---|---|---|
| `scopes` | `scope` | overrides the configured set for this request; `openid` added if missing |
| `prompt` | `prompt` | closed enum: `None`, `Login`, `Consent`, `SelectAccount`, `Create`; `None` makes an interaction error `Reauthenticate(InteractionRequired)` rather than a browser prompt |
| `loginHint` | `login_hint` | |
| `uiLocales` | `ui_locales` | list, in order |
| `acrValues` | `acr_values` | list; also set by `stepUp()` |
| `maxAge` | `max_age` | seconds; when set, the ID token must carry `auth_time` and it is checked |
| `resources` | `resource` (RFC 8707) | repeatable; also sent on the token request |
| `ephemeralBrowser` | platform | `false`: an ephemeral session breaks passkeys and SSO; opt-in only. Best effort, as iOS's `prefersEphemeralWebBrowserSession`: Android passes it to the Auth Tab or Custom Tab when the provider supports ephemeral browsing, and otherwise logs one warning and opens the session shared. The end-session request is never ephemeral |
| `extraParameters` | verbatim | a map for provider extensions (`audience`, `claims`, `kc_idp_hint`, …); a key that collides with a reserved parameter (`client_id`, `redirect_uri`, `response_type`, `scope`, `state`, `nonce`, `code_challenge*`, `request_uri`, `prompt`, `max_age`, `acr_values`, `resource`, `login_hint`, `ui_locales`, `dpop_jkt`) or names what the SDK keeps unrepresentable or outside its validator (`client_secret`, `request`, `response_mode`) is `Configuration(InvalidConfiguration)` |

The SDK always sends `response_type=code`, `code_challenge_method=S256`, a fresh `state` and
`nonce` (CSPRNG, at least 128 bits each), and `response_mode` unset (query). A discovery document
whose `code_challenge_methods_supported` is present without `S256` is
`Configuration(ProviderUnsupported("S256"))` at `login()`; an absent member is treated as unknown
and `S256` is sent anyway, since providers that omit the member accept it (`providers.md`). JARM, `request`
objects and `response_mode=form_post` are not used.

## 7. Pushed authorization requests

| `pushedAuthorization` | `pushed_authorization_request_endpoint` advertised | not advertised |
|---|---|---|
| `Never` | plain request | plain request |
| `WhenAdvertised` (default) | PAR, then `request_uri` in the browser | plain request |
| `Required` | PAR | `Configuration(ProviderUnsupported("par"))` |

`require_pushed_authorization_requests: true` in discovery is honoured regardless of the option:
`Never` then yields `ProviderUnsupported` rather than a request the provider will refuse. A PAR
rejection surfaces as `Configuration(AuthorizationRejected(code))` before the browser opens, which
is the precise error scenario 17 cannot give without PAR.

## 8. Refresh and session lifetime

- A refresh token is stored encrypted when issued; a response that echoes the same value stores it
  again unchanged; a response that rotates it stores the new value before the old one is forgotten,
  with the pending-rotation slot of `state-machine.md` persisted first.
- `offline_access` is not added to any request by the SDK. Providers that need it for a refresh
  token say so in `providers.md`; the integrator puts it in `scopes`. The SDK logs once, at
  `create()`, when the configured scopes lack it and the discovered `scopes_supported` lists it.
- A session without a refresh token (the provider issued none) is `Authenticated` until the access
  token expires, then `accessToken()` is `Reauthenticate(SessionExpired)`. Nothing is retried.
- `invalid_grant` on refresh wipes the grant and is `Reauthenticate(GrantRejected)`, never retried.
- The refresh skew is `state-machine.md`'s: `min(30 s, expires_in / 10)` on a monotonic clock. A
  response without `expires_in` means *unknown*, not expired: no proactive refresh, the session
  waits for the 401, and one warning is logged.
- The generic facade sends no `Idempotency-Key`: it is not defined by a standard a provider is held
  to, and the core sends only what a standard defines (ADR 0001). The pending-rotation slot is still
  persisted, so a process killed mid-rotation restarts with the outgoing token and retries once; a
  provider that already rotated answers `invalid_grant`, which is `Reauthenticate(GrantRejected)`.
  Scenarios 09 and 13 therefore hold for the Versola facade only.
- An `id_token` on a refresh response is validated with the same rules as at login, except that
  `nonce` is not required and `auth_time` must not move backwards (OIDC Core 12.2).

## 9. Token binding

| `tokenBinding` | `dpop_signing_alg_values_supported` includes `ES256` | absent or without `ES256` |
|---|---|---|
| `Bearer` (default) | bearer | bearer |
| `Dpop(required = false)` | DPoP: hardware P-256 key, proofs on every token and resource request, nonce per origin | bearer, one warning logged |
| `Dpop(required = true)` | DPoP | `Configuration(ProviderUnsupported("dpop"))` |

Bearer is the default because a resource server that does not verify DPoP rejects a DPoP-bound token
presented as `Authorization: DPoP`; an integrator opts in when their resource servers do. Under DPoP
the behaviour is `errors.md`'s: one `use_dpop_nonce` retry per origin, one `invalid_dpop_proof`
retry, clock-skew learned from the `Date` header, `ath` on resource requests. The key is
non-exportable, not user-gated, and regenerated on every `login()`; `keyAttestation()` reports the
tier read back. The authorization request, pushed or not, carries `dpop_jkt` (RFC 9449 section
10), the thumbprint of that key; a refresh is proved with the same key. A key whose
tier is `Software` where hardware was required (`Dpop(requireHardware = true)` on Android,
`dpop(required: true)` on iOS) is `Configuration(HardwareBindingUnavailable)` before any request to
the authorization endpoint (`errors.md`). Scenario 33 holds all of this against a real provider.

On Android the key is generated in StrongBox first. A StrongBox that is absent (the Keystore's
`StrongBoxUnavailableException`) falls through to the TEE at once; any other provider fault of the
attempt may be transient (a busy secure element), so it is retried once before the fall-through.
The key is generated once and kept, so a fall-through is not revisited: the key stays in the TEE
until it is regenerated (the next `login()`, or a logout), and `keyAttestation()` reports
`TrustedEnvironment`, not `StrongBox`, for that whole time. `requireHardware` is satisfied by the
TEE; there is no way to require StrongBox itself.

## 10. The authenticated client

The platform's HTTP client with the session attached, so most integrators never hold a token:

| Platform | Shape |
|---|---|
| Android | `interceptor(origins)`: an OkHttp application interceptor; `authenticatedClient(origins)`: the configured client plus the interceptor, redirects off |
| iOS | `authenticatedSession(origins)`: a `URLSession` wrapper (`data(for:)`) that attaches the token and handles the retries |
| Flutter | `httpClient({origins})`: a `package:http` `Client` (`BaseClient`) whose `send` hands the request to the native authenticated client above and returns its response, so the token, the DPoP key and its proofs and the refresh never reach Dart; an app wraps it with its own interceptors, ours innermost |

Behaviour, per request to a protected origin: attach `Authorization: Bearer` or `DPoP` plus a proof;
on 401 with `error="invalid_token"` (or no `error`) refresh once and replay once; on 401 with
`error="insufficient_user_authentication"` (RFC 9470) publish `StepUpRequired` and raise
`StepUp(acrValues, maxAge)`; on 401 `use_dpop_nonce` retry once with the nonce; everything else is
returned as the response it is (403, 404, 429, 5xx are the app's). A request to any other origin
passes through untouched, and `origins` must be non-empty and `https` (or `http` on a loopback
host, as in section 3; `InvalidConfiguration` otherwise). All of this sits inside the originating call's retry budget.

A request the app addresses to a protected origin carries the SDK's credential and no other: the
client sets `Authorization` (and, for a key-bound token, `DPoP`) itself, replacing any value the app
supplied under those names, so an app's own `Authorization` is never sent beside the SDK's; under a
bearer token a `DPoP` header the app supplied is dropped. On any other origin the app's headers go
out untouched.

A key-bound (DPoP) access token with no proof source configured fails closed with
`Configuration(InvalidConfiguration)` and nothing is sent, never as a bare `Bearer`.

Flutter's `httpClient()` is the same behaviour reached through the bridge: Dart describes the
request (method, URL, header pairs, bytes) and receives the response (status, reason phrase where
the platform has one, header pairs, bytes); nothing credential-shaped crosses. What the bridge
shapes, and what is therefore Flutter's deviation from the native clients:

- `origins`, where given, replaces `protectedOrigins` for that client (it does not narrow them), as
  it does for the native clients.
- The body is buffered in memory in both directions and in both runtimes; there is no streaming and
  no limit beyond the process's memory.
- `origins` is validated natively when the first request is sent, because `httpClient()` returns
  synchronously: an empty set (and, with none given, an empty `protectedOrigins`) or a non-`https`
  origin fails that request with `Configuration(InvalidConfiguration)` before anything is sent.
- A request that is not a valid HTTP request (a relative URL, a header name that is not a token or a
  value that is not visible ASCII, space or tab, a body on `GET`) is
  `Configuration(InvalidConfiguration)` with a fixed text that does not quote the header.
- A call that produced no HTTP response (no route, DNS, TLS, the native client's own timeout) is not
  an SDK error and has no place in the taxonomy; Dart raises `package:http`'s `ClientException`
  carrying the native exception's class name and never its message. Timeouts are the native
  client's own configuration.
- Response headers: Android reports every value of a repeated header, iOS's `URLSession` folds them
  into one comma-separated value; Dart joins repeated names with a comma (`package:http`'s
  convention). `Set-Cookie` cannot be split reliably from that.
- There is no cancellation: `package:http`'s `Abortable` is not honoured and a Dart-side timeout
  stops waiting without stopping the native call.

The access token is also available as a value (`accessToken()`), documented as the escape hatch: a
token handed to app code is one the app can log.

## 11. ID-token and UserInfo validation

Mandatory on every platform, before the token response is persisted (OIDC Core 3.1.3.7):

1. Signature with a key from `jwks_uri` (cached, refetched once on an unknown `kid`), algorithm in
   the closed set `RS256`, `PS256`, `ES256`, `ES384`, `ES512`, `RS384`, `RS512`, `PS384`, `PS512`,
   and in `id_token_signing_alg_values_supported` when advertised; `none` and HMAC algorithms are
   refused (a public client has no secret to verify with).
2. `iss` equals the configured issuer (or the discovered one, which must be equal).
3. `aud` contains `clientId`; with several audiences `azp` must be present and equal `clientId`.
4. `exp` in the future and `iat` present, within `clockSkewTolerance` after skew correction.
5. `nonce` equals the value sent, compared in constant time (login only).
6. `auth_time` present and no older than `max_age` when `max_age` was sent.
7. `at_hash`, when present, matches the access token (`c_hash` is not applicable to `code`).

A failure is `Configuration(IdTokenRejected(reason))`, where `reason` is a closed enum
(`Signature`, `Algorithm`, `Issuer`, `Audience`, `Expired`, `IssuedAt`, `Nonce`, `AuthTime`,
`Malformed`, `AccessTokenHash`): nothing is persisted, the pending request is discarded, the state
settles on what it was before `login()`. The category is `Configuration` because every cause is
either a deployment mistake (issuer, algorithm, audience, clock) or an attack, and neither is fixed
by the user trying again; see `errors.md`'s rule that a category is the app's action.

`IdTokenClaims` exposes `subject`, `issuer`, `audience`, `issuedAt`, `expiresAt`, `authTime`,
`acr`, `amr`, `azp` typed, and every claim as a read-only map; `nonce` and the raw token are not
exposed. The raw token is stored encrypted for `id_token_hint` only.

UserInfo: `sub` must equal the ID token's `sub`; a signed (JWT) UserInfo response is verified with
the same key set; a response whose `sub` differs is `Configuration(UserInfoRejected)`.

## 12. Sign-out

`logout(options)` with `endSession = true`, `revoke = true` by default:

1. Revoke the refresh token at `revocation_endpoint` when advertised (RFC 7009; a public client
   sends `client_id` only). Best effort; a failure is logged and `tokenRevoked = false`.
2. End the server session through the system browser at `end_session_endpoint` when advertised
   (RP-Initiated Logout 1.0): `id_token_hint`, `client_id`, `post_logout_redirect_uri` when
   configured, `state`. Best effort; dismissed or failed is `sessionEnded = false`.
3. Wipe everything credential-shaped: refresh token, raw ID token, pending request, rotation slot,
   nonce caches, DPoP key. Unconditional; `Unauthenticated` is published even if 1 or 2 failed.

A provider without `end_session_endpoint` gets steps 1 and 3 and `sessionEnded = false`; the app is
told, not surprised (`providers.md` lists which providers this is). A sign-out URL the provider
does not advertise is given as the `endSessionEndpoint` override (section 3); the parameters stay
standard. A provider whose sign-out takes non-standard parameters (Cognito's `logout_uri`) is
handled in app code after `logout()` has wiped locally; the SDK does not special-case it.

## 13. Platform mapping

| Concept | Kotlin (`versola.oauth`) | Swift (`VersolaOAuth`) | Dart (`versola_oauth`) |
|---|---|---|---|
| Entry point | `OAuthClient.create(context, config)` | `OAuthClient.create(configuration:presentationAnchor:)` (static, async: one instance per configuration per process, as on Android; an `init` could not return an existing one) | `OAuthClient.create(config)` |
| Configuration | `OAuthConfiguration(...)` data class | `OAuthConfiguration` struct | `OAuthConfiguration` |
| State | `Flow<SessionState>` (cold; the first emission is the restored state, which a `StateFlow` could not promise) | `sessionStates() -> AsyncStream<SessionState>` (one stream per observer) | `Stream<SessionState> sessionStates()` (any number of listeners over one native subscription; a late listener first gets the latest state), `Future<SessionState> currentSessionState()` |
| Sign-in | `suspend fun login(options)` | `func login(_ options:) async throws` | `Future<void> login([options])` |
| Options | `LoginOptions` data class | `LoginOptions` struct | `LoginOptions` |
| Sign-out | `suspend fun logout(options): LogoutOutcome` | `func logout(_:) async -> LogoutOutcome` | `Future<LogoutOutcome> logout([options])` |
| Token | `suspend fun accessToken(): AccessToken` (`isDpopBound`; the scheme is `DPoP` if set, else `Bearer`) | `func accessToken() async throws -> AccessToken` (`tokenType` is `Bearer` or `DPoP`, in that spelling whatever the provider's `token_type` said; a type other than DPoP is `Bearer`, as on Android) | `Future<AccessToken> accessToken()` |
| Claims | `val claims: IdTokenClaims?` | `var claims: IdTokenClaims? { get async }` | `Future<IdTokenClaims?> claims()` (a method, not a getter: the claims stay native, so the answer is asynchronous, and a `Future` getter would make `client.claims != null` always true) |
| UserInfo | `suspend fun userInfo(): UserInfo` | `func userInfo() async throws -> UserInfo` | `Future<UserInfo> userInfo()` |
| Step-up | `suspend fun stepUp(challenge, options)` | `func stepUp(acrValues:maxAge:options:) async throws` (the challenge is the `stepUp` case's payload) | `Future<void> stepUp(challenge, [options])` |
| HTTP | `interceptor(origins)`, `authenticatedClient(origins)` | `authenticatedSession(origins)` | `httpClient({origins})`, a `package:http` `Client`; `accessToken()` stays the escape hatch |
| Browser leg | Auth Tab (androidx.browser, activity result) where the Custom Tabs provider supports it, Custom Tabs otherwise, any browser last; `WebView` unrepresentable | `ASWebAuthenticationSession` | native |
| Redirect | an Auth Tab returns it as its result; otherwise the manifest-declared activity | `ASWebAuthenticationSession` returns it; `handleRedirect(_ url: URL) async -> Bool` feeds a Universal Link received while the app was cold to the pending authorization that `create()` resumes | native |
| Errors | `sealed class VersolaError : Exception` (the rename to `OAuthError` is deferred, ADR 0001) | `enum OAuthError: Error, Sendable` with the same four cases and payloads | `sealed class OAuthError implements Exception` |
| Internal wiring | `@VersolaInternalApi` (`RequiresOptIn`, error level) | `package` access / `_` prefix, not in products | `src/` private, not exported |

Threading: Kotlin APIs are `suspend` and main-safe; the SDK never blocks the caller's thread except
inside an OkHttp interceptor, where the work it waits on runs on a dispatcher the SDK owns. Swift
APIs are `async` on a `Sendable` client; the coordinator is an actor. Dart APIs return futures; the
plugin forwards to the native SDK and never reimplements protocol logic (`flutter.md`).

Flutter: the Dart side may receive the short-lived access token (issue #46 decision 7) and nothing
else credential-shaped; refresh tokens, keys and the pending request stay native. A DPoP-bound
token is used through `httpClient()`, which executes the request natively, so no proof-minting
capability crosses the bridge.

## 14. Persistence

As `state-machine.md`'s persistence summary, minus the edge-mode rows, plus:

| Item | Storage | Survives process death | Survives logout |
|---|---|---|---|
| JWKS | Disk, unencrypted | yes | yes |
| Configuration hash (storage key) | Disk | yes | yes |

Granted scopes are not persisted: `stepUp()` re-requests the configured scopes, or the ones its
options carry, which an app that changed them per login still has. The Versola facade requires
them as a parameter for the same reason.

## 15. Logging

`Logger` with `info` and `warn`; the default implementation logs warnings only. No line at any
level carries a token, code, verifier, `state`, `nonce`, proof, header value or claim value.
Warnings are emitted for: a private-use redirect scheme, DPoP requested but not advertised, no
refresh token issued, `offline_access` advertised but not configured, a response without
`expires_in`, a software-tier key. Each is emitted once per `create()`.

## 16. Open questions for review

1. `IdTokenRejected` as `Configuration` (section 11) versus a fifth category; the spec's
   four-category rule argues for `Configuration`.
2. `login()` while `Authorizing` refused (section 5) versus cancelling the outstanding request.
3. `stepUp()` takes the configured scopes by default (section 5); the Versola facade requires
   them as a parameter. The two differ in signature, not in what is sent.
4. The 24-hour discovery cache age and the 30-second refresh skew: both fixed, not configurable.
5. Whether `authenticatedSession` on iOS should be a `URLSession` subclass or a wrapper; a wrapper
   keeps the surface small.
