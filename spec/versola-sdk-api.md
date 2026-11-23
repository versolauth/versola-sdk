# Versola SDK: public API of the `Versola` facade

Normative for the `Versola` facade on every platform. The facade signs a native app in to a Versola
deployment through an `edge` and its native-app endpoints, and calls APIs through that edge. It
shares the protocol core, the state machine (`state-machine.md`), the error taxonomy (`errors.md`)
and the retry policy (`retry-policy.md`) with the generic facade (`oauth-sdk-api.md`), and differs
from it wherever Versola chose something for its users. Where this document is silent, the generic
facade's rule applies; where the two disagree, this one holds for the `Versola` facade.

**Status.** This is the target the platforms are built to (ADR 0002). Android's `Versola`
(`android/sdk`) and iOS's (`ios/Sources/VersolaSDK`) implement it, and Flutter's `versola` plugin
(`flutter/versola`) binds the two. None of them has run the scenarios of section 15 against a
staged stack yet: what each holds is proven against stubs, and the pull request that changes a
platform says which tier ran.

Checked against `versolauth/versola` at `0a2b72d34` (branch `feat/central-topology-557`, draft pull
request 1023), the working tree rather than its documentation. What that server does not do yet is
in `server-dependencies.md`.

## 1. What the facade is

A session for a native app of a Versola deployment:

- sign-in in the system browser, started and finished through edge's native endpoints
  (`/native/start`, `/native/complete`), where edge is the OAuth client towards `auth` and the
  device holds only a DPoP key (RFC 9449);
- refresh and revocation through `/native/token` and `/native/revoke`;
- authenticated HTTP to that edge (`/resources/...`), with step-up (RFC 9470);
- sign-out.

Two kinds of app use it, with one API:

| | First-party app | Partner app |
|---|---|---|
| Edge | the deployment's own | the partner's (`mode = "partner"`) |
| `issuer` | usually the edge's own address | the operator's issuer, never the partner edge's address |
| Sign-in pages | served at the issuer, which with cells is an edge | served by the operator; the partner edge serves none |
| Consent | none | the operator's consent screen, shown in the browser |
| Server support | present | **absent**: `server-dependencies.md`, "Partner native clients" |

There is no mode switch. A partner app is a configuration whose `issuer` differs from its `edgeUrl`;
everything else follows from what the edge answers.

Not part of the facade, on purpose:

- **A direct back channel to `auth`.** A deployment with cells has no `/token` at the issuer's
  address, and a `fapi2` tenant refuses a public client. An app that talks to an `auth` directly
  (a `standard` tenant, one `auth`) uses the generic facade.
- **Mutual TLS or a client certificate on the device.** Edge authenticates to `auth` with the
  client's certificate; the device is never asked for one. EST enrolment is for web and service
  clients and refuses a native one.
- **Discovery.** Edge serves no `/.well-known/*`; everything the facade needs is in its
  configuration and in what `/native/start` answers.
- **UserInfo.** No native endpoint reaches it. Claims come from the ID token (section 9).
- Bearer tokens, a client secret, an embedded web view, a private-use redirect scheme.

## 2. Design rules

The nine rules of `oauth-sdk-api.md` section 2 hold. Four more are this facade's:

1. **Edge is the only server the facade calls.** The browser is the only thing that reaches the
   issuer. A URL the facade signs a proof for but does not call (section 7) is never dialled.
2. **Values are opaque.** An authorization code, a refresh token, a `request_uri`, a blob, a
   `state`, a session id and an access token are stored and sent byte for byte (section 8).
3. **What edge would drop cannot be expressed.** `login()` takes typed options that mirror what
   `/native/start` forwards. There is no free-form parameter map: a parameter edge ignores would be
   a setting that silently does nothing.
4. **One user per session.** A step-up that comes back as another user is refused (section 6).

## 3. Configuration

One value type, `VersolaConfiguration`, validated eagerly: a bad value is
`Configuration(InvalidConfiguration)` at `create()`.

| Field | Type | Default | Rules |
|---|---|---|---|
| `edgeUrl` | URL | required | The public origin of the edge (its `edge-url`). `https`, or `http` on a loopback host only (`localhost`, `127.0.0.1`, `[::1]`; `security.md`). An origin: no path, query or fragment, because edge computes every proof's `htu` from its own configured origin and the request path |
| `issuer` | string | the origin of `edgeUrl` | The issuer identifier of the deployment, compared with the redirect's `iss` (RFC 9207) and the ID token's `iss` by simple string comparison, no normalisation. `https` (loopback exception as above), no query or fragment. Set it when the issuer is not this edge: a partner edge always, a deployment whose issuer is another address, an issuer written with a trailing slash. The default is the origin (scheme, host, a non-default port), so a trailing slash on `edgeUrl` does not reach it; a value the app passes is compared exactly as it was written |
| `clientId` | string | required | non-blank |
| `redirectUri` | URI | required | `https` with a host, no fragment: an App Link or Universal Link of the app. A private-use scheme or a loopback address is refused; an edge-fronted native client cannot register one in any tenant |
| `postLogoutRedirectUri` | URI | none | same rule as `redirectUri`; `oauth-sdk-api.md` section 3 says what happens without one |
| `requireHardwareKey` | boolean | `false` | `true`: a DPoP key that did not land in hardware is `Configuration(HardwareBindingUnavailable)` before `/native/start` |
| `unlockPolicy` | `UnlockPolicy` | `None` | `state-machine.md` |
| `retryPolicy` | `RetryPolicy` | `Default` | `retry-policy.md` |
| `clockSkewTolerance` | duration | 60 s | for the ID-token checks of section 9; maximum 5 minutes |
| `logger` | `Logger` | platform default | `oauth-sdk-api.md` section 15 |
| `httpClient` | platform HTTP client | platform default | `oauth-sdk-api.md` section 3, the same guarantees |

No `tokenBinding`, no `scopes` default, no `endpoints`, no `protectedOrigins`, no
`pushedAuthorization`: each is fixed by what the native endpoints are (DPoP always, a pushed
request always, tokens to the edge only).

`issuer` defaults to the origin of `edgeUrl` because that is what a first-party deployment is, with
or without cells. The origin and not the string: `https://id.example.com/` is a valid `edgeUrl`,
and an issuer that kept its slash would fail every sign-in after the browser. A wrong default is not a silent hazard: the first redirect fails with
`Configuration(IssuerMismatch(expected, received))` before any network call, and edge checks `iss`
again at `/native/complete`.

## 4. Entry point and lifecycle

```kotlin
val versola = Versola.create(context, VersolaConfiguration(
    edgeUrl = "https://id.example.com",
    clientId = "acme-mobile",
    redirectUri = "https://app.example.com/callback",
))
```

`oauth-sdk-api.md` section 4 applies with these differences:

- Storage is keyed by a hash of `edgeUrl`, `issuer` and `clientId`.
- `create()` does no network I/O and no key generation, and there is no discovery to run later.
- A pending authorization request is restored as `Authorizing` while it is younger than the
  lifetime `/native/start` gave it (section 5), not a fixed ten minutes.

## 5. `login()`

| Option | Sent to `/native/start` as | Rules |
|---|---|---|
| `scopes` | `scope` | `openid` and `offline_access` are always added: the facade is a session, and a response without a refresh token is `Configuration(TokenResponseMalformed)` |
| `acrValues` | `acr_values` | list, space-joined; `Acr.Sensitive` names the built-in `sensitive` class |
| `maxAge` | `max_age` | seconds; when set, the ID token's `auth_time` is checked (section 9) |
| `prompt` | `prompt` | the generic facade's closed enum (`None`, `Login`, `Consent`, `SelectAccount`, `Create`); `None` makes an interaction error `Reauthenticate(InteractionRequired)` |
| `loginHint` | `login_hint` | |
| `uiLocales` | `ui_locales` | list, in order |
| `resources` | `resource` (RFC 8707) | repeatable. Sent at `/native/start` only: `/native/complete` takes none, and the SDK sends none on a refresh |
| `claims` | `claims` | a JSON object as text, passed as given |
| `authorizationDetails` | `authorization_details` (RFC 9396) | a JSON array as text, passed as given |
| `ephemeralBrowser` | platform | `false`; `oauth-sdk-api.md` section 6 |

That list is `PassThroughParameters` of edge's `NativeService` and nothing else. The facade always
sends `redirect_uri` and a fresh `nonce` (CSPRNG, at least 128 bits), and never sends `client_id`,
`state`, `response_type`, `code_challenge`, `code_challenge_method` or `dpop_jkt`: those are
edge's.

The sequence, with what is persisted (`state-machine.md`, `Unauthenticated → Authorizing`):

1. The DPoP key is created if absent; its tier is read back.
2. `POST {edgeUrl}/native/start/{clientId}` with a proof whose `htu` is that URL. Edge's nonce
   challenge (`401`, `WWW-Authenticate: DPoP error="use_dpop_nonce"`) is answered once.
3. The answer must carry `request_uri`, `state`, `blob`, `authorization_endpoint`,
   `token_endpoint`, `revocation_endpoint` and a positive `expires_in`; anything missing is
   `Configuration(TokenResponseMalformed)`. Each of the three endpoints must be `https` (loopback
   exception), or the same error.
4. The pending request is persisted, encrypted: `state`, the blob, the nonce, the options, the
   redirect URI, the two back-channel endpoints and its expiry.
5. The system browser opens `authorization_endpoint` **as edge answered it** with exactly
   `client_id` and `request_uri`. The `request_uri` is percent-encoded as a query value and not
   otherwise touched.
6. The redirect is validated before any network call: `state` (constant time), then `iss` against
   the configured `issuer` (always required here), then `code`.
7. `POST {edgeUrl}/native/complete/{clientId}` with `code`, `state`, `iss`, `blob` and a proof whose
   `htu` is the `token_endpoint` of step 3. One attempt; never repeated (`retry-policy.md`).
8. The ID token is checked (section 9), then the grant is persisted, then `Authenticated`.

**Lifetime.** The pending request expires `expires_in` seconds after step 3, capped at ten
minutes. A redirect that arrives later is not redeemed: the wait ends with
`Recoverable(PendingRequestExpired)` at the expiry, as `state-machine.md` already says for the
ten-minute bound. Edge would answer `invalid_grant` for the expired blob; the facade does not spend
a request to learn it, and does not report a sign-in that ran out of time as a rejected grant.

`login()` while `Authenticated`, the join and supersede rules for concurrent calls, and the resume
after a cold start are those of `oauth-sdk-api.md` sections 4 and 5. A `login()` over a live session
may come back as another user: that is an account switch, and it replaces the grant.

## 6. `stepUp()`

`stepUp(challenge)` takes the `StepUp` error the authenticated client raised and runs `login()` with
its `acr_values` and `max_age` and the **scopes of the current grant**, which the facade persists
for this (section 11), so the app does not have to remember them. `stepUp(challenge, options)`
overrides scopes and the other options; `acrValues` and `maxAge` come from the challenge.

`/native/start` forwards no `id_token_hint`, so nothing on the wire ties the new authorization to
the user of the session: a person who signs in as someone else in the browser would come back with
another user's grant. The facade therefore compares the `sub` of the new ID token with the `sub` of
the session's:

- equal: the new grant replaces the old one, `Authenticated`;
- different: the new grant is **not** stored, its refresh token is revoked best effort (as a
  rejected ID token's is, `oauth-sdk-api.md` section 11), the session stays as it was and the call
  fails with `Recoverable(AccountMismatch)`. The app tells the user to continue as the account they
  are signed in with; nothing is retried by the SDK.

A session whose ID token cannot be read (it is stored encrypted and the store is locked) fails the
step-up with the store's own `Recoverable` before the browser opens.

The `sub` the step-up expects is stored with the pending request, so the rule holds for a step-up
that is finished without its caller: one whose caller was cancelled while the browser was up and
whose redirect the live process still receives. A pending request with no expected `sub` is a
login and replaces the grant. A step-up whose process died is not finished at all: on restore a
stored grant outranks a pending request (`state-machine.md`, "process death"), the request is dropped
and the session stays as it was.

## 7. Proofs, nonces and the three addresses

Every native call carries exactly one `DPoP` header, minted for that request: a repeat under the
retry policy, or after a nonce challenge, carries a new proof with a new `jti` (edge refuses a
`/native/start` proof it has seen). Which URL the proof names, and whose nonce it carries, differs
per call:

| Call | Sent to | Proof `htu` | Nonce and clock offset cached under |
|---|---|---|---|
| `/native/start` | edge | the request URL | edge's origin |
| `/native/complete`, `/native/token` | edge | `token_endpoint` from `/native/start` | that endpoint's origin |
| `/native/revoke` | edge | `revocation_endpoint` from `/native/start` | that endpoint's origin |
| `/resources/...`, `/permissions/me` | edge | the request URL, with `ath` | edge's origin |

The two back-channel endpoints are `auth`'s, on its mutual-TLS address. The facade signs for them
and **never connects to them**: there is no code path that dials a URL taken from a response. They
are remembered beside the grant (section 11), because a refresh in a later process has no
`/native/start` of its own to learn them from. Every completed sign-in replaces them with the ones
its own `/native/start` answered.

A nonce challenge relayed from `auth` has its own shape (`400`, JSON `use_dpop_nonce`, the nonce in
`DPoP-Nonce`, no `WWW-Authenticate`) and is cached under the `htu`'s origin, not edge's; edge's own
is a `401` with `WWW-Authenticate`. Both are read on the `error` value (`errors.md`).

The retry budget, the `Retry-After` cooldown and the cooldown check at the start of `login()` are
keyed by the origin the request **goes to**, which is edge's for every call above
(`retry-policy.md`).

The key is ES256 on P-256, non-exportable, never user-gated, created at the first `login()` and
kept until a logout or a rejected grant destroys it. `keyAttestation()` reports the tier read back.

## 8. Cells

A deployment may have several `auth` cells. The values a cell issues name it (`v1.<cell>.<value>`
for a code, a refresh token, a `request_uri` and a session id; a `cell` header on an access token),
and edge routes by them. For the facade this is one rule:

- A value received from the server is stored and sent **exactly as received**. The facade does not
  parse, split, trim, normalise, re-encode, shorten, compare by prefix or log any of it, and it
  derives nothing from one (no cell, no region, no expiry). The only operations on a value are:
  form-encoding or percent-encoding it for the request that carries it, hashing it (the
  `Idempotency-Key`, `ath`), and comparing two values for equality.
- The facade keeps no notion of a cell, and no configuration names one.

What follows without any code of the facade's own:

- A sign-in placed in a cell that does not hold the user is handed to the user's home cell by a
  redirect inside the browser. The app sees one redirect, with the `state` it expects and a code
  the home cell issued.
- A value that names a cell the deployment does not have is answered by edge with `400`
  `invalid_grant` and no description: `Reauthenticate(GrantRejected)`, as any `invalid_grant`.
- An edge that cannot place a new sign-in answers a server error: `Recoverable(Server)`.

## 9. The ID token

Checked on every platform before the grant is persisted, at login and on a refresh that carries
one (on a refresh the refresh token is stored first, `state-machine.md`):

1. It is a JWS of three segments whose header and payload are JSON; `alg` is not `none`.
2. `iss` equals the configured `issuer`.
3. `aud` contains `clientId`; with several audiences `azp` is present and equals `clientId`.
4. `exp` is in the future and `iat` is present, within `clockSkewTolerance`; `nbf` as
   `oauth-sdk-api.md` section 11.
5. `nonce` equals the value sent, compared in constant time (login only).
6. `auth_time` is present and no older than `max_age` when `max_age` was sent.
7. `at_hash`, when present, matches the access token.
8. On a refresh and on a step-up, `sub` equals the session's (section 6).

A failure is `Configuration(IdTokenRejected(reason))` with the generic facade's consequences.

**The signature is not verified, and that is a stated limit, not an option.** Nothing a native app
can reach serves the deployment's key set: edge serves no JWKS and no discovery
(`server-dependencies.md`). OpenID Connect Core 1.0 section 3.1.3.7, step 6, allows it for this
case: "If the ID Token is received via direct communication between the Client and the Token
Endpoint (which it is in this flow), the TLS server validation MAY be used to validate the issuer
in place of checking the token signature." Here the token reaches the device from edge over TLS,
and edge is the client that received it from the token endpoint over mutual TLS. What the claims
are used for is bounded accordingly: the app's display of who is signed in, `id_token_hint` at
sign-out, and the `sub` comparison of section 6. Authorization is edge's, from the access token.

When the server serves the key set at the issuer's address, the signature check of
`oauth-sdk-api.md` section 11 becomes step 1 here and this paragraph goes. There is no switch in
between: a build either can verify or cannot.

`IdTokenClaims` is the generic facade's type. `claims` is null when unauthenticated. It is an
asynchronous read on every platform: after a cold start the state is `Authenticated` before the
stored ID token has been read (the state is decided without the storage key, so that a cold start
asks for no unlock), and the accessor reads it then. A store that cannot be read raises the store's
own error rather than answering null, and the next call reads again.

## 10. The authenticated client

The shapes and the 401 handling of `oauth-sdk-api.md` section 10, with one scope: the edge's
origin. A request to any other origin passes through untouched, and there is no way to widen the
scope: the access token is bound to the device key and is presented to edge only.

| Platform | Shape |
|---|---|
| Android | `httpClient()`: the configured `OkHttpClient` plus the SDK's interceptor, redirects off; `call(request)` for a suspending single call |
| iOS | `session()`: the `URLSession` wrapper, `data(for:)` |
| Flutter | `httpClient()`: a `package:http` `Client` executed natively |

There is no `accessToken()`. A key-bound token is useless without a proof for the exact request,
so a token handed to app code could only be logged. An app whose transport is not the platform
HTTP client is the open question of section 16.

## 11. Persistence

`state-machine.md`'s persistence summary, with these rows for this facade:

| Item | Storage | Survives process death | Survives logout |
|---|---|---|---|
| Pending authorization request, with the blob and its expiry | Encrypted | yes, until the expiry `/native/start` gave, at most 10 min | no |
| `token_endpoint` and `revocation_endpoint` from the last `/native/start` | Disk, unencrypted | yes | yes |
| Granted scope (the token response's `scope`, else what was requested) | Disk, unencrypted | yes | no |
| Discovery metadata, JWK Set | not kept: the facade has neither | | |

A stored grant without the two endpoints cannot be proved to `auth`: a refresh then fails with
`Reauthenticate(CredentialsInvalidated)` and the grant is wiped, as for a DPoP key that is gone.
The endpoints are written before the refresh token is, so only a damaged store gets there.

## 12. Sign-out

`logout(options)` with `endSession = true`, `revoke = true` by default, in the order of
`state-machine.md`:

1. Revoke the refresh token through `/native/revoke`, proof for the remembered
   `revocation_endpoint`. Best effort; `tokenRevoked` says whether edge answered `200`.
2. Open `{issuer}/logout` in the system browser with `id_token_hint`, `client_id`,
   `post_logout_redirect_uri` when configured, and `state`. Best effort; `sessionEnded` says
   whether the redirect came back with that `state`.
3. Wipe: refresh token, ID token, pending request, rotation slot, granted scope, nonce caches, DPoP
   key. Unconditional.

The end-session address is `issuer` plus `/logout` because that is where the deployment serves it
(the issuer's `/authorize`, `/challenge` and `/logout` are the pages edge fronts) and there is no
metadata to read another from. `endSession = false` skips step 2 for an app that does not want a
browser on sign-out; the user's single sign-on session then survives, and the next `login()` may
complete without asking who they are.

## 13. Platform mapping

| Concept | Kotlin (`versola.sdk`) | Swift (`VersolaSDK`) | Dart (`package:versola`) |
|---|---|---|---|
| Artefact | `io.versola:versola-android`, depending on `oauth-android` at the same version | product `VersolaSDK` of the root package | plugin `versola`, depending on `versola_oauth` for the shared types |
| Entry point | `Versola.create(context, configuration)` | `Versola.create(configuration:presentationAnchor:)` | `Versola.create(configuration)` |
| State | `sessionState: Flow<SessionState>`, `currentSessionState()` | `sessionStates() -> AsyncStream<SessionState>`, `sessionState` | `sessionStates()`, `currentSessionState()` |
| Sign-in | `suspend fun login(options = LoginOptions())` | `func login(_:) async throws` | `Future<void> login([options])` |
| Step-up | `suspend fun stepUp(challenge, options = null)` | `func stepUp(_ challenge: OAuthError, options:) async throws` | `Future<void> stepUp(challenge, [options])` |
| Sign-out | `suspend fun logout(options = LogoutOptions()): LogoutOutcome` | `func logout(_:) async -> LogoutOutcome` | `Future<LogoutOutcome> logout([options])` |
| Refresh | `suspend fun refresh()` | `func refresh() async throws` | `Future<void> refresh()` |
| Claims | `suspend fun claims(): IdTokenClaims?` | `var claims: IdTokenClaims? { get async }` | `Future<IdTokenClaims?> claims()` |
| HTTP | `httpClient()`, `call(request)` | `session()` | `httpClient()` |
| Key tier | `suspend fun keyAttestation(): KeyAttestation?` | `func keyAttestation() async throws -> KeyAttestation?` | `Future<String?> keyAttestation()` |
| Redirect | the manifest-declared redirect activity; an Auth Tab's result | `handleRedirect(_ url: URL) async -> Bool` | native |
| Errors | `VersolaError` | `OAuthError` | `OAuthError` |
| Test seam | `interface VersolaApi` | `protocol VersolaApi: Sendable` | `abstract interface class VersolaApi` |

The Swift module is `VersolaSDK` and the type is `Versola`: a module and a type of one name make
`Versola.LoginOptions` ambiguous between the two. `SessionState`, the error type, `IdTokenClaims`,
`KeyAttestation`, `RetryPolicy`, `UnlockPolicy`, `LogoutOptions` and `LogoutOutcome` are the shared
core's types, not copies. `VersolaConfiguration` and `LoginOptions` are this facade's own.

Flutter: nothing credential-shaped crosses the bridge, the access token included
(`flutter.md`). The plugin is a binding over the two native facades and carries no protocol logic.

`VersolaApi` holds the state, `claims`, `login`, `stepUp`, `logout`, `refresh` and
`keyAttestation`, as `oauth-sdk-api.md` section 17 does for the generic facade.

## 14. Errors this facade adds

In `errors.md`; listed here as the surface:

| Error | Code | When |
|---|---|---|
| `Configuration(EdgeClientUnknown(clientId))` | `configuration.edge_client_unknown` | edge answers `404` to a native call |
| `Recoverable(AccountMismatch)` | `recoverable.account_mismatch` | a step-up came back as another user (section 6) |

`EdgeClientUnknown` is a facade's own detail: Kotlin's `Configuration.Detail.Extension`, and on
Swift and Dart a case that carries a facade's code and text, so that the shared error type gains no
edge vocabulary (ADR 0001). `AccountMismatch` is a case of the shared `Recoverable` cause on every
platform.

## 15. Conformance

Scenarios 21 to 23 and 39 to 44 are this facade's own. Scenarios 01 to 20 that name a step this
facade has (refresh, the edge API call, nonce handling, step-up, logout, process death, the redirect
rules, the retry budget, the unlock window) run through the native endpoints on a `fapi2` tenant.
Scenarios 25 and 27 hold; 26 (the signature) does not until section 9's limit is lifted. Scenarios
07, 09, 10 and 13 describe bearer tokens and are not this facade's (`conformance/README.md`).

A stack with two cells is needed for 39 and 40. No such stack is staged by `conformance/` today.

## 16. Open questions for review

1. **An escape hatch for other transports** (gRPC, WebSocket, Ktor, Alamofire). It needs three
   things, not one: the `Authorization` and `DPoP` values for a method and URL, a way to feed the
   response's `DPoP-Nonce` and `Date` back, and the 401 classification. Proposed as a later
   addition once an integrator asks; until then the platform HTTP client is the only way in.
2. **`issuer` defaulting to `edgeUrl`** (section 3) versus a required parameter.
3. **`Recoverable(AccountMismatch)`** as a shared cause versus a facade extension. It is shared
   here because the generic facade's `stepUp()` has the same gap and should close it the same way.
4. **`Idempotency-Key` on `/native/token`.** A DPoP-bound grant is renewed in place, so the key
   changes nothing today. The facade keeps sending it: it costs nothing and holds if the server
   ever rotates a bound grant.
5. **Later surface**, each its own change: `permissions(resources)` over `/permissions/me`, the
   account surface over edge's `auth` resource (issue #18), app attestation on `/native/start`
   (pull request 142), a typed option for phone-number verification once the server names it.
