# Error taxonomy

Normative for every SDK. Grounded by issue #1.

Four categories, and the category *is* the contract: it tells the app what to do. Integrators
get this wrong far more often than they get a protocol detail wrong, so the type system carries
the answer rather than the documentation.

| Category | Payload | What the app does |
|---|---|---|
| `Recoverable` | cause | Nothing. The SDK already retried; this is surfaced only once retries are exhausted. Show a transient failure, offer a retry. |
| `Reauthenticate` | reason | Send the user through `login()`. The grant is gone and no amount of retrying revives it. |
| `StepUp` | `acrValues`, `maxAge` | Call `stepUp(challenge)`, then resume the original call. |
| `Configuration` | detail | Developer error. Fail loudly in debug builds. Never catch in production — catching it hides a deployment mistake behind a login screen. |

Rules that hold across all four:

- **Exhaustive.** Sealed hierarchy on every platform; adding a server error code is a
  compile-time break, not a silent `default:` branch.
- **One category per code, as seen by the app.** No error is "sometimes recoverable". A code
  that the SDK retries internally before ever handing anything to the app (`use_dpop_nonce`,
  `invalid_dpop_proof`) is not an exception to this — it surfaces exactly one category, once,
  only if the internal retry also fails.
- **No raw strings in the public API.** `error_description` from the server is attached for
  logging, never matched on. The server deliberately returns uniform descriptions across causes
  (`TokenEndpointError.InvalidGrant`, `UserInfoError.InvalidDpopProof`) so it cannot be used as
  an oracle; an SDK that branched on the text would branch on nothing.
- **`Reauthenticate` is a diagnosis, not a command.** The SDK never opens the browser on its
  own. The app decides when.
- **Retries are budgeted.** Every `Recoverable` path has a ceiling, configurable within fixed
  bounds and never unbounded. See [`retry-policy.md`](retry-policy.md).

## Token endpoint — `POST /token`

From `versola.oauth.token.model.ErrorCode` and `TokenEndpointError`.

| `error` | HTTP | Category | Notes |
|---|---|---|---|
| `invalid_request` | 400 | `Configuration` | The SDK built a malformed request. There is no user-facing recovery. |
| `invalid_client` | 401 | `Configuration` | Unknown client, or credentials supplied where none belong. A mobile client is public; the API must make a secret unrepresentable. |
| `invalid_grant` | 400 | `Reauthenticate` | Covers code expiry, PKCE mismatch, redirect mismatch, refresh replay, family revocation and DPoP key mismatch — the body is identical for all of them by design. Must **not** be retried. |
| `unauthorized_client` | 400 | `Configuration` | The client is not registered for this grant type. |
| `unsupported_grant_type` | 400 | `Configuration` | |
| `invalid_scope` | 400 | `Configuration` | The app asked for a scope the client is not registered for. |
| `invalid_target` | 400 | `Configuration` | RFC 8707 `resource` unknown. |
| `invalid_authorization_details` | 400 | `Configuration` | RFC 9396. |
| `invalid_dpop_proof` | 400 | handled internally, then `Reauthenticate` | Never surfaced on the first occurrence, the same treatment as `use_dpop_nonce` below. Retry once with a freshly minted proof: the usual cause is clock skew the SDK can now correct from the `Date` header. A second failure means the key no longer matches the grant — that is the one category the app sees, `Reauthenticate`. |
| `use_dpop_nonce` | 400 | handled internally | Never surfaced on the first occurrence. Retry once with the `DPoP-Nonce` from the response. A second `use_dpop_nonce` for the same request is `Recoverable` with an exhausted-retries cause — never a third attempt. |

`invalid_grant` deserves the emphasis: it is the *only* token-endpoint code that means the user
must sign in again, and it is the one most often mistaken for something to retry. A retry loop
on `invalid_grant` against a rotating-refresh deployment is how clients silently log users out.

Two things about the wire shape, both from `TokenEndpointController`: **`/token` never sends
`WWW-Authenticate`**, for any error — `use_dpop_nonce` is a `400` with the code in the JSON
body and the nonce in `DPoP-Nonce`, and `invalid_client` is a bare `401`. And on a `fapi2`
tenant a public client gets `invalid_client` for every request, because FAPI 2.0 admits
confidential clients only: that is not a registration typo but the signal that the deployment
needs `BackChannel.Edge`, and the `Configuration` message says so.

## Edge's native endpoints — `POST /native/{start,complete,token,revoke}/{clientId}`

Under `BackChannel.Edge` (#40). From `NativeController` and `NativeService`. Every endpoint
demands exactly one `DPoP` header.

| Response | Category | Notes |
|---|---|---|
| 404, empty | `Configuration`, detail `EdgeClientUnknown(clientId)` | Edge fronts no such client: not `native`, not `tls_client_auth` with an edge certificate, not on a tenant assigned to this edge, or edge has no `native` block. The most likely first-run mistake under this back channel. |
| 401, `WWW-Authenticate: DPoP error="use_dpop_nonce"` + `DPoP-Nonce` | handled internally | Edge's own nonce, on `/native/start` only. Cached under edge's origin — the same cache the authenticated client fills. One retry; a second is `Recoverable(NonceLoop)`. |
| 400 `invalid_request` on `/native/start` | `Configuration`, detail `AuthorizationRejected` | Auth's `/par` refusing the pushed request, relayed: unregistered `redirect_uri`, unknown scope, and the rest of the authorization-endpoint table. This is the precise error scenario 17 cannot give under `BackChannel.Auth`. |
| 400 `invalid_request` on `/native/complete` | `Configuration` | A missing `code`, `state`, `iss` or blob. SDK fault. |
| 400 `invalid_grant` from edge on `/native/complete` | `Reauthenticate(GrantRejected)` | The blob is not edge's, is expired, names another client or `state`, `iss` is not the server edge pushed to, or the proof is by a different key than the flow started with. Edge refuses these *before* calling auth, so the code is not spent. |
| 400 `invalid_dpop_proof` from edge | handled internally, then `Reauthenticate` | Edge checked the forwarded proof's signature, `htm`, `htu` and `iat` against auth's endpoint and refused it. One retry with a fresh proof, as at the token endpoint. |
| 400 `unsupported_grant_type` on `/native/token` | `Configuration` | Only `refresh_token` is served there. |
| Anything relayed from auth | as the token endpoint table | Status, body, `DPoP-Nonce` and `WWW-Authenticate` are relayed unchanged — including auth's `400` + JSON `use_dpop_nonce`, whose nonce is cached under the **`htu`'s** origin (auth's mutual-TLS listener), never under edge's. |
| 200 on `/native/revoke` | — | RFC 7009: says the request was taken, not that the token was live. |

## Authorization endpoint — `GET /authorize`

From `versola.oauth.authorize.model.ErrorCode` and `Error`. These arrive on the redirect as
query parameters, or inside a JARM `response` JWT.

| `error` | Category | Notes |
|---|---|---|
| `invalid_request` | `Configuration` | Malformed or missing parameter, bad `code_challenge`, invalid `state` length, conflicting hints, invalid `dpop_jkt`. All SDK or integration faults. |
| `invalid_client` | `Configuration` | |
| `unsupported_response_type` | `Configuration` | |
| `unauthorized_client` | `Configuration` | |
| `invalid_scope` | `Configuration` | Unregistered scope. |
| `invalid_target` | `Configuration` | |
| `invalid_authorization_details` | `Configuration` | |
| `invalid_request_object` | `Configuration` | RFC 9101. Returned directly rather than redirected. |
| `login_required` | `Reauthenticate` | Only reachable with `prompt=none`. |
| `consent_required` | `Reauthenticate` | Only reachable with `prompt=none`. |
| `interaction_required` | `Reauthenticate` | Only reachable with `prompt=none`. |
| `access_denied` | `Reauthenticate` | The resource owner could not be resolved, or the user declined. The SDK must not re-open the browser automatically. |
| `unmet_authentication_requirements` | `Configuration` | The requested ACR cannot be satisfied by this deployment. Not a step-up: retrying with the same `acr_values` fails identically. |

Errors returned directly rather than by redirect — `BadRequest` (unregistered `redirect_uri`,
missing or duplicate `client_id`) and `invalid_request_object` — answer with an error page in
the browser itself, not a response the app's process ever sees. **This is not `Configuration`
in practice: the SDK has no visibility into that page.** Custom Tabs and
`ASWebAuthenticationSession` expose neither the page's status nor its body, so an unregistered
redirect URI is indistinguishable from the user closing the tab — see scenario 17. An
unregistered redirect URI is still the single most common first-run mistake; the SDK cannot
fix the integrator's afternoon here, only PAR (RFC 9126) can, by moving the check to a plain
HTTPS response the app makes itself — which is exactly what `BackChannel.Edge` gets from
`/native/start`, see the native table below.

## UserInfo — `GET /userinfo`

From `versola.oauth.userinfo.model.UserInfoError`.

| Error | Category | Notes |
|---|---|---|
| `InvalidToken` | `Recoverable` → refresh → retry, else `Reauthenticate` | |
| `InsufficientScope` | `Configuration` | The token was not issued with the scopes this call needs. |
| `Unauthorized` | `Reauthenticate` | |
| `InvalidDpopProof` | handled internally, then `Reauthenticate` | Same one-retry rule as the token endpoint; nothing reaches the app until the retry also fails. Also covers the RFC 9449 §7.2 downgrade refusal: a `Bearer`-scheme request carrying a key-bound token. |
| `UseDpopNonce` | handled internally | Retry once against the **userinfo origin's** nonce cache. |

## Edge — `versola.io`

From `EdgeService`'s failure outcomes. Note the `WWW-Authenticate` scheme differs by cause;
**parse the `error` value, not the scheme**.

| Response | Challenge | Category |
|---|---|---|
| 401, `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="…", max_age="…"` | RFC 9470 | `StepUp(acrValues, maxAge)` |
| 401, `WWW-Authenticate: DPoP error="invalid_dpop_proof"` | RFC 9449 §7 | handled internally, then `Reauthenticate` |
| 401, `WWW-Authenticate: DPoP error="use_dpop_nonce"` + `DPoP-Nonce` | RFC 9449 §9 | handled internally, edge's nonce cache only |
| 401, bare | | refresh once, then one replay; a second 401 is `Reauthenticate`, reason `SessionRejected` |
| 403, 404, 429, 5xx | | not converted — returned to the caller as the response it is |

`insufficient_user_authentication` arriving under the `Bearer` scheme while the client is using
DPoP is not a bug in edge and must not be treated as a downgrade attack. Issue #9's original
text said `DPoP` here; the code says `Bearer`, and the code is ground truth.

### Why only 401 is converted

Edge is a reverse proxy. Its own rejections — `Outcome.Forbidden`, `Outcome.NotFound`,
`Outcome.InternalServerError` — are built as bare `Response.status(...)` with no body and no
marker header, and the response from a resource behind it is forwarded essentially verbatim.
At 403, 404, 429 and 5xx the two are therefore **indistinguishable on the wire**: nothing tells
a client whether the permission check in `checkPermissions` refused the call or whether the
application refused it for reasons of its own.

So the SDK does not guess. It converts a response into a `VersolaError` only where the response
is *about the credential the SDK attached* — which is 401, in the four forms above, three of
them carrying a `WWW-Authenticate` that no application would emit. Everything else is the
application's answer to the application's call, and is handed back as a response.

This is a narrowing of what earlier drafts of this table said, and it costs something: an app
that wants "403 means the session lacks the permission" has to decide that itself, from a path
it registered and therefore understands. The alternative costs more — an SDK that reports
`Configuration` because a REST endpoint legitimately answered 404 sends an integrator hunting a
deployment bug that does not exist.

The residual ambiguity at 401 is accepted rather than solved: a bare 401 from an application
behind edge is read as an expiry and spends one refresh before the call is replayed. It is
bounded at exactly one refresh and one replay per operation, which is the same bound a genuine
expiry gets, and the alternative is refusing to refresh on the one status that usually means
the token is stale.

The `Reauthenticate` outcome edge produces for browser sessions — 401 with a `Location` header
and a cookie-clearing `Set-Cookie` — belongs to the cookie-session path and is not reachable by
a mobile client. An SDK that follows that `Location` is wrong.

## Client-side conditions

Not every error comes from a server.

| Condition | Category | Notes |
|---|---|---|
| `state` mismatch on redirect | `Configuration` | Hard failure. **No token request is made.** Either a bug or an injection attempt; both are unsafe to continue from. |
| `iss` mismatch on redirect (RFC 9207) | `Configuration` | Same treatment. |
| Missing `code` and missing `error` on redirect | `Configuration` | |
| User cancelled the browser | `Recoverable`, cause `UserCancelled` | Pending request wiped. Never retried automatically. |
| The browser could not verify the redirect's `https` host as this app's App Link (Auth Tab `RESULT_VERIFICATION_FAILED` / `TIMED_OUT`) | `Configuration`, detail `InvalidConfiguration` | Android only. Pending request wiped; a deployment mistake (`assetlinks.json`), not something a retry fixes. |
| System tore down the browser session | `Recoverable`, cause `SystemCancelled` | Pending request kept; may be resumed. See the cancel table in [`state-machine.md`](state-machine.md). Exception: an Auth Tab result code the SDK does not know wipes it, since no redirect can follow. |
| Network failure, timeout, DNS | `Recoverable`, cause `Network` | Surfaced only after the SDK's retry policy is exhausted, or at once on an operation that is not repeated (`retry-policy.md`, operations). |
| 408, 429 or 5xx from a request the SDK originates | `Recoverable`, cause `Server(status, retryAfter, attempts, elapsed)` | After the budget is exhausted, or at once when `Retry-After` exceeds what is left of it, or on a 5xx that cannot be transient (501, 505). `retryAfter` is the parsed header on 429 and 503, absent otherwise. The session is left where it was. `retry-policy.md`. |
| Nonce demanded on a retry that already carried one | `Recoverable`, cause `NonceLoop` | **Terminating.** A server that always demands a nonce must produce an error, never an unbounded retry. |
| Stored bytes that can never be opened again: the Keystore reports the key permanently invalidated (biometric or lock-screen change), the key entry cannot be recovered, or the ciphertext fails authentication (Android: `KeyPermanentlyInvalidatedException`, `UnrecoverableKeyException`, `AEADBadTagException`) | `Reauthenticate`, reason `CredentialsInvalidated` | Indistinguishable from tampering; treated as sign-out. These are the only verdicts that sign the user out: the rest of this group fails the operation and leaves the grant alone. |
| A storage-key operation fails and the failure is no verdict on the key (Android: a busy or restarting Keystore service, a StrongBox or TEE fault, any exception not listed in the row above) | `Recoverable`, cause `Network` (detail names the failure class) | The grant is intact: nothing is wiped and the DPoP key is kept. The session stays `Authenticated`, and the retry budget may repeat the operation. `UnlockRequired` is deliberately not used, since it moves the session to `Locked` and asks the app for an authentication prompt that cannot help. `Network` is the closest cause that exists today; a dedicated cause is an open decision (it is a public enum case on every platform). A caller cancelled during the operation is a cancellation, never one of these. |
| Storage key's authentication window has elapsed | `Recoverable`, cause `UnlockRequired` | `UnlockPolicy.OnAppUnlock` only. The app presents the prompt and retries; the grant is intact. |
| Hardware key unavailable while `requireHardware = true` | `Configuration` | The app asked for a guarantee this device cannot provide. |
| `BackChannel.Edge` without `edgeBaseUrl`, with `TokenBinding.Bearer`, or with a non-`https` redirect URI | `Configuration` | Refused at `configure()`. Edge's native endpoints are edge's, accept no bearer presentation, and front clients registered with `https` redirect URIs only. |
| A grant started through one back channel redeemed through the other | `Configuration` | Wiring. Refused before the code is spent. |
| Discovery document missing a required field | `Configuration` | A missing `dpop_signing_alg_values_supported` is **not** this: it means bearer mode, logged, not failed. |
| Pending authorization request older than 10 minutes | `Recoverable`, cause `Expired` | Discarded on restore. |

## Generic facade additions

The generic facade (`oauth-sdk-api.md`) adds conditions the Versola facade cannot meet, each in
exactly one category. The Versola facade may raise the ID-token and UserInfo rows too once it
validates ID tokens (architecture review F5).

| Condition | Category | Detail / reason | Notes |
|---|---|---|---|
| ID token fails validation (signature, algorithm, `iss`, `aud`/`azp`, `exp`, `iat`, `nonce`, `auth_time`, `at_hash`, malformed) | `Configuration` | `IdTokenRejected(reason)` with a closed reason enum | Nothing is persisted; the state settles on its pre-`login()` value. Every cause is a deployment mistake or an attack; the user trying again fixes neither. Scenarios 25 to 27. |
| UserInfo `sub` differs from the ID token's, or a signed UserInfo response does not verify | `Configuration` | `UserInfoRejected` | OIDC Core 5.3.2. |
| A capability the configuration requires is not advertised (`TokenBinding.Dpop(required)`, `pushedAuthorization = Required`, `require_pushed_authorization_requests` with `Never`, `userInfo()` without an endpoint, `code_challenge_methods_supported` present without `S256`) | `Configuration` | `ProviderUnsupported(capability)` | Raised at the first operation that needs the capability, never by a silent downgrade. An absent `code_challenge_methods_supported` is unknown, not a refusal. |
| Access token expired and the provider issued no refresh token | `Reauthenticate` | `SessionExpired` | No token request is made. Scenario 31. |
| `login()` called while `Authorizing` | `Configuration` | `InvalidConfiguration` | The app observes `sessionState` before asking. |
| A resource server answers 401 with `error="insufficient_user_authentication"` (RFC 9470) | `StepUp(acrValues, maxAge)` | | Same as edge's row; any resource server in `protectedOrigins`. |
| A resource server answers 401 otherwise | refresh once, replay once, then `Reauthenticate`, reason `SessionRejected` | | As edge's bare 401. |

## Cross-platform naming

Semantics are identical; spelling follows each language.

| Concept | Kotlin | Swift | Dart |
|---|---|---|---|
| Base | `sealed class OAuthError` (`VersolaError` is a type alias in the Versola facade, ADR 0001) | `enum OAuthError: Error` | `sealed class OAuthError` |
| Recoverable | `VersolaError.Recoverable(cause)` | `.recoverable(Cause)` | `Recoverable(cause)` |
| Reauthenticate | `VersolaError.Reauthenticate(reason)` | `.reauthenticate(Reason)` | `Reauthenticate(reason)` |
| Step-up | `VersolaError.StepUp(acrValues, maxAge)` | `.stepUp(acrValues:maxAge:)` | `StepUp(acrValues, maxAge)` |
| Configuration | `VersolaError.Configuration(detail)` | `.configuration(Detail)` | `Configuration(detail)` |

An error crossing the Flutter bridge must keep its category. A `StepUp` arriving in Dart as a
generic `PlatformException` is a defect in the bridge, not an acceptable lossy conversion.
