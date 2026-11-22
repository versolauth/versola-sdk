# Server dependencies

What the spec assumes of `versolauth/versola`, and which of those assumptions are still open
work there. Grounded by issue #1, whose ground-truth table this document qualifies: #1 records
what the server *does*, this records what is *not finished* and what the SDK must therefore not
rely on.

Checked against `versolauth/versola` at `0a2b72d34` (2026-11-22), the working tree rather than
issue text. That commit is the head of `feat/central-topology-557`, the branch of draft pull
request 1023 (cells, the issuer served by edge, partner edges), which is not merged: the sections
"Cells and the issuer's address", "Edge's rate limits" and "Open" describe that branch, and are
checked again when it lands. Rows cite the file that decides the behaviour.

## Settled — DPoP is the default

Edge-side DPoP enforcement shipped with [versola#294](https://github.com/versolauth/versola/issues/294),
now closed. `edge/.../dpop/DpopVerifier.scala` compares the proof's thumbprint against the
access token's `cnf.jkt`, `auth.scala` refuses a `Bearer` presentation of a bound token,
`DpopReplayGuard` rejects `jti` replays, and edge issues its own nonces keyed by
`EdgeConfig.nonceSalt`.

So **the SDK ships DPoP on by default**, and bearer is the fallback rather than the norm:

- `TokenBinding.Dpop` is the default. Bearer is reached only when discovery does not advertise
  `dpop_signing_alg_values_supported` — conformance scenario 07, which describes an older or
  differently configured deployment, not the Versola default. Auth advertises `ES256` and
  `PS256` even when the stored metadata omits the field (`ServedMetadata.scala`,
  `Dpop.Algorithm.Default`).
- Under DPoP the server renews sender-constrained refresh tokens in place (`BoundRenewal`,
  `OAuthTokenService.scala`): the response **echoes the same `refresh_token` value** rather
  than omitting it, and the SDK stores it again unchanged. There is no rotation and no replay
  window. The rotation machinery in #8 and #14 — pending slot, idempotency key,
  family-revocation handling — is a **safety net for bearer mode**, not the load-bearing path.
- A mobile client must be registered with `dpopBoundAccessTokens = true`. Note the coupled
  constraint in `InvalidRegistrationConfiguration`: enabling it requires
  `accessTokenTtl >= 3600s`, so a client registered with a shorter access-token lifetime is
  rejected at registration.
- Both nonce spaces are real, which is why a shared nonce cache loops. Scenario 04. Auth
  demands a nonce only when the client's tenant has `requireDpopNonce = true` (default
  `false`); a registered edge demands one by default (`EdgeRecord.requireDpopNonce`).
- **The two nonce challenges have different shapes.** Auth's token endpoint answers
  `400` with `{"error":"use_dpop_nonce"}` in the body and the nonce in `DPoP-Nonce` — no
  `WWW-Authenticate` on `/token` for any error. Edge (its proxy, `/permissions/me` and
  `/native/start`) and `/userinfo` answer `401` with `WWW-Authenticate: DPoP error="use_dpop_nonce"`
  and `DPoP-Nonce`. Both reach the SDK; both are read on the `error` value.

## Settled — FAPI 2.0 tenants authorize through edge

[versola#353](https://github.com/versolauth/versola/issues/353) and
[versola#420](https://github.com/versolauth/versola/issues/420) closed with versola PR #428
(2026-10-01). Every tenant now carries a security profile, `standard` or `fapi2`, fixed at
creation — and **`fapi2` is the default for a new tenant, the bootstrap `default` tenant
included** (`TenantService.scala`, `ChallengeSettingsRecord.scala`).

On a `fapi2` tenant a public client (`authMethod = none`) is refused with `invalid_client` at
`/token`, `/revoke`, `/par` and `/introspect` (`ClientAuthentication.scala`). FAPI 2.0 §5.3.2.1
admits confidential clients only, and a mobile app cannot keep a credential. So the direct
public-client flow of #5 and #8 works on `standard` tenants only, and the SDK's
edge's native endpoints (#40), the `Versola` facade's only back channel (`versola-sdk-api.md`), are
what a `fapi2` tenant needs:

| Leg | Endpoint | Proof `htu` | Notes |
|---|---|---|---|
| Start | `POST {edge}/native/start/{clientId}` | edge's own URL | Edge generates PKCE, `state` and pushes to `/par` with `dpop_jkt` from the proof. Answers `{client_id, request_uri, expires_in, authorization_endpoint, state, blob, token_endpoint, revocation_endpoint}`. Edge's nonce policy applies here. The proof is not forwarded and is refused if seen twice. |
| Browser | `{authorization_endpoint}?client_id&request_uri` | — | The `authorization_endpoint` of the start answer: edge's `versola-url` plus `/authorize`, the issuer, which an edge serves when there are cells. Redirect carries `code`, `state`, `iss`. |
| Complete | `POST {edge}/native/complete/{clientId}` | `token_endpoint` from start (auth's mutual-TLS listener) | Body `code, state, iss, blob`. Edge opens the blob, checks client, `state`, `iss`, expiry and that the proof's `jkt` equals the blob's, then calls `/token` over mTLS forwarding the `DPoP` and `Idempotency-Key` headers unchanged and relays auth's answer. |
| Refresh | `POST {edge}/native/token/{clientId}` | `token_endpoint` | Body `grant_type=refresh_token, refresh_token`. |
| Revoke | `POST {edge}/native/revoke/{clientId}` | `revocation_endpoint` | Body `token, token_type_hint`. Auth's `/revoke` reads no proof; edge checks the one it forwards. |

Registration constraints for such a client (`InvalidRegistrationConfiguration.scala`):
`applicationType = native`, `authMethod = tls_client_auth` with an edge-held certificate,
`requirePushedAuthorizationRequests = true`, `dpopBoundAccessTokens = true`,
`certificateBoundAccessTokens = false`, `https` redirect URIs only, in every tenant and not only
under `fapi2` — **no private-use schemes and no loopback**. The certificate is edge's, enrolled by
edge from central; the device is never asked for one, and EST enrolment (versola#804) is for web
and service clients and refuses a native one (`ClientEstService.scala`). A client that does not meet
these is not fronted, and edge answers `404` to every native endpoint for it; the SDK names
that `Configuration(EdgeClientUnknown)`.

The sealed blob replaces the PKCE verifier on the device: the SDK persists `state` and the
blob before the browser opens and never sees the verifier. Edge keeps no state; auth remains
the only token store.

### What `/native/start` forwards

`NativeService.PassThroughParameters`: `scope`, `nonce`, `acr_values`, `prompt`, `login_hint`,
`ui_locales`, `max_age`, `claims`, `resource` (the only one that may repeat) and
`authorization_details`, plus `redirect_uri`, which is optional when the client registered exactly
one. A repeated parameter other than `resource` is `invalid_request`. **Any other parameter is
dropped without an error**, `id_token_hint` included. `versola-sdk-api.md` section 5 is that list
as typed options, and section 6 is what the missing `id_token_hint` costs a step-up.

`/native/token` takes `refresh_token`, an optional `grant_type` (only `refresh_token`), `scope` and
`resource`. A DPoP-bound grant, which every native one is, is **renewed in place and not rotated**
(`OAuthTokenService.scala`), so the `Idempotency-Key` edge forwards changes nothing for it.

Edge relays from auth the status, the body and five headers: `Content-Type`, `Cache-Control`,
`Pragma`, `DPoP-Nonce` and `WWW-Authenticate` (`NativeAuthClient.RelayedHeaders`). Nothing else,
`Retry-After` included.

## Settled — cells and the issuer's address

A deployment may run several `auth` instances, each a cell with its own database
(versola#547). What the SDK has to know of it is small, and `versola-sdk-api.md` section 8 is the
rule that follows.

| Fact | Where | Effect on the SDK |
|---|---|---|
| A cell's values name it: `v1.<cell>.<value>` for an authorization code, a refresh token, the reference inside a PAR `request_uri` and a session id; a `cell` JOSE header on an access token. An `auth` with no `cell-id` issues unprefixed values | `RoutingKey.scala`, `AuthPropertyGenerator.scala` | Every value is opaque: stored and sent as received, never parsed. The same build works with and without cells. |
| Edge routes each native call by the value it carries (`/par` is placed in an open cell; `/token` by the code or the refresh token; `/revoke` by the token) | `NativeAuthClient.scala`, `CellTable.scala` | Nothing. The device calls one edge. |
| A value naming a cell the deployment does not have is answered by edge itself: `400 {"error":"invalid_grant"}`, no description | `NativeAuthClient.scala` | `Reauthenticate(GrantRejected)` (`errors.md`). |
| With cells the issuer's address is an edge's. Edge serves `/authorize`, `/challenge/**` and `/logout` there and forwards them to the cell; it serves **no** `/token`, `/par`, `/userinfo`, `/revoke`, `/introspect`, discovery or JWKS | `IssuerFront.scala` | The `Versola` facade reads no discovery and calls nothing at the issuer; only the browser goes there. An app that needs those endpoints needs an `auth`'s own address and the generic facade. |
| A sign-in placed in a cell that does not hold the user is handed to the home cell by a redirect to `/challenge/handoff` inside the browser, carrying the sealed request (`state`, PKCE challenge, `dpop_jkt`, `nonce` among it) | `CellHandoff.scala` | Nothing: the redirect the app receives has the `state` it expects and the home cell's code. Not handed over: a login-and-password sign-in and a passkey without a typed address. |
| A partner's edge keeps one issuer address, syncs no cells and serves no issuer pages (`404`) | `ConfigurationSource.scala`, `IssuerFront.scala` | A partner app's `issuer` is the operator's, never its edge's address. |

## Settled — edge's rate limits

[versola#310](https://github.com/versolauth/versola/issues/310) is closed. Edge limits by caller
address before it does anything else, and sheds load when it is overloaded.

| Fact | Where | Effect on the SDK |
|---|---|---|
| A refusal is `429` with no body, `Retry-After` in whole seconds, and `RateLimit-Policy` and `RateLimit` | `RateLimiter.scala`, `AddressLimit.scala` | `Retry-After` is honoured (`retry-policy.md`); the `RateLimit*` headers are not read. An HTTP-date is never sent, and is still parsed. |
| `/native/start` and `/native/complete` are counted on every call; `/native/token` and `/native/revoke` only for a failed authentication | `AddressLimit.scala` | A sign-in is what a limit meets first. `login()` checks edge's cooldown before the browser opens. |
| Overload is `503` with `Retry-After`; `/native/start` is shed before the calls that continue a flow | `InboundAdmission.scala`, `EdgeAdmission.scala` | As a 429. |
| Auth's own client-authentication throttle guards its main listener, not the mutual-TLS one edge calls, and edge would not relay its `Retry-After` | `PostgresOAuthApp.scala`, `NativeAuthClient.scala` | The only server that asks the `Versola` facade for quiet is edge. |
| Policies are configured in central and default to shadow mode | versola documentation, `operations/rate-limits` | A deployment may answer no 429 at all; the SDK's own ceiling does not depend on one. |

## Settled — proof-key policy

[versola#302](https://github.com/versolauth/versola/issues/302) closed on 2026-09-26. `Dpop.verify`
refuses RSA keys below 2048 bits (`Dpop.KeyPolicy.MinRsaKeySize`), and a client may raise the
floor with `dpopMinRsaKeySize`, applied at `/token`. Nothing changes for the SDK, which mints
ES256 on P-256; documentation may now say the server enforces a key-strength floor.

## Settled — what else moved since #1 was written

| Change | Where | Effect on the SDK |
|---|---|---|
| `iss` is always on the redirect, success and error alike, and discovery advertises `authorization_response_iss_parameter_supported: true` | `AuthorizeRedirect.scala` | A missing `iss` is a hard failure against Versola; required in any case for `/native/complete`. |
| Refresh-token expiry is fixed at the code exchange and never extended (default 180 days) | `OAuthTokenService.scala`, 2026-10-11 | A long-lived session ends in `invalid_grant` on schedule, not on inactivity. `Reauthenticate(GrantRejected)`, as before. |
| `nonce` is required when `response_type` includes `id_token` | `AuthorizeRequestParser.scala` | The SDK requests `code` only and always sends a nonce; no change. |
| `acr_values` outside the tenant's vocabulary are dropped rather than refused | `AuthorizeRequestParser.scala` | A step-up asking for an unknown ACR does not fail; it is answered with whatever ACR the login reached, and edge challenges again. Scenario 14's `unmet_authentication_requirements` row describes a deployment that does refuse. |
| Edge never emits `invalid_token`: a missing, expired or revoked header token is a bare `401` | `EdgeService.scala` | The bare-401 path in `errors.md` — one refresh, one replay — is the normal expiry path, not a fallback. |
| `/logout` renders a signed-out page carrying `post_logout_redirect_uri` and `state`; the redirect list is **tenant-level** (`postLogoutRedirectUris`); an **expired `id_token_hint` is silently ignored** | `LogoutController.scala`, `LogoutService.scala` | `logout()` sends the last `id_token` it holds, which a refresh renews (refresh responses carry `id_token` when `openid` was granted). A session that has not refreshed within one access-token lifetime ends locally but may survive at auth. |
| A refresh response carries a fresh `id_token` when the grant has `openid` | `TokenEndpointController.generateIdToken` | The stored ID token is replaced on every refresh, so `id_token_hint` is fresh when the app refreshes regularly. |
| Discovery says `request_uri_parameter_supported: false` while `/par` and `request_uri` work | `ServedMetadata.scala` | The SDK ignores the field. A generic OIDC library would not; reported upstream. |
| `/users/*` is an internal admin API; self-service is `AccountSettingsController` reached through edge as resource `auth` (`/resources/auth/settings...`) | `authorizeInternal.scala`, `AccountSettingsController.scala` | #18's account surface targets edge's `auth` resource, not `/users`. |

## Open

What the server does not do, or does in a way the SDK has to work around. None of these has a
server issue yet; a row gains its link when one is filed.

| Gap | Code state | What the SDK does meanwhile |
|---|---|---|
| **A sign-in has to finish within the `request_uri`'s lifetime.** | The blob's expiry is `min(par.expiresIn, native.blob-ttl)` (`NativeService.scala`), and auth's default `requestUriTtl` is 60 s (`CoreConfig.scala`). RFC 9126 section 2.2 expects a short-lived `request_uri`, which is right for the reference and wrong for the blob: the reference is spent when the browser opens `/authorize`, the blob is needed when the user has finished. | The pending request expires at `expires_in` and the wait ends with `Recoverable(PendingRequestExpired)`; no `/native/complete` is sent for a late redirect. With the default, a sign-in that takes longer than a minute (a code by SMS) fails. Only the server can fix it. Scenario 42. |
| **No key set a native app can reach.** | Edge serves no JWKS and no discovery (`IssuerFront.scala`); the device cannot call an `auth`. | The ID token's claims are checked and its signature is not (`versola-sdk-api.md` section 9, OpenID Connect Core 3.1.3.7 step 6). Scenario 26 does not hold for the `Versola` facade. |
| **Partner native clients.** | A partner's native client cannot be registered: the native rule wants an `edgeClientCertificate`, which a partner's client does not have (`OAuthClientServiceSpec.scala`, "a partner's native (device) client is refused"). `partner-api.yaml` lists `native` among a partner's client kinds all the same. A partner edge also reaches one `auth` address, not a cell by value. | The facade is specified for a partner app (`versola-sdk-api.md` section 1) and not built or tested for one. |
| **`/native/start` drops what it does not forward.** | `PassThroughParameters`, above. | No free-form parameter map (ADR 0002, decision 4). Phone-number verification (versola#887) has no parameter in the code yet, and would be dropped by edge when it gets one. |
| **No `id_token_hint` on a step-up.** | Not forwarded by `/native/start`; `/authorize` takes the user from the browser's session cookie. | The SDK compares `sub` and refuses another user (`state-machine.md`, scenario 43). |
| **Proof `htu` with several cells.** | Edge hands out one `token_endpoint` (`native.auth-mutual-tls-external-url`) and sends the call to the cell's own listener; auth checks `htu` against its own `mutual-tls.external-url` (`CoreConfig.endpointUri`). The e2e cell stand gives its second cell another external URL and runs no native flow. | Nothing the SDK can do: it signs for the URL edge named. Not verified against a stack; if every cell must share one external URL, that is a deployment rule the server documents. Scenario 39 is what would show it. |
| **Moving auth's mutual-TLS address signs every native session out.** | The `htu` a refresh signs for is learned at `/native/start` only. | A refresh for the old address is `invalid_dpop_proof`, retried once, then `Reauthenticate(CredentialsInvalidated)`. The server could answer the current endpoints with a refusal, or accept the old address for a time. |
| **`/native/start` with no open cell answers 500**, and an unknown cell on `/native/revoke` answers 400 where RFC 7009 answers 200. | `NativeAuthClient.scala` | `Recoverable(Server(500))`; `tokenRevoked = false`. A 503 with `Retry-After` would let the SDK wait the right time. |
| **The cell handover drops `max_age`.** | Not among the sealed parameters (`CellHandoff.scala`). | Nothing: the home cell has no session for a user it is handed, so the sign-in is fresh anyway. The ID token's `auth_time` is still checked. |
| **UserInfo for a native app.** | No native endpoint; a partner edge cannot ask `/userinfo` for a DPoP-bound token at all. | The facade has no `userInfo()`. |
| **App attestation** (versola#423) and **phone-number verification** (versola#887) | Neither is on this branch; attestation is on unmerged branches. | Pull request 142 of this repository carries the SDK half of attestation and is specified there, not here. |
| Edge's OpenAPI and documentation against its code | `edge.yaml` lists a `401` nonce challenge of edge's own for complete, token and revoke, which edge never issues there, and no 429 or 503 on `/native/*`; the documentation calls a native refresh a rotation and shows auth's nonce challenge as a 401. | Read the code's shapes (done): auth's `400` + JSON `use_dpop_nonce`, edge's `401` + `WWW-Authenticate`. |

## Consequences that shaped the spec

**The retry budget is the SDK's own.** Not because edge will never have a limiter — it will —
but because a shipped app's retry loop keeps running on every installed device until the next
release reaches them. A server-side limiter bounds the damage to the server; only a client-side
ceiling bounds what the client emits. Both are wanted; they are not substitutes.

**Bearer mode still has to be correct**, even though it is no longer the default. A deployment
that has not turned DPoP on gets the rotation-race handling, and scenario 07 keeps that path
tested rather than notional.

**Each facade has one back channel** (ADR 0002). The generic facade talks to the provider's own
endpoints and is what works against a non-Versola provider, or against one `auth` on a `standard`
tenant. The `Versola` facade talks to edge's native endpoints and is what a deployment with cells
or a `fapi2` tenant needs. A step that both have (refresh, revocation, the redirect rules, the
retry budget) behaves the same in both, and the scenarios that hold for both say so in `facade`.

## Keeping this current

When a listed issue closes, move the assumption into the settled section above, or into #1's
ground-truth table if it is load-bearing enough to belong there. When the harness (#15) asserts
one of these behaviours against a staged stack, note the scenario in the row — an assumption a
test holds down does not need tracking here.
