# Server dependencies

What the spec assumes of `versolauth/versola`, and which of those assumptions are still open
work there. Grounded by issue #1, whose ground-truth table this document qualifies: #1 records
what the server *does*, this records what is *not finished* and what the SDK must therefore not
rely on.

Checked against `versolauth/versola` at `d6203f93` (2026-10-11), the working tree rather than
issue text. Rows cite the file that decides the behaviour.

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
`BackChannel.Edge` (#40) is what a `fapi2` tenant needs:

| Leg | Endpoint | Proof `htu` | Notes |
|---|---|---|---|
| Start | `POST {edge}/native/start/{clientId}` | edge's own URL | Edge generates PKCE, `state` and pushes to `/par` with `dpop_jkt` from the proof. Answers `{client_id, request_uri, expires_in, authorization_endpoint, state, blob, token_endpoint, revocation_endpoint}`. Edge's nonce policy applies here. |
| Browser | `{authorization_endpoint}?client_id&request_uri` | — | Goes to auth directly. Redirect carries `code`, `state`, `iss`. |
| Complete | `POST {edge}/native/complete/{clientId}` | `token_endpoint` from start (auth's mutual-TLS listener) | Body `code, state, iss, blob`. Edge opens the blob, checks client, `state`, `iss`, expiry and that the proof's `jkt` equals the blob's, then calls `/token` over mTLS forwarding the `DPoP` and `Idempotency-Key` headers unchanged and relays auth's answer. |
| Refresh | `POST {edge}/native/token/{clientId}` | `token_endpoint` | Body `grant_type=refresh_token, refresh_token`. |
| Revoke | `POST {edge}/native/revoke/{clientId}` | `revocation_endpoint` | Body `token, token_type_hint`. Auth's `/revoke` reads no proof; edge checks the one it forwards. |

Registration constraints for such a client (`InvalidRegistrationConfiguration.scala`):
`applicationType = native`, `authMethod = tls_client_auth` with an edge-held certificate,
`requirePushedAuthorizationRequests = true`, `dpopBoundAccessTokens = true`, `https`
redirect URIs only — **no private-use schemes and no loopback**. A client that does not meet
these is not fronted, and edge answers `404` to every native endpoint for it; the SDK names
that `Configuration(EdgeClientUnknown)`.

The sealed blob replaces the PKCE verifier on the device: the SDK persists `state` and the
blob before the browser opens and never sees the verifier. Edge keeps no state; auth remains
the only token store.

### App attestation on `/native/start` ([versola#423](https://github.com/versolauth/versola/issues/423))

`POST {edge}/native/start/{clientId}` authenticates as the client for any caller, so a script can
run its own login through edge. A client can therefore be set, per client in Central, to `off`,
`report` or `enforce` that the app proves it is the genuine build on a genuine device. A client with
no policy is not asked: nothing below is sent to it, and nothing changes for it.

The app sends the evidence as extra form fields of `/native/start`; edge reads them and never
passes them on to auth. Under `enforce` a request without a verifiable attestation of an accepted
build is refused with `400 invalid_client_attestation` before anything is pushed to `/par`; under
`report` edge verifies, counts and answers as if it had not. The attestation is tied to the DPoP
key the request is signed with, which is the key every token of the flow is bound to.

| Platform | Evidence | What binds it |
|---|---|---|
| Android | `attestation_platform=android` and `attestation_chain`, once per certificate (leaf first, each base64 DER), from Android Key Attestation of **the DPoP key itself** | The leaf's public key is the proof's key, so the chain is useless without the DPoP key. The key is generated with the attestation challenge `SHA-256("versola-attest-v1\n" + clientId)`, which names the client the chain was made for. |
| iOS | `attestation_platform=ios`, `attestation_key_id` (the App Attest key id, base64) and **either** `attestation_object` (the first request of a key) **or** `attestation_assertion` (every later one) | App Attest signs only what it is handed, so the DPoP key cannot be the attested key. The app hands App Attest `clientDataHash = SHA-256("versola-attest-v1\n" + clientId + "\n" + jkt + "\n" + jti)`, `jkt` and `jti` being the thumbprint of the DPoP key and the `jti` of the proof sent on the same request. An assertion is good for exactly one proof, and its counter must move forward. |

Test vectors, for an implementation to check its own hashing against: with `clientId` `mobile-app`
the Android challenge is `da1a942191246aaada23ebad9694ba705d6babcd5bfec362779077b377440e15`, and
with `jkt` `JKT` and `jti` `JTI` the iOS client data hash is
`59241b9875b6c77d3d24ca23f08be296ecd13f10e52a5ffa3e7be2e6f07b6860` (both hex).

Rules for the app, whichever platform:

- Attestation is **evidence about a key, never a permission**. The SDK sends what it has and lets
  edge decide; it does not skip a request, retry with other evidence or loosen anything on its own
  when edge refuses. A device that cannot produce evidence (no hardware attestation, App Attest
  unsupported) sends none, and the client's policy decides whether that is acceptable.
- An Android key is attested **when it is generated**, so a key that was generated before the SDK
  asked for attestation has no chain. Such a key is replaced by an attested one **only at the start of
  a login (`/native/start`) and only while no grant is held**. Never while signing a later request: a
  login is in flight between `/native/start` and `/native/complete`, possibly across the death of the
  process, and its blob is bound to the key's thumbprint. With a grant held the key is kept (a grant is
  bound to the thumbprint too) and no evidence is sent, and the next login after a logout gets an
  attested key. A device that cannot attest a key generates it without, and is not asked again in the
  same process.
- An iOS attestation object is made for one request's proof and App Attest attests a key once, so it
  is never re-sent: after a refusal the app attests a new key; after a request that failed once edge
  had accepted it, the key is known and the app asserts with it next. An assertion for a key edge has
  not been shown is refused with the description `this key has not been attested: send the attestation
  object`, which is what tells the app to attest it.

**Platform status.** The Android `Versola` facade sends the Android evidence under `BackChannel.Edge`.
There is no iOS counterpart of the `Versola` facade yet (`ios/Sources` holds only the generic
facade), so the iOS rows above are the contract it will implement, not behaviour any SDK has today.

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

| Assumption | Server issue | Code state | What the SDK must do |
|---|---|---|---|
| Edge protects itself from a client that floods it | [versola#310](https://github.com/versolauth/versola/issues/310), open | No rate limiter in `edge` yet; auth's `SubmissionLimiter` and `ThrottlePolicy` cover the challenge conversation only. Nothing emits 429 or `Retry-After` anywhere in `auth/src/main` or `edge/src/main`. | Bound retries client-side regardless — [`retry-policy.md`](retry-policy.md), asserted by scenario 19. When the limiter lands, honour 429 and `Retry-After`: tracked in #22, deliberately not phase 1, because there is no response shape to write against yet. |
| Edge's OpenAPI matches its code on the relayed nonce challenge | — | `edge/open-api/edge.yaml` says auth's `use_dpop_nonce` is "relayed the same way" as edge's own 401; the code relays auth's `400` + JSON unchanged. | Read both shapes (done). Reported upstream as a doc fix. |

## Consequences that shaped the spec

**The retry budget is the SDK's own.** Not because edge will never have a limiter — it will —
but because a shipped app's retry loop keeps running on every installed device until the next
release reaches them. A server-side limiter bounds the damage to the server; only a client-side
ceiling bounds what the client emits. Both are wanted; they are not substitutes.

**Bearer mode still has to be correct**, even though it is no longer the default. A deployment
that has not turned DPoP on gets the rotation-race handling, and scenario 07 keeps that path
tested rather than notional.

**Both back channels have to be correct.** `BackChannel.Auth` is the portable core and the
only one that works against a non-Versola provider; `BackChannel.Edge` is what the Versola
default tenant needs. A behaviour that exists in one and not the other is a conformance gap,
not a platform idiom: scenarios 21–23 run the edge flow, every other scenario runs both where
the step exists in both.

## Keeping this current

When a listed issue closes, move the assumption into the settled section above, or into #1's
ground-truth table if it is load-bearing enough to belong there. When the harness (#15) asserts
one of these behaviours against a staged stack, note the scenario in the row — an assumption a
test holds down does not need tracking here.
