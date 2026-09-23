# Session state machine

Normative for every SDK. Android, iOS, Flutter and React Native implement *this* machine;
they do not each invent one. Where a platform cannot express a rule, the deviation is recorded
here rather than in platform code.

Grounded by issue #1. Conformance scenarios in [`conformance/`](conformance/) reference states
and transitions by the names used below.

## States

| State | Meaning |
|---|---|
| `Unauthenticated` | No usable grant. `login()` is the only meaningful call. |
| `Authorizing` | An authorization request is outstanding: the browser is open, or the app was killed while it was. |
| `Authenticated` | A refresh token is held and an access token is available or derivable. |
| `Refreshing` | A token request is in flight. Concurrent callers coalesce onto it; they do not each enter this state. |
| `StepUpRequired` | Edge refused a call with `insufficient_user_authentication`. The grant is valid; its authentication context is not sufficient. |
| `Locked` | Credentials are present but the key protecting them needs user authentication. Only reachable under `UnlockPolicy.OnAppUnlock` or `OnEveryCall`. |
| `LoggingOut` | RP-initiated logout is in flight. |

`Refreshing`, `StepUpRequired`, `Locked` and `LoggingOut` are sub-states of holding a grant:
the app is not signed out while in them, and UI should not treat them as such.

## Transitions

```mermaid
stateDiagram-v2
    [*] --> Unauthenticated
    Unauthenticated --> Authorizing: login()
    Authorizing --> Authenticated: redirect validated, code exchanged
    Authorizing --> Unauthenticated: user cancel
    Authorizing --> Unauthenticated: authorization error
    Authorizing --> Authorizing: process death, pending request restored
    Authenticated --> Refreshing: access token expired or 401
    Refreshing --> Authenticated: token response persisted
    Refreshing --> Unauthenticated: invalid_grant
    Authenticated --> StepUpRequired: edge insufficient_user_authentication
    StepUpRequired --> Authorizing: stepUp(challenge)
    Authenticated --> Locked: key requires user authentication
    Locked --> Authenticated: unlock succeeded
    Locked --> Unauthenticated: credentials invalidated by enrolment change
    Authenticated --> LoggingOut: logout()
    LoggingOut --> Unauthenticated: local state wiped
```

Every transition below names what is persisted at the moment it happens. Anything not named as
persisted is memory-only and is gone after process death by design.

### `Unauthenticated → Authorizing`

Triggered by `login(scopes)`. Before the browser opens, the SDK persists the **pending
authorization request**: PKCE `code_verifier`, `state`, `nonce`, requested scopes, target
`redirect_uri`, and the `acr_values` / `max_age` if this is a step-up. Encrypted through
`CredentialKeyProvider`.

Persisting before opening the browser, not after, is the whole point: the app can be killed
between the two.

### `Authorizing → Authenticated`

On redirect, in this order, all before any network call:

1. `state` matches the persisted value, compared in constant time
2. `iss` matches the configured issuer (RFC 9207)
3. the response carries `code`

Then the code is exchanged. The token response is persisted **before** it is returned to the
caller, and the pending request is wiped only after the refresh token is durably stored.

Persisted: refresh token (encrypted), DPoP key reference, issuer metadata cache.
Memory only: access token, ID token claims, both nonce caches.

### `Authorizing → Unauthenticated` — cancel

Two causes, and they must be distinguishable. The category is `Recoverable` for both, but the
app shows a different thing.

| Cause | Android | iOS |
|---|---|---|
| **User cancel** — user dismissed the browser | Custom Tab closed with no redirect, app returned to foreground | `ASWebAuthenticationSessionErrorCodeCanceledLogin` **while the app is foreground** |
| **System cancel** — the OS tore the session down | activity destroyed while backgrounded, no redirect delivered | the same error code **while the app is backgrounded or inactive** |

iOS reports both through one error code. Pairing it with app lifecycle state at the moment the
error arrives is the only way to separate them, and it is required, not optional: a system
cancel should be retried silently, a user cancel must not be.

The pending request is wiped on user cancel and **kept** on system cancel, so the flow can be
resumed.

### `Authorizing → Authorizing` — process death

On startup, if a pending authorization request exists it is restored and the SDK re-enters
`Authorizing` rather than reporting `Unauthenticated`. A redirect delivered to a cold-started
process is then validated against the restored `state` and completes normally.

A pending request older than **10 minutes** is discarded and the SDK settles in
`Unauthenticated`; authorization codes do not outlive that anyway.

This is the `flutter_appauth` failure recorded in `mobile-demo`'s `pubspec.yaml`. It is not an
edge case on Android.

### `Authenticated → Refreshing → Authenticated`

Entered when the access token is expired, within its refresh skew, or a call returned 401 that
is *not* a step-up and *not* a nonce demand.

**Exactly one** token request may be in flight per session. Concurrent callers await the
winner's result; they do not queue further requests. In bearer mode this is a correctness
requirement rather than an optimisation — concurrent rotations are replays, and a replay
revokes the family.

Every refresh carries an `Idempotency-Key`. The key is derived from the refresh token
generation being consumed, so a retry after a dropped response reuses it and resolves to the
same rotation.

Persistence, in order:

1. the outgoing generation is copied into a `pending` slot before the request is sent
2. the response is persisted before it is returned to any caller
3. the `pending` slot is cleared after the new value is durably stored

A process killed between 1 and 3 recovers by replaying with the same idempotency key on next
start; the server resolves which generation is live.

Under DPoP the server renews the refresh token in place (`BoundRenewal`) and the stored value
does not change — steps 1 and 3 are inert. The machinery exists for bearer mode.

### `Refreshing → Unauthenticated`

Only on `invalid_grant`. Network failures, `use_dpop_nonce` and 5xx leave the state at
`Authenticated` and are retried under the SDK's own policy.

Everything credential-shaped is wiped: refresh token, pending slot, nonce caches. The DPoP key
follows the logout rule (below).

### `Authenticated → StepUpRequired → Authorizing`

Edge answers a call it will not serve with `401` and

```http
WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="…", max_age="…"
```

Note the scheme: edge emits **`Bearer`** on this challenge even for DPoP-bound callers, and
`DPoP` on `invalid_dpop_proof` and `use_dpop_nonce`. Parse on the `error` value, not the
scheme.

This is not a refresh condition. A client that refreshes here loops forever against a token
that can never satisfy the ACR. The SDK surfaces `StepUp(acrValues, maxAge)`; `stepUp()`
re-enters `Authorizing` carrying those parameters, and the originating call is resumed once
`Authenticated` is reached again.

The originating request is held in memory only. A process death during step-up loses it, and
the app is expected to re-issue the call.

### `Authenticated → Locked → Authenticated`

Under `UnlockPolicy.OnAppUnlock` the *storage* key requires user authentication; the DPoP key
does not. Entering `Locked` means the refresh token cannot currently be unwrapped. The access
token already in memory stays usable until it expires.

Under `OnEveryCall` the DPoP key is gated too, and background operation is disabled. That
combination is documented, not silently accepted.

The unlock prompt must be bound to the crypto operation (`BiometricPrompt.CryptoObject`,
`LAContext` reuse) rather than gating on a boolean returned by a biometric API. A boolean gates
nothing: a patched binary returns `true`. `mobile-demo`'s `device_lock.dart` is the worked
example of the wrong version.

### `Locked → Unauthenticated`

Biometric enrolment changes invalidate the storage key, and the wrapped refresh token becomes
undecryptable. This is indistinguishable from tampering and is treated as sign-out:
`Reauthenticate`, wipe, no error dialog beyond that.

### `Authenticated → LoggingOut → Unauthenticated`

`logout()` revokes the refresh token at `/revoke`, opens auth's `/logout` with `id_token_hint`
and `post_logout_redirect_uri`, then wipes local state.

Local state is wiped **even if the browser leg fails or is dismissed**. Reaching
`Unauthenticated` locally is unconditional; only the server-side session teardown is
best-effort.

The DPoP key is **destroyed** on logout. It is cheap to regenerate and its purpose is binding
one grant to one device-installation; reusing it across users on a shared device defeats that.

## Persistence summary

| Item | Storage | Survives process death | Survives logout |
|---|---|---|---|
| Refresh token | Encrypted, `CredentialKeyProvider` | yes | no |
| Pending refresh generation | Encrypted | yes | no |
| Pending authorization request | Encrypted | yes, ≤10 min | no |
| Access token | Memory | no | no |
| ID token claims | Memory | no | no |
| DPoP private key | Hardware keystore, non-exportable | yes | no (destroyed) |
| DPoP nonce, per origin | Memory | no | no |
| Clock skew offset | Memory | no | no |
| Discovery metadata | Disk, unencrypted | yes | yes |

Discovery metadata is not credential material and is cached across logout deliberately: a
re-login should not need a round trip to `/.well-known/openid-configuration`.

## Observability

Each SDK exposes the current state as a stream — `Flow<SessionState>` on Android,
`AsyncStream<SessionState>` on iOS, `Stream<SessionState>` in Dart. The state values are the
seven above and no others; platform-specific states are not permitted.
