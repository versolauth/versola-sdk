# Retry policy

Normative for every SDK. Grounded by issue #1.

Retries are **configurable within fixed bounds**. An integrator can make the SDK more patient
or less, and cannot make it unbounded. There is no configuration that produces an unlimited
retry loop, and none that disables the per-operation ceiling.

The reason is not politeness. A retry loop in a shipped app cannot be recalled: it keeps
running on every installed device until the next release reaches them. Whether the server
pushes back is a separate question from whether the client stops on its own, and only the
second is under our control.

## What counts as one operation

One application-visible call: a `login()`, a `logout()`, one request through the SDK's HTTP
client, or one refresh. Internal steps the SDK performs to satisfy it — a nonce retry, a
refresh triggered by a 401, the replay of the original request afterwards — are **inside** that
operation's budget, not new operations with budgets of their own.

Only a request that **failed** is spent from the allowances: a `login()` that discovers, fetches the
keys and pushes makes several repeatable requests on one origin, and a success is not a retry. For a
request that fails every time the count is the number in the table, which is what the scenarios
assert.

This is the rule that stops the classic compounding failure, where a refresh with three
attempts is triggered by a call with three attempts and the pair emits nine requests.

## Defaults

| Knob | Default | Hard maximum | Meaning |
|---|---|---|---|
| `maxAttemptsPerOrigin` | 3 | 5 | Requests to one origin per operation, original included, that failed. |
| `maxTotalAttempts` | 4 | 8 | Failed requests across all origins per operation. A call that fails and the refresh it triggers share it. |
| `initialBackoff` | 500 ms | 30 s | Delay before the second attempt. |
| `backoffMultiplier` | 2.0 | 4.0 | Applied per attempt. |
| `maxBackoff` | 8 s | 30 s | Ceiling on any single delay. |
| `jitter` | full | — | Not configurable. Synchronised retries across a user base are a thundering herd. |
| `totalBudget` | 20 s | 60 s | Wall-clock ceiling for one operation including delays. |

A value above the hard maximum is a `Configuration` error at `configure()` time, not a silent
clamp, and so are a `maxBackoff` below `initialBackoff` and a `maxAttemptsPerOrigin` above
`maxTotalAttempts`. Silently accepting a rejected value teaches an integrator that the knob works.

## Retries that are fixed, not configurable

Three are protocol-shaped rather than transport-shaped, so they are ceilings rather than
budgets. None of them are affected by the numbers above.

| Condition | Attempts | Why it cannot be raised |
|---|---|---|
| `use_dpop_nonce` | exactly 1 retry, per origin, per operation | RFC 9449 §9 nonces arrive in the response. One retry is enough; a second demand means the server will never be satisfied, and looping is the failure mode scenario 05 exists to prevent. |
| `invalid_dpop_proof` | exactly 1 retry | The one recoverable cause is clock skew, which the SDK corrects from the `Date` header (#6). A second failure means the key does not match the grant. |
| 401 that is not a step-up or a nonce demand | exactly 1 refresh, then 1 replay | A second refresh in one operation cannot help: the first either produced a usable token or did not. |

## Never retried

- `invalid_grant` — the grant is gone; retrying is how clients silently log users out
- Any `Configuration` error — `state` mismatch, `iss` mismatch, unregistered redirect URI,
  unknown scope. A retry cannot fix a deployment mistake.
- `insufficient_user_authentication` — a step-up needs a new authorization, not another attempt
- User cancel. A system cancel may be resumed, which is a resumption rather than a retry.
- The `authorization_code` exchange, including on a dropped response. The code is single-use
  and the server offers no idempotency for this grant type, so a second attempt is a replay
  the server may answer by revoking what it already issued from the code (RFC 6749 §4.1.2) —
  turning a login that failed into one that cannot complete. The user signs in again instead.
  The nonce and clock-skew retries below still apply: both answer a challenge raised before
  the code was redeemed.

## What is retried

Two questions decide whether a failed request is repeated: **what the response was**, and **what
the operation is**. The first is the classification below, the second the operation table. A
failure is repeated only when both say yes, and always inside the operation's budget.

### Classification

| Outcome | Class | Notes |
|---|---|---|
| No response: connect failure, DNS, TLS, reset, timeout | `transport` | A timeout after the request left the device may have been processed, so it is repeated only for an operation that tolerates a repeat (table below). |
| 408, 429, 500, 502, 503, 504 | `transient` | The provider is busy or briefly broken. 429 and 503 may carry `Retry-After` (below). |
| Any other 5xx (501, 505, ...) | `permanent server fault` | Not implemented, or an HTTP version the server refuses: a repeat cannot help. Surfaced at once as `Recoverable(Server)` with no retry. |
| A status the operation has no use for and no more precise error for (a 404 on the key set, a 1xx) | `unexpected` | `Recoverable(Server(status))`, never repeated. It was a `Network` before, which the budget would have repeated as a transport failure. |
| 3xx from discovery, the key set, the token endpoint, UserInfo or the push | `Configuration` | A redirect is not followed and is a deployment fault no retry fixes (`errors.md`), the same at every endpoint. |
| 4xx other than 408 and 429 | the OAuth error, or `Configuration` | `errors.md`. A 4xx is never repeated. UserInfo's own mapping: any answer that is not 2xx, 401, 408, 429 or 5xx (a 403, a 404, a redirect, a 1xx) is `Configuration(UserInfoRejected)` on every platform. |
| 401 and 400 DPoP challenges | handled internally | The fixed retries above. |

A `transport` or `transient` failure on an operation that tolerates a repeat consumes the
configurable budget. On any other operation it is surfaced at once.

### Operations

Every request the SDK originates is in this table, and each row says why. The default is "retried":
an operation is excluded only for a reason written in the row.

| Operation | Repeated on `transport` / `transient` | Why |
|---|---|---|
| Discovery (`GET`) | yes | Read-only. |
| JWKS (`GET`) | yes | Read-only. |
| Pushed authorization request (`POST /par`) | yes | A second push creates a second `request_uri`; the first expires unused. Nothing is spent. |
| `authorization_code` exchange | **no** | The code is single-use and the server offers no idempotency for this grant (above). The user signs in again. |
| Refresh (`POST /token`, `refresh_token`) | **with an `Idempotency-Key`: yes. Without one: only when the request provably was not processed** | A facade that sends the key (the Versola facade) repeats freely: a repeat after a dropped response resolves to the same rotation. A facade that sends none (the generic facade) cannot tell a request the provider never saw from one it processed and answered badly, and a repeat of a refresh the provider already rotated is a replay that a rotating provider can answer by revoking the whole family. It repeats a refresh only after a failure in the connect phase (no such host, connection refused, no route, a TLS handshake or certificate failure: nothing was written) or an answer that says the provider did not take it up (408, 429, 503). A timeout after connecting, a reset, a 500, a 502 or a 504 surface after one request, with no delay and the stored token and rotation slot untouched. |
| Revocation (`POST`, RFC 7009) | yes | Revoking an already revoked token succeeds by definition. |
| UserInfo (`GET`) | yes | Read-only. |
| Edge `/native/start` | yes | As a pushed authorization request. |
| Edge `/native/complete` | **no** | It redeems the code, as the exchange above. |
| Edge `/native/token`, `/native/revoke` | yes | As refresh and revocation. |
| The application's request through the authenticated client | **no on status; transport only if never sent** | The SDK cannot know the call was idempotent. A failure to establish the connection is repeated, because a request that never left the device cannot have been processed; a 429, 5xx or timeout after sending is the application's, with its `Retry-After` header intact. |

One budget serves one application-visible operation across every row it touches (above): a
`login()` that discovers, fetches the JWKS and pushes a request shares one allowance, and a
discovery that failed twice leaves less for the push.

### The timeout of one request

`totalBudget` bounds an operation only if no single request can outlast it. Every request the SDK
originates therefore carries a **deadline for the whole exchange** (the time to the last byte, not
an idle timeout that every dripped byte restarts), equal to what is left of the operation's
`totalBudget` at the moment it is sent, and never longer than the HTTP client's own request
timeout. A nearly spent budget does not set a request up to fail at once: the deadline is floored
at **5 seconds**, since the one request that cannot be repeated (the code exchange, after the
user's time in the browser) must get a fair try. That request has the deadline too: if it passes
after the request left the device the code may already be spent, so the exchange is surfaced as
`Recoverable(Network)` and the user signs in again (it is never repeated, above). The deadline passing is a `transport` failure
(`Network`), classified as any other (a timeout after the request left the device is repeated only
by an operation that tolerates it). A request outside any operation (a flight started from a timer
the app owns has its own budget; a bare call has none) gets the client's own timeout.

**Android deviation.** Android does not derive a per-request deadline from the budget: a request is
bounded by the timeouts of the `OkHttpClient` it was given (its connect, read and write timeouts, 10
seconds each by default, and no whole-call timeout), so a nearly spent budget does not shorten it
and there is no 5-second floor to keep. The rule about the code exchange holds all the same: a
timeout after the request left the device may have spent the code, so it is surfaced as
`Recoverable(Network)` and never repeated.

### A stale key set for a refresh

The ID token on a refresh response is judged after the rotated refresh token is stored
(`state-machine.md`), so a key set that cannot be fetched fails the refresh as `Recoverable` with
the grant intact. Left there, an outage of the key set while the token endpoint is up would make
every `accessToken()` spend a rotation, receive an access token and throw it away, for as long as
the outage lasts. For this check alone, and only when the fetch failed as a `Recoverable` (never
for an answer that is not a key set), the key set the client holds past its lifetime is used,
**up to one week after it expired**; a set that lacks the token's `kid` is `Recoverable`, not a
signature rejection, since it proves an outage and nothing else. Login, UserInfo and every other
reader of the key set never see a stale one.

The cost, stated: for at most a week a signing key the provider has withdrawn can still verify an
ID token that arrives on a refresh. What that ID token vouches for on a refresh is bounded (the
`sub` must not change, `aud`, `iss`, `exp` and the rest still apply, and the access token it
accompanies came from the token endpoint over TLS), and a provider that rotates keys for
compromise reasons revokes refresh tokens too. Android and iOS apply the same rule.

### Order of work

`login()` has one step that cannot be repeated, the code exchange, and a request that can fail after
it: the key set the ID token is verified against, when it is not cached yet. That fetch is repeated
under the budget like any other (three attempts and the backoff), which is what covers the window
in which a login the provider already completed would otherwise be lost. Fetching the key set before
the browser opens was considered and refused: it changes when the key set is requested (scenarios 24
and 26 assert that validation, and a rejection before it, decide that), for a window the budget
already covers. The time the user spends in the browser is not counted against `totalBudget`, and the allowances
are shared across it: a `login()` is one budget, paused while the browser is up.

### `Retry-After`

Read on **429 and 503 only**; on any other status the header is ignored.

- **Forms.** `delta-seconds` (a non-negative integer) or an HTTP-date (RFC 9110 section 10.2.3).
  An HTTP-date is measured against the response's `Date` header when it has one, and against the
  device clock otherwise, so a skewed device clock does not stretch or shrink the wait. Anything
  else (negative, fractional, empty, repeated, unparseable, a date in the past) is treated as
  absent and the policy's own backoff applies. A malformed header never fails the request.
- **In preference to the backoff.** With a value `R` the delay before the next attempt is `R` plus
  jitter of up to `min(R / 10, 1 s, what is left of the budget after R)`, never negative, not the
  computed backoff. The jitter never turns a `Retry-After` that fits into one that does not: the server has said when it will
  accept the request, and an earlier one is a request it said it would refuse. `maxBackoff` does
  not cap it.
- **Never retried early to fit the budget.** If `R` plus the time already spent exceeds
  `totalBudget` (the jitter is not part of this test), the SDK does not sleep and does not shorten the wait. It stops at once and
  surfaces `Recoverable(Server)` carrying `retryAfter`, so a `Retry-After: 86400` costs no
  waiting and no request, and the app decides what to do with the day. This replaces the earlier
  draft ("clamped to `totalBudget`"), which would have retried earlier than the server allowed.
- **Still an attempt.** A request made after waiting counts against `maxAttemptsPerOrigin` and
  `maxTotalAttempts` like any other, so `Retry-After: 0` repeated forever is still three requests.
- **Surfaced values saturate** at one day, so arithmetic on them cannot overflow.

### Cooldown

When an operation **ends** because of a `Retry-After` (the wait does not fit the budget, or the
attempts ran out while the server kept asking), the SDK remembers, per origin and in memory, the
moment the server said it would accept requests again. A `Retry-After` that fits, is waited out
and is followed by a success starts nothing, so a concurrent call is not refused on its account.
The origin is the one the request goes to: a revocation endpoint on another host than the token
endpoint has its own allowance and its own cooldown. Until the time passes every SDK-originated
request to that origin (a refresh triggered by a call, a revocation, a UserInfo) fails
immediately with the same `Recoverable(Server)`, `retryAfter` set to what is left and `attempts` 0,
**without sending anything**. Without this, an app that calls `accessToken()` in a loop, or fifty screens
that each retry, would send a new request per call to a server that asked for quiet.

- The code exchange is the exception on both sides. It is **not refused** by a cooldown: the code
  was just obtained after the user's time in the browser, and refusing it would waste that step for
  a request the provider was going to answer anyway. It is made once, and if it ends with a
  `Retry-After` of 429 or 503 that starts a cooldown like any other ending. `login()` therefore
  checks the cooldown of the token origin at its **start**, before the browser opens, where a
  refusal costs the user nothing; `resumePendingLogin()` does not check.
- Memory only. A cold start forgets it; the server still enforces its limit, and one request
  after a restart is the cost of not persisting a deadline.
- Only what the server said. Exhausting the budget on 5xx with no `Retry-After` starts no cooldown:
  the SDK does not invent a provider's policy, and the app owns the retry loop above it.
- The application's requests through the authenticated client are never blocked by it.
- Both the cooldown and the budget are measured on a clock that keeps running while the device
  sleeps (Android `SystemClock.elapsedRealtime`, iOS a continuous clock), because `Retry-After` is
  wall time: a monotonic clock that stops in deep sleep would hold an origin for the time the
  phone slept on top of what the server asked.

### What the app sees

`Recoverable` carries one of two network causes. `Network` is a transport failure (nothing
answered). `Server(status, retryAfter, attempts, elapsed)` is an HTTP answer that kept the
operation from finishing: `status` is the last status seen (408, 429, 5xx or an unusable one),
`retryAfter` is the parsed header (absent when there was none), `attempts` is the number of failed
requests **of the call that surfaced the error** (not of the whole operation, so a `login()` whose
discovery failed twice and whose push then fails three times reports 3 on the push), and the
attempt count and elapsed time say whether the ceiling was reached. Both leave the session where it was (`Authenticated` after a failed refresh;
the pre-`login()` state after a failed login). What the app does:

- `retryAfter` present: do not repeat before it; schedule the retry instead of looping.
- Absent: offer a retry, or back off on the app's side. The SDK has already spent its budget.
- A 429 and a 5xx are distinguished by `status`, not by category: both are `Recoverable`.

The default log level records each attempt as a status, an attempt number and a delay, and no
header or body.

### Not done, on purpose

No circuit breaker beyond the cooldown, no persisted deadline, no retry of an application request
on a status, and no retry loop that outlives the operation that started it (background refresh is
the app's scheduler's, not a timer in the SDK).

## Idempotency

A retry is only safe on an operation the server can recognise as a repeat. The refresh path
of a facade that sends one carries an `Idempotency-Key` derived from the generation being consumed
(#8), so a retry after a dropped response resolves to the same rotation rather than reading as a
replay. The generic facade sends none (ADR 0001), and its refresh is repeated only when it provably
was not processed (operations table). Even so, the next `refresh()` the app makes after an
ambiguous failure sends the same stored token, because the SDK cannot know whether the provider
rotated it; a provider that did answers `invalid_grant`, which is `Reauthenticate`.

An application request the SDK replays after a refresh is replayed **once**, and only when the
original failed with 401 before reaching the application — not when it failed mid-response.

## Configuration surface

```kotlin
Versola.configure(
    context,
    issuer = "https://id.versola.io",
    clientId = "mobile-app",
    redirectUri = "https://app.example.com/oauth",
    retry = RetryPolicy(
        maxAttemptsPerOrigin = 2,
        maxBackoff = 4.seconds,
    ),
)
```

`RetryPolicy.Conservative` and `RetryPolicy.Patient` are provided as named presets within the
same bounds, because most integrators want "fewer" or "more" rather than five numbers.

The same type exists on every platform with the same field names, the same defaults and the
same maxima. A policy that behaves differently across platforms is a conformance failure, not a
platform idiom.

Observability: every exhausted budget is reported with the attempt count and elapsed time
attached to the `Recoverable` cause, so an integrator can see the ceiling was reached rather
than guessing.
