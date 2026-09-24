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

This is the rule that stops the classic compounding failure, where a refresh with three
attempts is triggered by a call with three attempts and the pair emits nine requests.

## Defaults

| Knob | Default | Hard maximum | Meaning |
|---|---|---|---|
| `maxAttemptsPerOrigin` | 3 | 5 | Requests to one origin per operation, original included. |
| `maxTotalAttempts` | 4 | 8 | Requests across all origins per operation. A refresh plus the replayed call is two. |
| `initialBackoff` | 500 ms | — | Delay before the second attempt. |
| `backoffMultiplier` | 2.0 | 4.0 | Applied per attempt. |
| `maxBackoff` | 8 s | 30 s | Ceiling on any single delay. |
| `jitter` | full | — | Not configurable. Synchronised retries across a user base are a thundering herd. |
| `totalBudget` | 20 s | 60 s | Wall-clock ceiling for one operation including delays. |

A value above the hard maximum is a `Configuration` error at `configure()` time, not a silent
clamp. Silently accepting a rejected value teaches an integrator that the knob works.

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

Transport failures, timeouts, DNS, 5xx, and 408. These consume the configurable budget above.

429 is not listed, because nothing in the server emits one yet. When edge's rate limiter lands
([versola#310](https://github.com/versolauth/versola/issues/310)) the SDK should treat 429 as
its own cause and honour `Retry-After` in preference to its own backoff — clamped to
`totalBudget`, so a `Retry-After: 86400` cannot park a request for a day. Tracked in #22, out
of scope for phase 1. Until then a 429 falls through to the generic `Recoverable` path and is
retried under the budget like any other transient failure, which is safe but imprecise.

## Idempotency

A retry is only safe on an operation the server can recognise as a repeat. The refresh path
carries an `Idempotency-Key` derived from the generation being consumed (#8), so a retry after
a dropped response resolves to the same rotation rather than reading as a replay.

An application request the SDK replays after a refresh is replayed **once**, and only when the
original failed with 401 before reaching the application — not when it failed mid-response.

## Configuration surface

```kotlin
Versola.configure(
    context,
    issuer = "https://id.versola.kz",
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
