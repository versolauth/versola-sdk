# Server dependencies

What the spec assumes of `versolauth/versola`, and which of those assumptions are still open
work there. Grounded by issue #1, whose ground-truth table this document qualifies: #1 records
what the server *does*, this records what is *not finished* and what the SDK must therefore not
rely on.

Checked against the working tree at the time of writing, not against issue state. An open issue
whose code has landed is still listed, because until it is closed and verified nothing
guarantees the behaviour stays.

## DPoP

| Assumption | Server issue | Code state | What the SDK must do |
|---|---|---|---|
| Edge verifies a DPoP proof on proxied calls, compares it against the access token's `cnf.jkt`, refuses a `Bearer` presentation of a bound token, and rejects `jti` replays | [versola#294](https://github.com/versolauth/versola/issues/294), open | Landed: `edge/.../dpop/DpopVerifier.scala`, `DpopReplayGuard.scala`, and the scheme handling in `edge/.../auth.scala`. Every box on #294's checklist has code behind it. | Do not treat the issue's "there is no DPoP code in `edge/src/main` at all" as current. **Assert it in the harness (#15) against a staged edge** rather than trusting either the issue or this table. Scenarios 01 and 04 are what make it real. |
| A client can be *required* to present DPoP | [versola#294](https://github.com/versolauth/versola/issues/294), open on rollout | `OAuthClientRecord.dpopBoundAccessTokens` exists and `OAuthTokenService.requireDpop` enforces it at `/token`. #294 holds the enablement, not the mechanism. | The SDK must be correct against a client with the flag **off**, which is every client today. Scenario 07 is not a legacy-deployment courtesy; it is the current default. |
| Nonces are demanded when the deployment says so | — | `requireDpopNonce` on `ChallengeSettingsRecord`, per client, default `false`. Auth and edge keep separate nonce spaces (`EdgeConfig.nonceSalt`). | Nonce handling is driven **by the response, never by configuration**. A deployment that never demands one must not leave the code path untested, which is why scenarios 03, 04 and 05 use fault injection instead of a real deployment. |
| The server refuses proof keys too weak to constrain anything | [versola#302](https://github.com/versolauth/versola/issues/302), open | `Dpop.verify` accepts any key whose algorithm is allow-listed; Nimbus enforces no minimum RSA modulus. EC is already narrow — `ES256` fixes the curve. | Nothing, mechanically: the SDK mints ES256 on P-256 and cannot present a weak key. But **the SDK's documentation must not claim the server enforces a key-strength floor**, because it does not yet. |
| Edge protects itself from a client that floods it | [versola#310](https://github.com/versolauth/versola/issues/310), open | No rate limiter anywhere in `edge` — not per client, token, IP or endpoint. Auth's `SubmissionLimiter` and `ThrottlePolicy` cover the challenge conversation only. | **The retry budget is the SDK's responsibility.** Nothing server-side will stop a retry loop in a shipped app. Scenario 19 makes the budget observable, and scenario 05's nonce-loop guard is the same rule applied to one specific loop. |

## Consequences that shaped the spec

Two of the rows above are the reason for a rule that would otherwise look arbitrary:

**The one-shot retry ceiling** in [`errors.md`](errors.md) — one nonce retry, one proof retry,
one refresh per 401 — is not a stylistic preference. With versola#310 open, an unbounded retry
loop in a shipped SDK has nothing between it and edge's backend capacity. Client-side budgets
are the only limiter that exists.

**Bearer mode is not the legacy path.** `dpopBoundAccessTokens` is off for every client while
versola#294's rollout is pending, so the machinery in #8 and #14 — idempotency keys, the pending
slot, replay handling — is load-bearing today, not a safety net for old deployments. The
"DPoP is the default, so rotation races cannot happen" reasoning becomes true only after that
flag is on.

## Keeping this current

When a listed issue closes, delete its row and move the assumption into #1's ground-truth
table. When the harness (#15) asserts one of these behaviours against a staged stack, note the
scenario in the row — an assumption a test holds down does not need to be tracked here.
