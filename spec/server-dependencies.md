# Server dependencies

What the spec assumes of `versolauth/versola`, and which of those assumptions are still open
work there. Grounded by issue #1, whose ground-truth table this document qualifies: #1 records
what the server *does*, this records what is *not finished* and what the SDK must therefore not
rely on.

Checked against the working tree, not against issue text.

## Settled — DPoP is the default

Edge-side DPoP enforcement shipped with [versola#294](https://github.com/versolauth/versola/issues/294),
now closed. `edge/.../dpop/DpopVerifier.scala` compares the proof's thumbprint against the
access token's `cnf.jkt`, `auth.scala` refuses a `Bearer` presentation of a bound token,
`DpopReplayGuard` rejects `jti` replays, and edge issues its own nonces keyed by
`EdgeConfig.nonceSalt`.

So **the SDK ships DPoP on by default**, and bearer is the fallback rather than the norm:

- `TokenBinding.Dpop` is the default. Bearer is reached only when discovery does not advertise
  `dpop_signing_alg_values_supported` — conformance scenario 07, which describes an older or
  differently configured deployment, not the Versola default.
- Under DPoP the server renews sender-constrained refresh tokens in place (`BoundRenewal`), so
  there is no rotation and no replay window. The rotation machinery in #8 and #14 — pending
  slot, idempotency key, family-revocation handling — is a **safety net for bearer mode**, not
  the load-bearing path.
- A mobile client must be registered with `dpopBoundAccessTokens = true`. Note the coupled
  constraint in `InvalidRegistrationConfiguration`: enabling it requires
  `accessTokenTtl >= 3600s`, so a client registered with a shorter access-token lifetime is
  rejected at registration. Worth knowing before #5 and #11 write their setup fixtures.
- Both nonce spaces are real, which is why a shared nonce cache loops. Scenario 04.

## Open

| Assumption | Server issue | Code state | What the SDK must do |
|---|---|---|---|
| Edge protects itself from a client that floods it | [versola#310](https://github.com/versolauth/versola/issues/310), open | No rate limiter in `edge` yet; auth's `SubmissionLimiter` and `ThrottlePolicy` cover the challenge conversation only. Nothing emits 429 or `Retry-After` anywhere in `auth/src/main` or `edge/src/main`. | Bound retries client-side regardless \u2014 [`retry-policy.md`](retry-policy.md), asserted by scenario 19. When the limiter lands, honour 429 and `Retry-After`: tracked in #22, deliberately not phase 1, because there is no response shape to write against yet. |
| The server refuses proof keys too weak to constrain anything | [versola#302](https://github.com/versolauth/versola/issues/302), open | `Dpop.verify` accepts any key whose algorithm is allow-listed; Nimbus enforces no minimum RSA modulus. EC is already narrow \u2014 `ES256` fixes the curve. | Nothing mechanically: the SDK mints ES256 on P-256 and cannot present a weak key. But **the SDK's documentation must not claim the server enforces a key-strength floor**, because it does not yet. |

## Consequences that shaped the spec

**The retry budget is the SDK's own.** Not because edge will never have a limiter — it will —
but because a shipped app's retry loop keeps running on every installed device until the next
release reaches them. A server-side limiter bounds the damage to the server; only a client-side
ceiling bounds what the client emits. Both are wanted; they are not substitutes.

**Bearer mode still has to be correct**, even though it is no longer the default. A deployment
that has not turned DPoP on gets the rotation-race handling, and scenario 07 keeps that path
tested rather than notional.

## Keeping this current

When a listed issue closes, move the assumption into the settled section above, or into #1's
ground-truth table if it is load-bearing enough to belong there. When the harness (#15) asserts
one of these behaviours against a staged stack, note the scenario in the row — an assumption a
test holds down does not need tracking here.
