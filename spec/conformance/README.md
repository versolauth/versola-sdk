# Conformance scenarios

Language-neutral acceptance criteria, one file per scenario, validated against
[`schema.json`](schema.json). The harness (issue #15) executes them against a real staged
`auth` + `edge` once per SDK and asserts identical observable behaviour.

A scenario names preconditions, a request sequence and machine-checkable assertions. It does
not describe intent — intent belongs in [`../state-machine.md`](../state-machine.md) and
[`../errors.md`](../errors.md), which every scenario is derived from.

Scenarios 01–20 run with `BackChannel.Auth` on a `standard`-profile tenant. Where a step
exists under `BackChannel.Edge` as well — refresh, revocation, the edge API call, logout,
nonce handling — the harness runs it there too, against a `fapi2` tenant, and the observable
behaviour must be the same. Scenarios 21–23 exist for what only the edge flow has.

## Index

| # | Scenario | Mode | Issues |
|---|---|---|---|
| 01 | Happy path through edge | dpop | 5, 9, 11 |
| 02 | Silent refresh before expiry | any | 8, 14 |
| 03 | Token endpoint nonce retry | dpop | 6, 12 |
| 04 | Edge nonce isolated from auth's | dpop | 6, 9, 12 |
| 05 | Nonce loop guard | dpop | 6, 12 |
| 06 | Clock skew correction | dpop | 6, 12 |
| 07 | Bearer fallback when DPoP is unadvertised | bearer | 5, 6, 11, 12 |
| 08 | Single-flight refresh | any | 8, 14 |
| 09 | Idempotent retry after a dropped response | bearer | 8, 14 |
| 10 | Replay revokes the family | bearer | 8, 14 |
| 11 | Bound renewal in place | dpop | 8, 14 |
| 12 | Process death with the browser foreground | any | 5, 11 |
| 13 | Process death mid-rotation | bearer | 8, 14 |
| 14 | Step-up and resume | any | 9, 14 |
| 15 | `state` mismatch | any | 5, 11 |
| 16 | `iss` mismatch | any | 5, 11 |
| 17 | Unregistered redirect URI | any | 5, 11 |
| 18 | RP-initiated logout | any | 10, 14 |
| 19 | Retry budget bounded, backed off, configurable within maxima | any | 8, 9, 14 |
| 20 | Elapsed unlock window locks refresh, not the session | any | 7, 14 |
| 21 | Login through edge's native endpoints (FAPI 2.0 tenant) | dpop | 40 |
| 22 | Stolen code, blob or refresh token is useless without the device key | dpop | 40 |
| 23 | Edge's and auth's nonce challenges answered once each, from their own cache | dpop | 40, 6 |
| 24 | Generic facade: sign-in, authenticated call and sign-out against a conforming provider | bearer | 46 |
| 25 | ID token `nonce` mismatch rejected before persistence | any | 46 |
| 26 | ID token signature or algorithm refused | any | 46 |
| 27 | ID token `iss`, `aud`, `exp`, `iat`, `auth_time` rejected with the matching reason | any | 46 |
| 28 | Explicit endpoints without discovery | bearer | 46 |
| 29 | PAR when advertised, required, and rejected before the browser | any | 46 |
| 30 | Logout without `end_session_endpoint` | any | 46 |
| 31 | Session without a refresh token ends in `Reauthenticate` | any | 46 |
| 32 | Token attached only to protected origins | any | 46 |
| 33 | DPoP end to end against a provider that requires it and a resource server that verifies it | dpop | 46 |
| 34 | A transient server error is repeated or surfaced according to the operation | any | 22, 46 |
| 35 | `Retry-After` on 429 and 503 is honoured, bounded and never fails the request when malformed | any | 22, 46 |
| 36 | After a `Retry-After`, the SDK sends nothing to that origin until it has passed | any | 22, 46 |
| 37 | A refresh whose ID token is rejected keeps the rotated refresh token | any | 46 |

## Facades

A scenario carries `facade:` naming the facades it holds for: `versola` (the `Versola` facade,
the default when the key is absent) and `oauth` (the generic facade of
[`../oauth-sdk-api.md`](../oauth-sdk-api.md)). A scenario tagged with both runs under both; under
`oauth` it runs once per provider in [`../providers.md`](../providers.md), and the `provider`
actor stands for whichever OpenID Provider is staged. Scenarios 24 to 33 exist for what only the
generic facade does (explicit endpoints, PAR policy, providers without an `end_session_endpoint`
or without refresh tokens, protected origins, DPoP against a provider that requires it) and for ID-token validation, which both facades
share.

`applies_to` lists the platforms that meet every assertion of a scenario. A platform that lacks a
surface the assertions need leaves it out, or, when only part of a scenario needs the surface, the
scenario's `notes` say which part is the native facades' (scenarios 24 and 33 and the replay of a
proof on Flutter, which has the authenticated client as `httpClient()`, `../oauth-sdk-api.md`
section 10, but no way to reach the SDK's own request).

## Fault injection

Most scenarios are unreachable without the harness being able to misbehave on purpose.

| Capability | What it does |
|---|---|
| `drop-response` | Lets a request reach the server and discards the response. |
| `force-dpop-nonce` | Makes the next request on an origin answer `use_dpop_nonce` once. |
| `always-demand-dpop-nonce` | Answers `use_dpop_nonce` unconditionally, including to retries that carry one. |
| `clock-skew` | Offsets the device clock relative to the server. |
| `process-death` | Kills the app process at a named point and cold-starts it. |
| `omit-discovery-field` | Serves a discovery document with a member removed. |
| `network-partition` | Blocks connectivity for a bounded window. |
| `respond-with-status` | Answers matching requests with a given status and headers (`Retry-After`, `Date`) instead of forwarding them, for a bounded number of requests or a bounded window. Matches by method and path, so one operation fails while the rest of the flow runs. |

## Validating

```shell
python3 tools/validate-scenarios.py
```

Checks every file against the schema, that `id` matches the file name, and that the index
above lists each scenario exactly once. CI runs the same command.

## Adding a scenario

1. Derive it from a rule in `state-machine.md`, `errors.md` or `retry-policy.md`. A scenario
   with no rule behind it
   means the rule is missing; add it there first.
2. Give assertions that a machine can check. "Handles X correctly" is not an assertion.
3. Add the row to the index.
4. Reference it from the acceptance list of every issue it covers.
