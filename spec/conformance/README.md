# Conformance scenarios

Language-neutral acceptance criteria, one file per scenario, validated against
[`schema.json`](schema.json). The harness (issue #15) executes them against a real staged
`auth` + `edge` once per SDK and asserts identical observable behaviour.

A scenario names preconditions, a request sequence and machine-checkable assertions. It does
not describe intent — intent belongs in [`../state-machine.md`](../state-machine.md) and
[`../errors.md`](../errors.md), which every scenario is derived from.

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
