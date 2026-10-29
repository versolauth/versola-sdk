---
paths: ["spec/**", "conformance/**", "tools/**"]
---

# Spec and Conformance

The spec is the artefact the three platforms share. There is no shared code that makes them agree;
`spec/` plus the conformance scenarios do (architecture review section 4: the transcripts prove
equivalence, shared source would only prove one bug exists twice). A change here is judged against
the standard's text first, then against the other platforms.

## The spec is normative

- `spec/state-machine.md`, `spec/errors.md` and `spec/retry-policy.md` say what every SDK does.
  Code that disagrees with them is the bug, unless the PR changes the spec.
- A behaviour change edits the spec first, in the same PR, then every platform. A PR that changes
  Android behaviour and leaves `spec/` untouched either has no observable change or has a missing
  spec edit; say which. A platform that cannot follow yet is listed in the PR as a gap with its
  issue, and the scenario's `applies_to` says so.
- The state set is closed. `spec/state-machine.md` lists seven states "and no others;
  platform-specific states are not permitted". The error taxonomy is four categories and the
  category is the contract (`spec/errors.md`): a new server error code maps to exactly one
  category, in the table, in the same change.
- Do not edit a rule to match what the code happens to do. If the code is right and the spec is
  wrong, the PR says so and changes the spec deliberately.
- `spec/server-dependencies.md` records what `versolauth/versola` does not do yet and what the SDK
  must therefore not rely on, checked against a named server commit. When a behaviour depends on
  the server, cite the file that decides it there; when the server catches up or changes, update
  the row and the commit it was checked against.

## Scenarios

- One file per scenario in `spec/conformance/NN-name.yaml`, validated against
  `spec/conformance/schema.json`. `id` equals the file name without its extension; `issues`,
  `applies_to`, `mode` (`dpop`, `bearer`, `any`), `preconditions`, `steps` and `assertions` are
  required.
- A new rule gets a scenario. Derive it from a rule in the state machine, errors or retry policy;
  a scenario with no rule behind it means the rule is missing, so add the rule first.
- Assertions are machine-checkable observations ("the token request carries exactly one `DPoP`
  header and no `client_secret` parameter"), never intent ("handles X correctly").
- Add the row to the index table in `spec/conformance/README.md`; the validator requires every
  scenario to be listed exactly once. Reference the scenario from the acceptance list of each issue
  it covers.
- Validate before you push:

  ```shell
  pip install -r tools/requirements.txt   # jsonschema, PyYAML, pinned
  python3 tools/validate-scenarios.py
  ```

  `spec.yml` runs the same command and markdownlint over `**/*.md` (`.markdownlint-cli2.jsonc`;
  line length is not enforced, keep lines near 100 characters like the neighbours).
- Every state and every error a scenario names must exist on every platform it `applies_to`: in
  `SessionState` and `VersolaError` on Android, and their Swift and Dart twins. Drift of this kind
  (a state in the spec that no code enters) is architecture review finding F4; the planned CI check
  over the `.api` dumps is meant to catch it, and until it exists you check by hand.
- Scenarios 01 to 20 run under `BackChannel.Auth` on a `standard` tenant; 21 to 23 exist for what
  only edge's native flow has. A step that exists under both back channels runs under both and
  behaves the same.

## Providers

- The generic OAuth SDK planned in issue #46 adds `spec/providers.md`: what the SDK assumes of a
  provider and a quirks matrix. Provider-specific behaviour (a missing `iss`, a refresh token that
  is not rotated, no `end_session_endpoint`) is a row there and a capability of the discovered
  metadata, never a branch on the issuer, the host name or the provider's product.
- A provider that cannot be supported without weakening a security check (a native client that
  must hold a secret) is recorded as unsupported in the matrix, with the reason.
- The Versola facade's own choices (DPoP by default, edge back channel, security profiles) are
  documented in the existing spec files and stay out of anything labelled generic.

## The harness (`conformance/`, `spec/conformance/README.md`)

The harness lands with PR #44 (branch `sdk/android-conformance-driver`); where this section names
files under `conformance/` or `android/conformance-android`, they exist once that merges.

Three tiers, and the harness is the third (`testing.md`): the scenario catalogue run against a real
staged `auth` + `central` + `edge`, once per SDK, asserting identical observable behaviour. A stub
cannot disagree with the SDK about Central's registration API, the exact `WWW-Authenticate` edge
sends or the `Idempotency-Key` auth looks up, so only this tier can confirm them.

- The stack is staged from a checkout of `versolauth/versola` (the e2e fixtures and the
  `gen-env.scala` configuration live there), or from published images through
  `conformance/stack/docker-compose.yml` for local runs. Never point the harness at a production
  tenant.
- The Android driver is `android/conformance-android` (instrumented tests, nothing published). The
  browser leg is `HttpLoginBrowser`, auth's login conversation driven over HTTP, so Custom Tabs,
  App Link delivery and the foreground-return detector are not proven by it; they belong to the
  device tier.
- Fault injection is a fixed vocabulary in the schema: `drop-response`, `force-dpop-nonce`,
  `always-demand-dpop-nonce`, `clock-skew`, `process-death`, `omit-discovery-field`,
  `network-partition`. A scenario that needs another capability adds it to the schema, to
  `spec/conformance/README.md` and to the harness mechanism table together (a TCP proxy for the
  response and nonce faults, `adb shell date` for skew, `am kill` for process death, `svc wifi` for
  partitions). A capability named in a scenario but not implemented is stated in the PR.
- The order of work in `conformance/README.md` is the plan: no-fault scenarios first, then the
  proxy, then the reference-transcript comparison, which is what turns "green" into "equivalent".
  Do not mark a scenario covered when only its happy half runs.
- The nightly run needs the `VERSOLA_CHECKOUT_TOKEN` secret; until it exists the workflow runs on
  demand only (`ci-release.md`).

## Saying what is proven

- A behaviour with no scenario that passes against a real stack is proven against stubs only. The
  PR description says so, by name: "scenario 09 not run, retry-after-dropped-response is proven
  against stubs only".
- Likewise say when a scenario ran on one platform and not the others, on one back channel and not
  both, or with `HttpLoginBrowser` in place of a real browser.
- A scenario that cannot pass is a finding. Do not loosen its assertions, drop a step or change
  `applies_to` to make the run green (`testing.md`).
