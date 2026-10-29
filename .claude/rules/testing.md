---
paths: ["**/src/test/**", "**/src/androidTest/**", "ios/Tests/**", "flutter/**/test/**", "conformance/**"]
---

# Testing Conventions

`AGENTS.md` ("Test coverage rules") says what must be tested. This file says how, and what each
kind of test is allowed to claim. Rules about the code under test are in `android-kotlin.md`,
`ios-swift.md`, `flutter.md` and `spec-conformance.md`.

## Three tiers and what each proves

| Tier | Runs where | Proves | Cannot prove |
|---|---|---|---|
| Unit | JVM (JUnit, Robolectric), `swift test`, `flutter test`, against stubs | the rule: given this input and these collaborators the SDK does X | that the real Keystore, Keychain, browser or server agree |
| Device | Emulator or simulator (`src/androidTest`, XCTest on a simulator) | the platform half: key tiers, GCM wrapping, Keystore behaviour per API level, browser and redirect delivery, process death | that a server accepts what the SDK sends |
| Conformance | Scenarios in `spec/conformance/` against a real staged provider (`versolauth/versola` for the Versola facade, a provider container under `conformance/providers/` for the generic one) | the wiring: Central's API, the exact `WWW-Authenticate`, the idempotency key, the replay detection; for the generic facade, what a real provider's discovery, login form, token endpoint and logout actually do | the browser leg when `HttpLoginBrowser` stands in for it |

- A stub cannot disagree with the code that wrote it. Every `MockWebServer` response and every
  fake collaborator is an assumption about the other side; only the conformance tier tests the
  assumption.
- Say which tier ran. A PR description lists, per tier, what ran and what did not ("unit: green;
  device: not run, no emulator; conformance: scenario 08 not run"). A tier you could not run is
  reported, never implied.
- A behaviour with no conformance scenario passing against a real stack is proven against stubs
  only, and the PR says so. Open issues #36, #37 and #39 list this by scenario for Android; keep
  those lists true when you change what is covered.

## Unit tests

- Name a test for the behaviour and its condition, in the existing style: Kotlin backtick names
  (``fun `an unparseable max_age drops that parameter rather than the whole challenge`()``), Swift
  `testRefreshWithReplayedTokenEndsInReauthenticate`, Dart `test('...')` with the same shape. Not
  `test2`.
- Every security rule has a negative test beside the positive one: wrong `state`, wrong `iss`,
  wrong `nonce`, wrong `aud`, bad signature, expired, replayed, malformed, missing. A rule with only
  a passing test is not tested. The refusal must be the specific typed error from `spec/errors.md`,
  not "some exception", and must happen before any network call where the spec says so.
- No sleeps and no real clocks. Use `kotlinx-coroutines-test` virtual time, an injected
  `clock: () -> Long`, an injected `SecureRandom`, and in Swift and Dart an injected clock. Where an
  asynchronous effect must be awaited, await the effect with a bound, never a fixed delay.
- Concurrency tests run two (or a hundred) racing callers, not one caller twice: single-flight
  refresh, coalesced results, a cancelled winner not stranding waiters. The F2 regression is 100
  concurrent `call()`s on `Dispatchers.IO` with a 401 first response, completing within a timeout.
- Stubs live at the seam (a token client, a store, a browser session), not inside the code under
  test. Assert on what the collaborator received, not only on the return value.
- Shared constants (issuer, client id, redirect URI) go at the top of the file or in the module's
  fixtures. Values are `example.com` and throwaway (`security.md`).
- HTTP is `mockwebserver3` on JVM and a `URLProtocol` stub on iOS. Never reach a real network
  from a unit test.
- Robolectric is for framework interactions in the modules that already have it (`:browser`,
  `:storage`, `:sdk`, `:oauth`, `:conformance-oauth`); do not spread it to protocol tests that run
  as plain JVM.

## Parsers facing untrusted input

Property tests (jqwik or kotest-property on JVM, the platform equivalent elsewhere) for the code
that reads attacker-controlled bytes: `AuthorizationResponseValidator.parseQuery`,
`AuthenticateChallenge.parse`, `wwwAuthenticateError`, `CredentialBlob.decode`, `Jose.derToJose`
and the ID-token parser when it exists (architecture review section 5, item 6). The property is "no
input crashes, hangs or is accepted wrongly", plus round trips and a generated malformed corpus.
`derToJose` is the case the KDoc itself says "fails one signature in every few hundred" when wrong:
a single example test cannot catch that.

## Device tests

- Run on an emulator or simulator: Keystore tiers, wrapping and unwrapping, the auth window,
  process death with the browser foreground, redirect delivery. Android: API 28 and 34 in the
  instrumented job, 36 planned. Assert the tier you read back (`KeyAttestation`), not the one you
  asked for.
- They do not need network access to a real provider; the conformance tier does.
- Browser-leg findings (F1 minimize versus cancel, F10 redirect hardening) are provable only here,
  with UI Automator on a real Custom Tab or Auth Tab. Do not claim them from a unit test.

## Conformance tests

- A test or driver step that implements a scenario carries its id (`@Scenario("12")` once the
  annotation exists, a comment naming `12-process-death-browser` until then), so a coverage matrix
  can fail when a scenario has no test at any tier (architecture review section 5, item 2).
- A scenario's assertions are the test's assertions. Do not weaken, drop or reorder them to get a
  green run, and do not mark a scenario covered on its happy half alone.
- Fault injection uses the capability vocabulary in `spec/conformance/schema.json`; the mechanism
  per capability is in `conformance/README.md`. A new fault is added there, not improvised in a test.
- Transcripts compare with the reference client's, ignoring `jti`, `iat` and nonce values.
- A generic-facade scenario (`facade: [oauth]`) runs in `android/conformance-oauth` against the
  provider container, through `ProviderProxy`; it is skipped, never failed, when no provider is
  configured, and the PR says which provider it ran against.

## Keeping tests honest

- A test that fails is a finding, not an obstacle. Do not delete it, `@Ignore` / `XCTSkip` / `skip:`
  it, loosen an assertion, widen a timeout or add a retry to make it pass; find out whether the code
  or the test is wrong, and say which in the report.
- A flaky test is a bug to be fixed at its cause (usually an unawaited asynchronous step, a shared
  static, an unfrozen clock), not rerun until green. If CI shows a flake, report it with the log
  rather than re-running silently.
- Do not make production code test-aware (a `testMode` flag, a loosened check, a public wiring type)
  to ease a test; add an `internal` seam, or the opt-in marker, instead (`android-kotlin.md`).
- When you could not run a tier, the final report says so (`AGENTS.md`, Definition of Done).
