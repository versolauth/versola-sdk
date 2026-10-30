# Code Review Guide

Instructions for a reviewer (human or Claude) of a pull request to versolauth/versola-sdk. This
repository ships the mobile SDKs (Android today, iOS and Flutter next) that sit inside other
companies' apps. Their sign-in, refresh and logout code runs on every device of every user of every
integrator, and it holds the refresh token and the device key. A mistake here is a vulnerability or
a lockout in an app we do not control and cannot hot-fix: a leaked token stays leaked, a wrong
default is compiled into binaries in the store, and a fix reaches users only as fast as integrators
ship it. A server bug is an incident; an SDK bug is an incident multiplied by every app that has not
updated yet.

Project rules live in `AGENTS.md` and `.claude/rules/*.md`; the normative behaviour lives in `spec/`
(`state-machine.md`, `errors.md`, `retry-policy.md`, `server-dependencies.md`,
`conformance/*.yaml`). This file does not repeat them; it says **how to review** against them and
what to weigh first. When a rule or a spec section is violated, cite the file.

## Principles

1. **Review the diff against the base branch, not the description.** Read the changed code and the
   code around it. Verify claims ("tested", "no behaviour change", "internal only") against the
   source and the regenerated `.api` dump.
2. **Report only what you can point at.** Every finding names a `file:line`, a concrete failing
   scenario (input/state -> wrong result, leaked token, hung caller, lost sign-in), and a suggested
   fix. No "consider", no style taste a formatter already decides.
3. **Rank by blast radius.** Token and key safety, data loss and the public contract first; then
   concurrency and platform lifecycle; then conformance; readability and tests after. Do not bury a
   blocker under ten nits; cap nits at three.
4. **Read the whole path, not the hunk.** A new suspension point or lock is judged by every caller
   that can reach it (interceptor, facade, app coroutine scope, process restore), not by how small
   the diff is. Follow the call from the public entry point down to the platform store.
5. **Silence is fine.** If nothing is wrong, say "No findings" and list what you checked. Do not
   invent issues to look thorough.

## Review order

Go in this order and stop to flag a blocker as soon as you find one.

0. **Shape and public surface**: is this the right, smallest thing to expose (section 0)? Do it
   first; a wrong shape makes the line review moot
1. **Security**
2. **Correctness and concurrency**
3. **Platform behaviour** (Android, iOS, Flutter)
4. **Spec and conformance**
5. **Tests**
6. **Readability, docs, observability**

## 0. Is this the right shape and the right public surface?

Do this before reading the code line by line. Every public type, function, parameter, default, enum
case and error case is a semver promise: on Android `./gradlew apiCheck` and the committed
`android/*/api/*.api` dumps hold it, on iOS the public Swift API of the SPM products in
`Package.swift`, in Dart the exported package API. Before 1.0 the surface can only shrink: removing
what an app compiled against costs every integrator (`0.MINOR.PATCH`, breaking changes bump MINOR).
Prefer the change that adds the least; an `internal` type or one behind the `@VersolaInternalApi`
opt-in marker is free to change, a public one is not.

### Method

1. **State the problem in one sentence**, from the linked issue, not from the diff.
2. **Find what already serves it.** Search before judging: the facade (`Versola`, `OAuthClient` once
   #46 lands), `VersolaConfiguration`, `RetryPolicy`, `BackChannel`, `VersolaError`, and the sibling
   platform that already solved it. Never conclude "nothing exists" unsearched.
3. **List the alternatives**, always including "extend the existing option or sealed type
   additively" and "no new surface (derive it from discovery, the response, the state machine, or an
   internal decision)". Compare on: public surface, persisted state, platform divergence,
   compatibility risk, test and doc cost, security strength. Security is a veto, not a weight.
4. **Choose the cheapest shape that is not weaker.** If the PR did not, say which alternative and
   what it saves ("removes a public parameter", "removes a dump entry"). If the PR chose the same
   shape, say "alternatives considered, current shape kept" and why, in one line.

### Extend, do not add, when they are coupled

A new public function, option, module or persisted field is justified only by a real difference. If
the new behaviour has the **same** caller, lifecycle, failure semantics and security properties as
an existing one, extend it:

- An optional parameter whose default keeps today's behaviour, or a new case on an existing sealed
  type (`VersolaError.Configuration.Detail`, `Recoverable.Cause`, `BrowserOutcome`), rather than a
  second function repeating the discovery, proof and retry logic. A new sealed case breaks an app's
  exhaustive `when`/`switch`: say so, and check `spec/errors.md` for the category.
- A field on the existing persisted record rather than a second store with the same lifecycle (one
  persistence order, one wipe path); the existing retry budget, nonce cache and single-flight lock
  (a second lock around the same refresh is how two refreshes run at once); one of the four error
  categories (`Recoverable`, `Reauthenticate`, `StepUp`, `Configuration`).

### A new surface is justified when the difference is real

- **Different caller**: an app, a test harness, the conformance driver. Only the first is public;
  the others use the opt-in marker or a test-fixtures module.
- **Different contract owner**: standard behaviour (RFC 9449, 9207, 7636, 9470) stays RFC-shaped;
  Versola-only behaviour (edge `/native/*`, `BackChannel.Edge`) belongs to the Versola facade, not
  the generic OAuth facade.
- **Different security property**: misuse must be unrepresentable, not documented: a redacting
  secret type, a closed enum or a sealed result, not a boolean the app can flip.
- **Platform reality**: Android needs an `Activity` for Auth Tab, iOS a presentation anchor, Flutter
  a channel. Name the platform reason; "idiomatic" alone is not one.
- **Incompatible shape**: it cannot be added without a breaking change to the existing one. Do not
  overload either: a mode boolean or a result whose meaning depends on which optional fields are set
  is one function doing two jobs.

### Red flags

- Wiring types made public so a test or the conformance driver can reach them (`AuthorizationFlow`,
  `SessionCoordinator`, `HttpTokenClient` in `core.api`, 855 lines of wiring at the review of
  2026-10-12); do not add to it.
- A public accessor that hands out key or token capability: `Versola.dpop` returns a
  `DpopProofFactory`, so any caller can mint a proof for any method and URL with the session key, a
  bigger escape hatch than `accessToken()`. A public `KeystoreDpopKey.Companion.destroy(alias)` is
  the same class.
- A second way to do what an option already does (a `configure()` parameter next to a
  `VersolaConfiguration` field, a second entry point that skips `login()`'s persistence order).
- A public parameter whose only consumer is the conformance driver, or a cleartext allowance beyond
  the one documented rule (`http` to `localhost`, `127.0.0.1` and `[::1]` only; `security.md`):
  `10.0.2.2` or any other host, or a switch for it, shipped in the release artifact.
- The same concept shaped differently on Android, iOS and Dart for no platform reason (a sealed
  error on one platform, a string on another). A public type exposing a third-party type (OkHttp
  `Request`, Pigeon classes) puts that library's version on our ABI: `api(...)` in a
  `build.gradle.kts` is the tell.
- A second implementation of a rule the spec or the sibling platform already has (redirect
  validation, retry budget): the two will drift. Reuse, or flag that they differ.

### How to report it

A shape finding is **BLOCKER** when it breaks the existing public API without the approval in
`AGENTS.md` "Ask Before" or exposes key or token capability, **MAJOR** when it duplicates an
existing option or adds a public surface that is not needed (permanent and costly to remove),
**MINOR** when the cost is internal and reversible. Respect a decision the linked issue already took
and argued: raise the alternative once, as a question, and do not block unless the code shows the
premise is wrong. An alternative must be concrete and no weaker than the PR's. Confirm the dump:
public surface changes come with `./gradlew apiDump` in the same commit and a line in the PR
description; a hand-edited dump, or a `*.api` diff the source does not explain, is a finding.

## 1. Security

Fail closed. Anything that weakens a check is a blocker without an explicit, justified exception
(`AGENTS.md` "Ask Before"). Keys are non-exportable in hardware where available; refresh tokens and
keys never leave the platform store, never cross a bridge, never appear in logs, `toString()`,
errors, metrics, intents or crash reports; no client secret is representable.

- **Key material and storage classes.** The DPoP key lives in the Keystore (StrongBox, then TEE) or
  the Secure Enclave, non-exportable, not user-gated by default; the tier reported is the tier read
  back. Android files live under `noBackupFilesDir` so a backup cannot replay a refresh token
  elsewhere; iOS uses `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, not synchronizable. Ask
  what a stolen backup or an iCloud restore can replay; a weaker class is a blocker.
- **Browser.** System browser only (Auth Tab or Custom Tab, `ASWebAuthenticationSession`). A
  `WebView` or `WKWebView` is unreachable from every public API: `BrowserAuthorizationSession` takes
  a URI. Ephemeral browsing is opt-in; it breaks passkeys.
- **Redirect validation, before any network call.** `state` in constant time (length folded in, no
  early exit), then `iss` (RFC 9207; mandatory under `BackChannel.Edge`), then `error`, then `code`;
  duplicate parameters rejected. `VersolaRedirectActivity` is exported: an explicit intent from any
  app reaches it, so it checks scheme, host and path against the configured redirect, or
  `anything://x?state=junk` aborts a live login and pins `AUTHORIZE_LOCK`.
- **ID-token validation is never optional.** `iss`, `aud`/`azp`, `exp` and the `nonce` the SDK
  generated, on login and on every refresh that returns an `id_token`; `auth_time` under `max_age`;
  signature or a documented limitation. On 2026-10-12 the SDK persisted a nonce and never compared
  it. Claim handling without these checks is a blocker.
- **PKCE and client secret.** S256 only, 32 bytes from `SecureRandom` /
  `SystemRandomNumberGenerator`, no `plain`, no opt-out. No client secret is representable
  (`invalid_client` on a `fapi2` tenant means `BackChannel.Edge`, not "add a secret").
- **DPoP proof scope.** `htm`/`htu` match the server's normalisation (scheme, host, port, raw path;
  query and fragment stripped); `ath` is base64url SHA-256 of the token; nonces are cached per
  origin, one retry per origin per operation. Build `htu` from the parsed URL: a full string given
  to `java.net.URI` throws on `?filter={"a":1}` and the throw escaped the interceptor. Learn clock
  skew only from token and edge origins, or a backend with a wrong clock poisons `iat`.
- **Refresh token single use.** Persist the pending rotation, send, persist the new token before any
  caller sees it, clear the slot. Idempotency key reused on replay; `invalid_grant` never retried
  and wipes; a refresh returning after `logout()` writes nothing.
- **Secrets and bridges.** Types carrying a secret redact in `toString()`; no token, code, verifier
  or `Authorization`/`DPoP` header value in a log line, exception, `VersolaError` payload, metric
  label or URL. KDoc zeroization claims state the real boundary (okio buffers and `String` copies
  are not zeroed). Nothing credential-shaped crosses the Flutter bridge. No real secrets, client ids
  or issuers anywhere: `example.com`.
- **Intents and links.** Explicit intents inside the SDK; verified App Links, and Universal Links
  with the `webcredentials` service on iOS (`applinks` alone fails); a custom scheme only under
  `BackChannel.Auth`, with a warning.
- **Dependencies and CI.** A new dependency, workflow permission, unpinned action or untrusted
  input interpolated into `run:` needs approval. Recommend the `security-review` skill here.

## 2. Correctness and concurrency

- **Single-flight refresh.** Concurrent callers share one refresh and one result. Check every
  suspension point between "flight handed out" and "flight retired": a winner cancelled while it
  restores state from disk (`flow.sessionState.first()` outside the `try`) leaves a
  `CompletableDeferred` nobody completes, and every later `refresh()` waits forever. `endFlight`
  runs under `NonCancellable` on success, failure and cancel.
- **Fencing.** `logout()` and the `invalid_grant` wipe fence a refresh or exchange in flight (a wipe
  epoch checked under the flight lock before any write). Otherwise the late response re-persists the
  grant and publishes `Authenticated` after the app saw `Unauthenticated`: a ghost session the spec
  forbids.
- **Cancellation and persistence order.** A cancelled caller strands no waiter, holds no lock and
  does not abandon a pending request whose code is spent; persistence runs under `NonCancellable`;
  `CancellationException` is rethrown, never mapped to a `VersolaError`. For every step ask what is
  on disk if the process dies here: pending request before the browser opens, token before it is
  returned, pending request wiped only after the refresh token is durable, pending rotation before
  the request is sent. A reordering loses a sign-in or replays a spent token.
- **Blocking and dispatchers.** No `runBlocking`, `Thread.sleep` or `DispatchSemaphore.wait` on a
  dispatcher the awaited work needs. Known failure: `Versola.call()` runs `execute()` on
  `Dispatchers.IO`, `VersolaInterceptor` does `runBlocking`, and the refresh it waits on needs
  `Dispatchers.IO` too; 64 concurrent calls on a stale token hang the process. SDK-internal blocking
  work goes on one dispatcher the coordinator owns (`limitedParallelism(n)`).
- **Exceptions at the boundary.** Expected failures are `VersolaError` values of the category
  `spec/errors.md` assigns; nothing else leaves a public function. A non-`IOException` thrown in an
  interceptor on an enqueued OkHttp call ends the app's process, so `VersolaInterceptor` translates
  every `Throwable` (`URISyntaxException`, `InvalidKeyException`, DataStore
  `IllegalStateException`). A `catch (e: Exception) { clear(); null }` must not swallow
  `UnlockRequired`: out of reach is not gone.
- **Single instances.** DataStore allows one active instance per file and `Versola.configure()` in
  `Activity.onCreate` re-runs on every rotation: two calls must not yield two stores over
  `noBackupFilesDir/versola/credentials`, and the storage alias is generated once under a lock or
  the first wrapped blob is orphaned. Flags read outside the lock that wrote them (`restored`) are
  `@Volatile`; Swift shared state is an `actor`.
- **State machine.** Transitions match `spec/state-machine.md`: seven states, no others.
  `StepUpRequired` was specified and asserted by scenario 14 and never entered by any code: a state
  with no producer is a finding. A cancelled or failed step-up over a live grant returns to
  `Authenticated`; a failed code exchange settles `Unauthenticated`, or a cold-start
  `resumePendingAuthorization()` waits forever under the authorize lock.
- **Retries bounded by construction** (`spec/retry-policy.md`). One operation, one `RetryBudget`: a
  refresh triggered by a 401 and its replay sit inside the originating call's budget; discovery is
  retried under it; 408 and 5xx on SDK-originated requests are retried and 429 is not terminal.
  Maxima are refused, not clamped; `invalid_grant` and the code exchange are never retried. Expiry
  uses a monotonic, injected clock.
- **Caches expire.** Discovery and native-endpoint caches carry `fetchedAt` and refetch once on a
  rejection discovery could explain; one that never expires misses a rotated `token_endpoint`.

## 3. Platform behaviour

Platform lifecycle facts the protocol code cannot see; judge against the platform it runs on.

### Android

- **Custom Tab minimize versus cancel.** "Host resumed without a redirect" is not a user cancel.
  Since Chrome 122 a Custom Tab can be minimized to picture-in-picture while the host resumes and
  the tab stays alive; a notification tap resumes it too (`ForegroundReturnDetector`). Wiping the
  pending request on that signal destroys what the tab's later redirect needs. The resume heuristic
  is a fallback: surface `Recoverable(UserCancelled)` but keep the pending request for its
  ten-minute window. The primary path is Auth Tab (`AuthTabIntent`, androidx.browser 1.9+, Chrome
  137+, gated on `isAuthTabSupported`; results `RESULT_OK`, `RESULT_CANCELED`,
  `RESULT_VERIFICATION_FAILED`, `RESULT_VERIFICATION_TIMED_OUT`); a fallen-back Auth Tab reports
  `RESULT_CANCELED` on close, so the redirect activity still carries the code.
- **Activity and task lifecycle.** `FLAG_ACTIVITY_CLEAR_TOP` on the launcher finishes every activity
  above it: a `login()` started from a non-root activity loses its scope and the delivered redirect
  is drained by the next `authorize()`. A `singleTask` redirect activity overrides `onNewIntent`.
  Exported activities set transitions to none (TapTrap). Recovery after rotation or process death is
  `resumePendingAuthorization()`; API 36 is in the instrumented matrix when browser behaviour
  changes.
- **Keystore tiers.** StrongBox, then TEE, then software, read back from `KeyInfo`;
  `StrongBoxUnavailableException` falls back. `KeyPermanentlyInvalidatedException` after a biometric
  enrolment change deletes and regenerates the key, or every `login()` fails forever.
  `UnlockPolicy.OnAppUnlock` is reachable from `configure()`.
- **API 26 floor and R8.** No API above 26 without a `Build.VERSION` guard; a new reflective use
  ships consumer rules and keeps the R8 sample green.

### iOS

- **`ASWebAuthenticationSession` cancel semantics.** `canceledLogin` is one code for user and system
  cancel; pair it with app state (foreground wipes, backgrounded or inactive keeps the pending
  request, per `spec/state-machine.md`). The session is retained, the anchor is on the main actor,
  ephemeral is off by default.
- **Platform floor.** The https callback (`Callback.https(host:path:)`) needs iOS 17.4, while
  `Package.swift` says `.iOS(.v16)` and an edge-fronted client has https redirects only, so
  `BackChannel.Edge` has no browser leg on 16.0 to 17.3. Changing the floor is an "Ask Before".
- **Keychain.** `AfterFirstUnlockThisDeviceOnly`, not synchronizable; write the new item before
  deleting the old (`SecItemUpdate`); `errSecInteractionNotAllowed` is `UnlockRequired`, never a
  sign-out; `SecureEnclave.isAvailable` decides the software fallback and the reported tier.
- **Swift 6 and actors.** `-strict-concurrency=complete` in CI; value types are `Sendable`; no
  `@unchecked Sendable`. Actors are reentrant: re-check state after every `await` (the single-flight
  is the textbook case). One `AsyncStream` per observer. The app owns background refresh
  (`BGAppRefreshTask`); the SDK schedules nothing.

### Flutter

- **The plugin is a binding, not a third implementation.** No protocol logic, retry, validation or
  state transition in Dart. Nothing credential-shaped crosses the channel. Pigeon host APIs return
  sealed results, so the four error categories and `acrValues`/`maxAge` arrive typed and a `StepUp`
  never degrades to a `PlatformException`. Generated code is never hand-edited or exposed, and the
  state stream carries the seven states and no others.

## 4. Spec and conformance

- **Spec first.** A behaviour change edits `spec/state-machine.md`, `errors.md` or `retry-policy.md`
  in the same PR or earlier. Code that deviates without a spec edit is MAJOR either way: the code or
  the spec is wrong. An unavoidable platform deviation is recorded in the spec.
- **A scenario exists.** A new rule gets a `spec/conformance/NN-*.yaml` scenario valid against
  `schema.json` (`python3 tools/validate-scenarios.py`; `spec.yml` runs it). Every state and error a
  scenario names exists in `SessionState` and `VersolaError` on every platform; a case added on one
  platform only is a divergence.
- **Provider matrix, not `when (issuer)`.** Provider-specific behaviour is discovery-driven and
  documented as a limit: no branch on an issuer string or host in the protocol core.
- **Error mapping** follows `spec/errors.md` code by code: one category per code, `invalid_grant` is
  `Reauthenticate` and never retried, parse the `error` value and not the scheme, and 403, 404, 429
  and 5xx from edge are returned as the responses they are.
- A behaviour with no scenario is "proven against stubs only" in the PR (section 5).

## 5. Tests

`AGENTS.md` "Test Coverage Rules" and `.claude/rules/testing.md` are the bar. Three tiers, and a
rule proven only against stubs is not proven.

- **Unit** (`./gradlew test`, `swift test`, `flutter test`): stubs, MockWebServer, Robolectric.
  **Device** (emulator, simulator): Keystore, Keychain, Custom Tab and Auth Tab, process death, the
  `instrumented` job. **Conformance** (`conformance/`, a real staged provider). A change ships tests
  at the tier that can prove it, or the PR names the missing tier, why, and the follow-up.
- **Tests fail for the right reason.** Assert outcomes and interactions (what was sent, persisted,
  in which order), not "does not throw". A test pinning the implementation against the spec is a
  finding: "a failed exchange leaves the pending request where authorize left it" asserted the
  opposite of `Authorizing -> Unauthenticated: authorization error`.
- **Negative security tests** beside every positive one: wrong `state`, `iss` or `nonce`, a foreign
  redirect through the exported activity, `invalid_grant` not retried, a second `use_dpop_nonce` not
  retried, no token in any log line or `toString()`.
- **Concurrency and cancellation.** Cancel the refresh winner at every suspension point (state
  restore, `endFlight`), not only inside the token request, and assert a second `refresh()`
  completes. Race `logout()` against an in-flight refresh and assert the store stays empty. 100
  concurrent `call()`s on `Dispatchers.IO` with a first 401 finish within a timeout. Two
  `configure()` calls, then `login()` on the second. A throwing proof source and a URL containing `{
  } | ^` surface a `VersolaHttpException`. Prefer a deterministic seam to real threads.
- **Lifecycle tests** for process death at each persistence step (scenarios 12 and 13), cold-start
  redirect delivery, and minimize and resume at the device tier. No fixed `sleep`, no real clock, no
  shared state (`RedirectDispatcher` is process-wide: drain it in `@Before` and `@After`).
- **No weakened, skipped or deleted tests** to get green. The PR does not say "tested" for what
  was not run; the device and conformance tiers often cannot run locally, and it says so.

## 6. Readability, docs, observability

- One purpose per PR, no unrelated refactors. Commit messages are short imperative sentence case
  without `feat:` prefixes. Protocol logic stays in the core module, platform I/O behind a small
  interface (`CredentialKeyProvider`, `BrowserAuthorizationSession`, `DpopKey`), the facade holds
  none. No boolean parameters that fork behaviour. Comments explain *why*.
- **Docs on the public surface.** KDoc, DocC and dartdoc on every public symbol, written for the
  app's action: what to do on each error category, which scope or thread, what is persisted, what is
  not guaranteed. A doc the code cannot back is a finding (`login()` "lands the user back where they
  started" while `CLEAR_TOP` destroys the activity; "every array is zeroed").
- **Observability.** The SDK emits no analytics. `VersolaLogger` carries categories and
  `VersolaError` messages, never a token, code, verifier, header value or user id; no logging in
  loops or on the success path. The state stream lets an integrator tell signed out from locked and
  from step-up needed without catching exceptions.
- The PR description states what changed, tests per tier, the API dump change, the spec change,
  any gap left and, for a new public surface, why an existing option could not be extended. A
  change an integrator will notice (an added scope, a changed default) is called out in the PR
  description so the release notes can carry it.

## Output format

Lead with a verdict: **Approve**, **Approve with nits**, or **Request changes**, one sentence why.
List findings most severe first, each as:

```text
[BLOCKER|MAJOR|MINOR|NIT] path/to/File.kt:123 - short title
Why it matters: concrete scenario (input/state -> wrong behaviour; or "64 parallel call()s hang").
Fix: the smallest change that resolves it.
```

Severity:

- **BLOCKER**: a key or token leak (log, `toString`, intent, bridge, backup), a loosened or skipped
  validation (`state`, `iss`, `nonce`, ID token, PKCE, redirect), a breaking public API change
  without approval, a deadlock or stranded waiter, data loss, a persistence-order bug that loses a
  sign-in on process death, a wipe a late response undoes, CI will fail (`apiCheck`, lint).
- **MAJOR**: wrong behaviour in a reachable lifecycle case (minimize, rotation, cold start, second
  `configure()`), a public surface that duplicates an existing option or is wider than needed, a
  missing negative security test, a missing tier without a follow-up, code that deviates from the
  spec, an API shape that diverges between platforms for no platform reason, a raw exception
  crossing a public boundary.
- **MINOR**: maintainability, naming, a missed reuse, a doc that overstates, an internal and
  reversible cost.
- **NIT**: taste; at most three, and only if nothing above them is open.

Add a one-line **Shape** note after the verdict: the alternatives you weighed (section 0) and
whether the PR's shape is kept or which one is cheaper and why.

End with a short **Checked, no issues** list (areas you verified) and a **Not verified** list (what
you could not run or judge from the diff: emulator and simulator tiers, the conformance run, a real
provider, a physical device), so the author knows the review's limits.

## Do not flag

- Formatting that a formatter decides, or import order.
- Generated files beyond confirming they were not hand-edited: `android/*/api/*.api` (confirm
  `./gradlew apiDump` regenerated them and they match the source change), Pigeon output, lockfiles.
- Pre-existing problems the PR does not touch (mention separately as a follow-up).
- Hypothetical scale problems: the SDK runs on one device for one user. N+1, throughput and fan-out
  concerns are not findings.
