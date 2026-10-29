---
paths: ["android/**"]
---

# Android / Kotlin

Copy a neighbouring file of the same kind before writing a new one. The KDoc in this repository
explains why a choice was made; keep that habit, a non-obvious decision without its reason is a
trap for the next reader. Security rules are in `security.md`, test conventions in `testing.md`.

## Toolchain

- Gradle 9.7.1 (`android/gradle/wrapper`), JDK 17 (`JavaVersion.VERSION_17` in every module, Temurin
  17 in CI), Kotlin 2.4.20, AGP 9.4.1, `minSdk = 26`, `compileSdk = 36`. The versions are declared
  in `android/build.gradle.kts` and each module's `build.gradle.kts`; change one in every module
  together, and ask first to lower `minSdk` or raise it.
- Libraries declare no `targetSdk` (AGP would force consumers to match it); target 36 is the app's
  decision. Do not add one.
- `android/gradle.properties` sets `android.builtInKotlin=false` and `android.newDsl=false`, and
  every module applies `org.jetbrains.kotlin.android` explicitly. This is deliberate: AGP 9's
  built-in Kotlin has no working integration with `kotlinx-binary-compatibility-validator`
  (Kotlin/binary-compatibility-validator#312, KT-83410), and without the opt-out `apiCheck` applies
  cleanly and checks nothing. Do not "modernise" those properties or the plugin lines; the
  architecture review (F9) asks for a CI guard that fails when `apiCheck` ran zero tasks.
- Dependency versions are literals in the module files today, pinned and shared by value
  (`okhttp:5.4.0` in `:oauth-core` and `:okhttp`, `kotlinx-coroutines-test:1.11.0` everywhere). OkHttp
  stays at 5.4.0 because 5.5.0's AAR declares `minCompileSdk=37`; the comment in
  `android/okhttp/build.gradle.kts` says when to revisit. A new dependency needs approval.

## Commands (run from `android/`)

```bash
./gradlew assemble test lint apiCheck       # what android.yml's build job runs, in this order
./gradlew :storage:testDebugUnitTest        # one module, debug variant
./gradlew apiDump                           # after any public API change; commit the result
./gradlew :dpop:connectedDebugAndroidTest   # device tier: needs an emulator (AVD) or device
```

The maintainer's Mac has JDK 17 and the Android SDK under `~/Library/Android/sdk`; an AVD exists
for API 36. If you cannot start an emulator, say the device tier was not run (`testing.md`).

## Modules and direction

- Direction: `:oauth-core` (plain `kotlin("jvm")`, package `versola.oauth.core`) is the protocol
  engine and has no internal dependency; `:core` (package `versola.sdk.core`, the edge back channel
  and the errors only edge produces), `:dpop`, `:storage` and `:browser` depend on `:oauth-core`;
  `:okhttp` on `:oauth-core` and `:dpop`; the two facades sit on top: `:sdk` (Versola, on `:core`
  too) and `:oauth` (generic, `OAuthClient`, package `versola.oauth`, never on `:core`)
  (`android/settings.gradle.kts`, ADR 0001). The two drivers, `:conformance-android` (instrumented,
  the Versola facade against a staged stack) and `:conformance-oauth` (Robolectric, the generic
  facade against a provider container), depend on their facade and publish nothing. `:storage` and `:browser` never depend on each other;
  the facade is the one place that sees both. A new edge in this graph needs a reason in the PR.
- `:oauth-core`, `:core` and `:okhttp` contain no `android.*` import, and
  `.claude/hooks/check-core-purity.sh` fails on one. `:oauth-core` knows nothing about Versola:
  no edge, tenant, security profile or Versola endpoint. A facade reaches it through its seams
  (`AuthorizationStarter`, `TokenClient`, `BrowserAuthorizationSession`, the stores,
  `DpopProofSource`, `PendingAuthorizationRequest.extension`, the `Extension` case of each error
  detail, `RefreshTokenPolicy`, `IdTokenValidator`). A Versola behaviour that cannot be a seam
  lives in `:core`, never in `:oauth-core`. `:oauth` sends only what a standard defines: no
  `Idempotency-Key`, no `offline_access` added, bearer by default.
- Versola-specific code (`BackChannel`, `EdgeNativeTokenClient`, native endpoints, mTLS aliases)
  depends on generic code, never the reverse. Behaviour the core shows that a generic provider
  would reject is a bug (README, "Portability").
- Every module applies `explicitApi()`: public declarations spell out visibility and return types.
  Everything that is not API is `internal`.

## Public API and the binary-compatibility validator

- `kotlinx-binary-compatibility-validator` is applied in every module and the dumps live in
  `android/<module>/api/<module>.api`. Run `./gradlew apiDump` and commit the dump in the same PR
  as every public change. Never hand-edit a `.api` file; the guard hook denies it.
- Every public type, parameter, default and error case is a semver promise (`0.MINOR.PATCH`,
  breaking changes bump MINOR, `ci-release.md`) and can only shrink before 1.0. Prefer a new case of
  an existing sealed type, an option on an existing config type or an `internal` seam over a new
  public type. A boolean that forks behaviour, wiring made public for a test and a second way to do
  what an option already does are red flags.
- Wiring types (collaborators, executors, stores, clients) stay `internal` or sit behind the
  opt-in marker (`@VersolaInternalApi`, a `@RequiresOptIn(level = ERROR)` annotation, architecture
  review F6); the conformance driver opts in, apps cannot without saying so. Do not expose a
  capability that mints proofs or deletes keys (F6: `Versola.dpop`, `KeystoreDpopKey.destroy`).
- `BrowserAuthorizationSession` stays URI-only. That contract is what keeps a `WebView`
  unrepresentable (`security.md`).
- KDoc on every public symbol, with what the app does in it. No `@Suppress("EXPLICIT_API")` to dodge
  `explicitApi()`.

## Coroutines and concurrency

- No `runBlocking` on a dispatcher the awaited work also needs. F2: the interceptor's
  `runBlocking` on `Dispatchers.IO` while the refresh path does `withContext(Dispatchers.IO)`
  deadlocks at 64 concurrent callers. Prefer suspend-first paths and `Call.enqueue` bridged with
  `suspendCancellableCoroutine`; where blocking is unavoidable (an OkHttp interceptor), the work it
  waits on runs on a dispatcher it cannot starve, and the KDoc says the caller blocks.
- Persistence runs in `withContext(NonCancellable)`: a token that came back from the server is
  saved even if the caller was cancelled, and a cancelled winner must not strand the callers
  coalesced behind it.
- Refresh is single-flight: one request in flight, callers share its result, the rotation slot is
  persisted before the request and the new token before it is returned (`spec/state-machine.md`,
  scenarios 08, 10, 13).
- State is a `Flow` (`SessionState`), never a callback. Do not expose `MutableStateFlow`.
- Time comes through an injected `clock: () -> Long` and randomness through an injected
  `SecureRandom` parameter (`RetryPolicy`, `SessionCoordinator`, `AuthorizationFlow`, `Pkce`), so
  tests need no sleeps (`testing.md`). A new component takes the same seams rather than calling
  `System.currentTimeMillis()` inline.
- Main-thread work: key generation (StrongBox in particular) and Keystore I/O never run in
  `configure()` or on the caller's main thread.

## Browser and redirect

- Authorization uses Auth Tab (`androidx.browser`, `AuthTabAuthorizationSession` through the
  transparent `VersolaAuthTabActivity` trampoline, since the activity-result API needs one) first,
  with Custom Tabs as the fallback (`CustomTabsAuthorizationSession`). The foreground-return
  heuristic exists only in that fallback: Chrome's minimize button resumes the host app while the
  tab lives, so "resumed without redirect" is not a reliable user cancel (F1). Do not add logic
  that wipes the pending request on a bare resume, and do not extend the heuristic to the Auth Tab
  path, whose result code is the signal. `ephemeral` is best effort (one warning when the provider
  lacks it), never a security check.
- The redirect activity is reached by explicit intent. Verified App Links are preferred; a custom
  scheme works but logs a warning, since any app can register it (F10). The redirect activity stays
  exported only as far as the manifest merge snippet needs, with transitions overridden to none.
- Never start the integrator's activities with implicit intents or put credentials in an intent
  extra.

## Tests

- JUnit 4 with `kotlinx-coroutines-test` (virtual time) and MockWebServer (`mockwebserver3:5.4.0`)
  for HTTP. No sleeps, no real network.
- Robolectric is for framework interactions (Custom Tabs launch, `KeyGenParameterSpec` per API
  level) in `:browser`, `:storage`, `:sdk` and `:oauth` (and in `:conformance-oauth`, whose tests
  need only a `Context`); `:oauth-core`, `:core`, `:dpop` and `:okhttp` stay plain JVM tests.
  Do not add Robolectric to a module that does not have it, or `isIncludeAndroidResources` with it.
- The Keystore has no JVM implementation: what the hardware does is proved on an emulator
  (`src/androidTest`, `connectedDebugAndroidTest`), API 28 and 34 in the instrumented job and API
  36 planned; the unit tier proves what key the SDK asks for. Name which tier proved what.

## Logging and R8

- No secret in logcat at any level (`security.md`). Log through the injected `VersolaLogger`, never
  `Log.d` or `println`, and nothing on the default level that scenario 01's last assertion forbids.
- Serialization is kotlinx-serialization, reflection-free, so no consumer keep rules are needed. Do
  not add `consumer-rules.pro` without the failing R8 case that justifies it, and do not use
  reflection, `org.json` or Gson. A minified sample app is the proof (F9).
