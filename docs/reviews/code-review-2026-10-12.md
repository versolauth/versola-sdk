# Android SDK — adversarial code review, 2026-10-12

Scope: `android/` modules `core`, `dpop`, `storage`, `browser`, `okhttp`, `sdk` on branch
`sdk/android-conformance-driver`, read as the **working tree** at HEAD `eeb3e2b6` plus the
uncommitted edits present at review time (`SessionCoordinator.kt` adds `offline_access` to
`login()`, `VersolaConfiguration.kt` admits `http://` loopback issuers, `Versola.configure()`
gains a `browser` parameter, `settings.gradle.kts` includes `:conformance-android`). Several of
these files were being edited while the review ran; line numbers below are from the tree as it
stood when the report was written. Normative references: `spec/state-machine.md`,
`spec/errors.md`, `spec/retry-policy.md`, `spec/server-dependencies.md`,
`spec/conformance/*.yaml`. Server behaviour was checked against `versola-main`
(`TokenEndpointController`, `OAuthTokenService`, `NativeService`, `NativeController`,
`NativeAuthClient`, `EdgeService`, `RevocationController`, `LogoutController`, `util/Dpop.scala`,
`edge/dpop/DpopVerifier.scala`, `V0004__tokens_tables.sql`).

Baseline: all unit suites pass (core 208, dpop 32, okhttp 26, storage 27, browser 11, sdk 9)
and `apiCheck` passes for every module with the working tree as reviewed. Three findings were
confirmed with throwaway tests (deleted afterwards; the tree was left as found).

## 1. Criteria

| # | Criterion | What was looked for |
|---|---|---|
| C1 | Concurrency / coroutines | Single-flight correctness under cancellation on every path; `Mutex` critical sections; `runBlocking` inside OkHttp; DataStore one-instance rule; process-wide singletons (`RedirectDispatcher`, `AUTHORIZE_LOCK`, `ABANDONED_STATES`); `accessToken()` cache vs refresh; `MutableStateFlow` conflation; exceptions in `finally`; `Dispatchers.IO` starvation. |
| C2 | Security | Secret leakage via logs/`toString`/exceptions/URLs; zeroization claims vs reality; constant-time compares; `state`/`iss`/`nonce`; exported `VersolaRedirectActivity` and intent injection; `singleTask`+`CLEAR_TOP`; nonce cache keying and default-port normalisation; clock-skew learning; `htu` vs server `normalizeHtu`; `ath`; JWK canonical form and DER→R‖S; AES-GCM IV; backup exclusion. |
| C3 | Protocol vs server | Form encoding, header names, both nonce-challenge shapes, `BoundRenewal` echo, `Idempotency-Key` semantics, `/native/*` contract incl. `iss` trailing slash, 404 handling, endpoint fallback order, error-code → category mapping. |
| C4 | Lifecycle | Process death mid-browser / mid-rotation / mid-logout; cold-start redirect delivery; `ForegroundReturnDetector` false positives/negatives; pending-request expiry; what `logout()` guarantees. |
| C5 | Resource handling | OkHttp `Response` closed on every path; atomic file writes; temp files; Keystore handles. |
| C6 | Error taxonomy | Every thrown error is a `VersolaError` of the category `spec/errors.md` assigns; no raw exceptions crossing the public API or the OkHttp interceptor boundary. |
| C7 | API / ABI | `explicitApi`, `.api` dumps in sync, nullability, parameter ordering, defaults. |
| C8 | Tests | Coverage gaps, flaky patterns, tests that pin implementation rather than behaviour. |

Only findings whose code path was read end to end are reported as findings. Anything not
fully confirmed is marked **plausible** with what would confirm it.

## 2. Findings

Severity: Critical (exploitable or data-destroying without preconditions) > High (wrong
outcome on a realistic path, no attacker needed) > Medium (wrong outcome on a narrower path or
under a configuration not yet exposed) > Low > Nit.

No Critical findings.

### High

#### H1. A winner cancelled during the lazy restore wedges every later refresh in the process — confirmed

`android/core/src/main/kotlin/kz/versola/sdk/core/SessionCoordinator.kt:241-297`

The flight is handed out under the mutex (`refreshFlight.pending = it; winner = true`), but the
first thing the winner does *outside* any `try` is

```kotlin
            val priorState = flow.sessionState.first()      // line 276
            flow.setState(SessionState.Refreshing)
            val result = try {                               // line 279
```

`flow.sessionState.first()` runs `AuthorizationFlow.ensureRestored()`, which does disk I/O
(`pendingStore.load()`, `hasStoredGrant()`), so it is a suspension point. If the winner's job is
cancelled there — the first `accessToken()` of a process is exactly the call that performs the
restore, and a `lifecycleScope` that is torn down on rotation is a routine way to cancel it —
the `CancellationException` propagates past `endFlight`. `refreshFlight.pending` stays set to a
`CompletableDeferred` nobody will ever complete. Every subsequent `refresh()` / `accessToken()`
in the process takes the `!winner` branch and `flight.await()`s forever; every `httpClient()`
call blocks in `runBlocking` forever.

Reproduced with a probe `hasStoredGrant` that suspends on a gate: cancel the winner while it is
inside `first()`, release the gate, then a second `refresh()` under `withTimeoutOrNull(2_000)`
returns null and no token request was made.

Related: `endFlight(flight, result)` on the success/failure path (line 295) is also outside
`NonCancellable`. `Mutex.lock()` only suspends (and only then throws on a cancelled job) when
contended, so this window is narrow, but the consequence is identical. The cancel path already
wraps `endFlight` in `NonCancellable` (line 288); the other two paths should too.

Fix:

```kotlin
// take the flight only after the restore, and never leave it unretired
val priorState = flow.sessionState.first()       // before the withLock that creates the flight
...
val result = try {
    flow.setState(SessionState.Refreshing)
    Result.success(performRefresh())
} catch (e: CancellationException) {
    withContext(NonCancellable) { flow.setState(priorState); endFlight(flight, null) }
    throw e
} catch (e: Throwable) {
    Result.failure(e)
}
withContext(NonCancellable) { endFlight(flight, result) }
return result.getOrThrow()
```

If `first()` must stay after the flight is created, wrap the whole stretch from the `withLock`
to `endFlight` in one `try/finally` that retires the flight with `null` under `NonCancellable`.

#### H2. `logout()` does not fence an in-flight refresh: the grant is re-persisted and the session comes back after the wipe — confirmed

`SessionCoordinator.kt:421-441` (`logout`), `:338-351` (steps 2–3 of `performRefresh`),
`:392-393`.

`logout()` never touches `refreshFlight`. Sequence: a refresh is in flight (its request already
sent) → `logout()` sets `LoggingOut`, revokes, opens the browser, `wipe()`s
(`credentialStore.clear()`, `cachedAccessToken = null`, `completeLogout()` → `Unauthenticated`)
and returns → the refresh response arrives → `performRefresh` runs
`credentialStore.save(it, issued.idToken)` (line 342), `cachedAccessToken = Cached(...)`
(392) and `flow.setState(SessionState.Authenticated)` (393).

Outcome: after `logout()` returned and the app observed `Unauthenticated`, the refresh token is
back on disk, an access token is cached and served by `accessToken()` until it expires, the
state flips to `Authenticated`, and the next cold start restores `Authenticated` via
`hasGrant()`. Under DPoP `BoundRenewal` the token written back is the very one that was just
revoked; under bearer it is the successor rotation. On a shared device this is a ghost session
after sign-out, which `spec/state-machine.md` ("Reaching `Unauthenticated` locally is
unconditional") and scenario 18 forbid.

Reproduced: refresh gated inside `TokenClient.refresh`, `logout()` completes
(`refreshToken == null`, state `Unauthenticated`), gate released → store events are
`[clear, save]`, state `Authenticated`, `currentAccessToken()` non-null. The refresh is
triggered automatically by the interceptor on any API call, so "user taps Sign out while a
screen is loading" is the real-world trigger. The same race exists between an `invalid_grant`
wipe and a concurrent `login()` exchange, in the other direction (less harmful).

Fix: give the coordinator a wipe epoch and check it before persisting, under the flight mutex,
and have `logout()` wait for (or cancel) the flight:

```kotlin
private val epoch = AtomicLong()
// performRefresh(): capture `val startedIn = epoch.get()` before the request;
// before step 2:
refreshFlight.mutex.withLock {
    if (epoch.get() != startedIn) throw VersolaError.Reauthenticate(GrantRejected) // already wiped
    issued.refreshToken?.let { credentialStore.save(it, issued.idToken) }
    credentialStore.savePendingRotation(null)
    cachedAccessToken = Cached(issued, elapsedMillis())
}
// wipe(): epoch.incrementAndGet() before credentialStore.clear(), and
// logout(): refreshFlight.mutex.withLock { refreshFlight.pending }?.let { runCatching { it.await() } }
```

Also do not publish `Authenticated` from `performRefresh` when the epoch moved.

#### H3. Non-`IOException` throwables escape `VersolaInterceptor` and kill the process on enqueued calls — confirmed

`android/okhttp/src/main/kotlin/kz/versola/sdk/okhttp/VersolaInterceptor.kt:52,63-64,174,185-189`;
`android/dpop/src/main/kotlin/kz/versola/sdk/dpop/DpopProofFactory.kt:75-76`;
`android/dpop/src/main/kotlin/kz/versola/sdk/dpop/DpopNonce.kt:24`.

`translating {}` wraps only `VersolaError`. Everything else thrown inside `runBlocking` leaves
`intercept()` as a non-`IOException`, which — exactly as `VersolaHttpException`'s own KDoc
explains — OkHttp's `AsyncCall.run` rethrows onto the dispatcher thread, where Android's
default handler ends the process. Concrete sources, all reachable:

1. `DpopProofFactory.htu()` and `Origin.of()` call `java.net.URI(url)` on
   `request.url.toString()`. OkHttp's query encode-set leaves `{ } | ^ \`` ` raw, `java.net.URI`
   rejects them. `Request.Builder().url("https://edge/api/search?filter={\"a\":1}")` — a JSON
   filter in a query string is an ordinary REST idiom — produces
   `URISyntaxException: Illegal character in query`. Reproduced end to end against a
   `MockWebServer`: the exception escapes `execute()` with `isIOException=false`; for
   `enqueue()` this is a crash. (`addQueryParameter` happens to encode `{`, so only
   string-built URLs trigger it, which is the common way apps build them.)
2. `KeystoreDpopKey.sign()` → `Signature.initSign(key)` after `destroy()` ran concurrently
   (logout racing an API call) throws `InvalidKeyException`/`KeyPermanentlyInvalidatedException`
   (`KeystoreDpopKey.kt:79-87`, `72-77`).
3. `DataStoreCredentialStore` throwing `IllegalStateException` (see H4) or any `IOException`
   from DataStore on `accessToken()`.

Fix (both halves):

```kotlin
// VersolaInterceptor.intercept
return try {
    runBlocking { authenticated(chain, request) }
} catch (e: VersolaHttpException) { throw e }
  catch (e: IOException) { throw e }
  catch (e: Throwable) {
    throw VersolaHttpException(VersolaError.Configuration(
        VersolaError.Configuration.Detail.InvalidConfiguration("unexpected failure: ${e::class.java.name}"), e))
}
// DpopProofFactory.htu / Origin.of: never hand a full URL to java.net.URI
private fun htu(url: String): String = URI(url.substringBefore('#').substringBefore('?')).let { ... }
```

Better still, take `okhttp3.HttpUrl` (already on the ABI of `:core`) in `DpopProofSource` and
build `htu` from `scheme`, `host`, `port`, `encodedPath`.

#### H4. `Versola.configure()` twice in a process violates DataStore's one-instance rule; the second instance throws `IllegalStateException` on every credential access — confirmed by reading

`android/sdk/src/main/kotlin/kz/versola/sdk/Versola.kt:217,291-294`;
`android/storage/src/main/kotlin/kz/versola/sdk/storage/DataStoreCredentialStore.kt:39-47,80`.

Each `configure()` builds a new `DataStoreCredentialStore` over
`noBackupFilesDir/versola/credentials`. `androidx.datastore:datastore-core 1.2.1` (the pinned
version; the guard string "There are multiple DataStores active for the same file" is present
in `datastore-core-okio-jvm-1.2.1.jar`) refuses a second active instance per file: the first
`dataStore.data.first()` of the second instance throws `IllegalStateException`. That is
`hasGrant()` → `ensureRestored()` → the first `sessionState` collection, and `login()`'s
`credentialStore.save`. The failure is not a `VersolaError`, so it also violates C6 and, via
`accessToken()` inside the interceptor, is one of H3's sources.

"Configure in `Activity.onCreate`" is the most common integration pattern on Android and
re-runs on every rotation. The conformance driver on this very branch
(`conformance-android/.../Scenario01HappyPathTest.kt:79`) calls `Versola.configure()` per
`@Test` in one instrumented process and `deleteRecursively()`s the directory under the previous
instance's live DataStore; the second scenario class added will hit this.

Fix: make the credential store (and the pending store, which shares the key alias) a
process-wide singleton keyed by canonical file path:

```kotlin
public class DataStoreCredentialStore private constructor(...) {
    public companion object {
        private val instances = HashMap<String, DataStoreCredentialStore>()
        public fun forFile(file: File, keyProvider: CredentialKeyProvider): DataStoreCredentialStore =
            synchronized(instances) { instances.getOrPut(file.canonicalPath) { DataStoreCredentialStore(file, keyProvider) } }
    }
}
```

and use it from `configure()`; alternatively cache the whole wiring of `configure()` per
`(context, issuer, clientId)` and document that a second call returns the same instance.

### Medium

#### M1. Exported `VersolaRedirectActivity` delivers any intent's `data` unchecked

`android/browser/src/main/kotlin/kz/versola/sdk/browser/VersolaRedirectActivity.kt:36`;
`RedirectDispatcher.kt:28-31`; `ForegroundReturnDetector.kt:54`.

`intent?.data?.let { RedirectDispatcher.deliver(it.toString()) }` — the intent filter belongs to
the integrator, but an *explicit* intent (`setClassName(pkg, "kz.versola.sdk.browser.VersolaRedirectActivity")`)
bypasses filters entirely, and the activity is `exported="true"` with no permission. Any
installed app can therefore, with no user interaction:

- during a live `login()`, deliver `anything://x?state=junk` → reaches the validator →
  `Configuration(StateMismatch)`, pending request wiped (`AuthorizationFlow.kt:416-421`), the
  real redirect that follows is then "someone else's" — a reliable login DoS;
- set `redirectDelivered = true` (line 29 of the dispatcher) so the detector never reports
  the user closing the tab (`ForegroundReturnDetector.kt:54`): `login()` hangs holding
  `AUTHORIZE_LOCK`, which also blocks `logout()`'s `endSession`;
- bring the app to the foreground at will via the launch intent at line 42.

A redirect with the right `state` cannot be forged (256-bit), so this is availability, not
confidentiality. Fix: validate before delivering. The browser module does not know the
configuration, so register the expected redirect(s) with the dispatcher at `configure()`
time and drop everything else:

```kotlin
internal object RedirectDispatcher {
    @Volatile var accepted: List<RedirectUri> = emptyList()   // set by Versola.configure
    fun deliver(uri: String) {
        val parsed = runCatching { URI(uri) }.getOrNull() ?: return
        if (accepted.none { it.matches(parsed) /* scheme, host, port, path prefix */ }) return
        ...
    }
}
```

Also override `onNewIntent` (see L5).

#### M2. `CLEAR_TOP` relaunch destroys the activity awaiting `login()` when it is not the task root

`VersolaRedirectActivity.kt:42-46`.

`getLaunchIntentForPackage(...)` + `FLAG_ACTIVITY_CLEAR_TOP` finishes every activity above the
launcher activity. A login started from `SettingsActivity` on top of `MainActivity` (the normal
shape of an "account" screen) has its `lifecycleScope` cancelled: `flow.authorize` takes the
`CancellationException` branch (`AuthorizationFlow.kt:265-276`), remembers the state as
abandoned, and the redirect that was just delivered sits in the channel. If the app's next
action is `login()` again, `CustomTabsAuthorizationSession.authorize` **drains** that redirect
(`CustomTabsAuthorizationSession.kt:33`) and the completed authorization is lost; the user
sees a second browser. Only an app that knows to call `resumePendingAuthorization()` from
`MainActivity` recovers. The KDoc's "lands the user back where they started" is not what
`CLEAR_TOP` does.

Fix: bring the existing task forward without clearing it — `singleTask` already placed this
activity in the app's task, so finishing is enough; if a foregrounding intent is wanted, use
`FLAG_ACTIVITY_NEW_TASK or FLAG_ACTIVITY_REORDER_TO_FRONT` targeting the task's root without
`CLEAR_TOP`, or `ActivityManager.moveTaskToFront(taskId, 0)`. Document that `login()` should be
launched from a scope that survives the calling activity (`viewModelScope`/application scope)
or that `resumePendingAuthorization()` must be called from the root activity.

#### M3. Failed code exchange leaves `Authorizing` and a pending request that can never complete; a cold-start `resumePendingAuthorization()` then blocks forever holding `AUTHORIZE_LOCK`

`SessionCoordinator.kt:153-175` (documented as deliberate), `AuthorizationFlow.kt:301-320`.

`login()` → `exchange` throws (`invalid_grant`, `invalid_client`, `Recoverable` network) → the
pending slot stays, state stays `Authorizing`. The redirect was already consumed and the code
spent. On the next cold start `ensureRestored()` reports `Authorizing`; the app does what the
spec tells it (`resumePendingAuthorization()`), which calls `browser.awaitPendingRedirect()`
under `AUTHORIZE_LOCK` (line 318) with no redirect ever coming and no timeout — the ten-minute
bound is checked only on entry. `login()` from a "Sign in" button now blocks on the same lock
until the app cancels the resume job. `spec/state-machine.md` has `Authorizing →
Unauthenticated: authorization error`; the pending request's lifetime exists for the browser
leg, not for a spent code. The unit test `a failed exchange leaves the pending request exactly
where authorize left it` pins the wrong behaviour.

Fix: in `SessionCoordinator.login()` catch the exchange failure, `flow.abandonLogin()` (clear
the slot, set `Unauthenticated`, or revert to the prior state per M4), rethrow. Additionally
bound `resumePendingAuthorization()`'s wait to the request's remaining lifetime
(`withTimeoutOrNull(MAX_AGE - age) { awaitPendingRedirect() }` → `PendingRequestExpired`).

#### M4. A step-up or re-authorization over a live session publishes `Unauthenticated` on cancel/failure while the grant is intact; `StepUpRequired` is never entered

`AuthorizationFlow.kt:400-403,416-421`; `Versola.kt:143`; `SessionState.kt:28`.

`stepUp()` is `login()`; a user cancel or a validator failure during it sets
`state.value = Unauthenticated` and wipes the pending slot, although `hasStoredGrant()` is true,
`cachedAccessToken` keeps being served and the next cold start restores `Authenticated`. UI
bound to `sessionState` shows a login screen over a live session. Separately, nothing in the
code base ever sets `SessionState.StepUpRequired` — the interceptor throws `StepUp` and the
state stays `Authenticated` — so `Authenticated → StepUpRequired → Authorizing` from the spec
is unreachable, and scenario 14's state assertions cannot pass. The seven-state contract says
these are "sub-states of holding a grant; UI should not treat them as signed out".

Fix: `authorize()` captures the entered-from state; cancel/failure in `complete()` reverts to
it when `hasStoredGrant()` (`Authenticated`), otherwise `Unauthenticated`. Have the
coordinator expose `enterStepUp()` that the interceptor's `insufficient_user_authentication`
branch calls (through `AccessTokenSource`) before throwing.

#### M5. `FilePendingAuthorizationStore.load()` swallows `UnlockRequired` and destroys the slot

`android/storage/src/main/kotlin/kz/versola/sdk/storage/FilePendingAuthorizationStore.kt:48-57`.

`catch (e: Exception) { clear(); null }` also catches `VersolaError.Recoverable(UnlockRequired)`
from `HardwareKeyProvider.unwrap` (`HardwareKeyProvider.kt:75-76`). Under
`UnlockPolicy.OnAppUnlock`, a cold start more than 300 s after the last OS authentication
runs `ensureRestored()` → `pendingStore.load()` → unlock window elapsed → the pending request
of a login killed mid-browser is **deleted**, and the restore settles `Unauthenticated`
(scenario 12 regressed). "Out of reach" is treated as "gone", the distinction
`DataStoreCredentialStore.unwrapping` gets right. Not reachable through `Versola.configure()`
today (it always constructs `HardwareKeyProvider()` with `UnlockPolicy.None`), so Medium.

Fix: `catch (e: VersolaError) { throw e }` before the generic catch, and let `ensureRestored()`
map `UnlockRequired` to `Locked` rather than `Unauthenticated`.

#### M6. A permanently invalidated storage key is never regenerated: after an enrolment change every `login()` fails forever

`HardwareKeyProvider.kt:45-52,73-81,83-90`.

`wrap()` calls `cipher.init(ENCRYPT_MODE, key())`; `key()` returns the existing Keystore entry
whatever its state. After a biometric enrolment change (OnAppUnlock keys are
`setUserAuthenticationRequired(true)`, invalidated by enrolment by default) `init` throws
`KeyPermanentlyInvalidatedException`, mapped to `Reauthenticate(CredentialsInvalidated)`. The
coordinator wipes — but `wipe()` deletes the blob, not the key — and the user signs in again;
`login()` → `credentialStore.save` → `wrap` → the same exception. Permanent until app data is
cleared. Same preconditions as M5 (latent until the facade exposes `OnAppUnlock`).

Fix: on `KeyPermanentlyInvalidatedException` (and on `UnrecoverableKeyException` from
`getEntry`) in `wrap`, `deleteEntry(alias)` and regenerate — nothing encrypted under the old key
is readable anyway; and have `CredentialStore.clear()` delete the storage key alongside the
blob so a logout starts the next user on a fresh key.

#### M7. Retry budgets are per refresh, not per application operation; discovery has none — spec deviation

`SessionCoordinator.kt:328` (`retryPolicy.newBudget()` inside `performRefresh`),
`AuthorizationFlow.kt:246`, `Discovery.kt:133-152`.

`spec/retry-policy.md`: "a refresh triggered by a 401 … [is] inside that operation's budget";
scenario 19 asserts "A refresh triggered by a 401 is counted inside the originating call's
budget, not given a budget of its own" and "at most four [requests] in total". Today an
application call that 401s triggers `renewAccessToken()` → a fresh `RetryBudget` (3 per origin
/ 4 total) on top of the call and its replay, so one operation can emit up to 1 + 4 + 1
requests. Conversely discovery is retried by nobody: a single 5xx on
`/.well-known/openid-configuration` fails `login()` with `Recoverable(attempts=1)`, although
the spec lists discovery under "requests the SDK originates" that are retried.

Fix: thread a `RetryBudget` through `AccessTokenSource` (`accessToken(budget)`), create it in
the interceptor per `intercept()` and in `login()`/`refresh()` per public call; wrap
`DiscoveryService.metadata()`'s `client.fetch` in the caller's budget.

#### M8. 408 and 429 from the token endpoint / `/native/start` / revocation are mapped to `Configuration`, not retried

`TokenClient.kt:383-441` (`rejected`: only `>= 500` is `Network`), `:318-357` (`revoke`),
`BackChannel.kt:260-296`.

A 408 or 429 carries no OAuth body, so `rejected` falls into
`Configuration(TokenRequestRejected("(no OAuth error in a HTTP 429 response)"))` — terminal and
"fail loudly in debug builds". `spec/retry-policy.md` lists 408 among what is retried and says
429 "falls through to the generic `Recoverable` path and is retried under the budget". Fix:
`if (status == 408 || status == 429 || status >= 500) throw Recoverable(Network(...))` in all
three places.

#### M9. `Versola.call()` + `runBlocking` + inner `Dispatchers.IO` can starve the IO pool — plausible

`Versola.kt:193`, `VersolaInterceptor.kt:52`, `TokenClient.kt:288`, `DataStoreCredentialStore`
(DataStore scope is `Dispatchers.IO`).

`call()` runs `execute()` on `Dispatchers.IO`; the interceptor then `runBlocking`s on that IO
thread; the refresh it waits for needs another IO thread (`withContext(Dispatchers.IO)` for the
token request, DataStore's own scope for `savePendingRotation`). `Dispatchers.IO` is capped at
64 (max(64, cores)); 64 concurrent `call()`s (or the equally common app pattern
`withContext(Dispatchers.IO) { client.newCall(r).execute() }`) all parked in `runBlocking`
leave no thread for the one refresh they are waiting on. The interceptor's KDoc argues this
cannot happen because OkHttp's dispatcher caps `enqueue` only — true, but `call()` moves the
blocking onto the IO pool. Would be confirmed by 65 parallel `versola.call()`s against a 401
with a gated refresh. Fix: run SDK-internal blocking work on a private dispatcher
(`Dispatchers.IO.limitedParallelism(4)` creates threads beyond the 64 cap) or make
`TokenRequestExecutor` call `execute()` inline when already on a blocking thread.

### Low

#### L1. Zeroization claims overstate what is zeroed

`TokenClient.kt:481-493` ("every array that ever held a byte of it is zeroed"),
`TokenResponse.kt:13-17`, `DataStoreCredentialStore.kt:82-85,98-101`.

What is not zeroed: okio `Buffer` segments that `body.toRequestBody()` writes through (pooled,
recycled unzeroed); the TLS layer's buffers; the response `payload` `String` and
`TokenResponsePayload.refreshToken` `String` on every login and refresh (the `TokenResponse`
KDoc admits this; the `FormBody` KDoc does not); `rawIdToken()` / `pendingRotation()` returning
`String`s. The request-side discipline is real and correct; the documentation should state the
boundary rather than "every array". No code change beyond wording, unless `pendingRotation()`
is made bytes.

#### L2. Quadratic regex on untrusted-length `WWW-Authenticate`

`AuthenticateChallenge.kt:26`. `([A-Za-z_][A-Za-z0-9_.\-]*)\s*=` on a long header with no `=`
backtracks O(n²) per start position; a 64 KiB header from an application behind edge (edge
forwards application 401s verbatim) costs seconds on the OkHttp thread. The source is a
deployment's own backend, so Low. Fix: possessive quantifier `[A-Za-z0-9_.\-]*+` or cap the
header length before matching. `wwwAuthenticateError` in `BackChannel.kt:321` is anchored on
the literal `error` and is fine.

#### L3. Raw exceptions outside the `VersolaError` contract

- `FilePendingAuthorizationStore.kt:38` `error(...)` → `IllegalStateException` from `login()`.
- `KeystoreDpopKey.kt:91` `load() ?: generate()`: `KeyStoreException`, `UnrecoverableKeyException`,
  `ClassCastException` (`certificate.publicKey as ECPublicKey`) from `jkt()`/`proof()`.
- `DataStoreCredentialStore.hasGrant()` IO failures surface from `sessionState` collection.
- `Jose.derToJose` `require` → `IllegalArgumentException` (unreachable with a conforming
  provider, but still raw).
- `SessionCoordinator.tokenOrigin()` / `originOf()` → `URISyntaxException` on malformed
  metadata URLs (discovery validates presence, not syntax).

Fix: map Keystore/IO failures at the module boundary to `Configuration(InvalidConfiguration)`
or `Recoverable(Network)` as appropriate; validate endpoint URLs in `ProviderMetadata.validate`.

#### L4. `ForegroundReturnDetector` false positive on any foreground return while the tab is open

`ForegroundReturnDetector.kt:46-57`. A notification tap, an incoming call ending, or the user
switching back via Recents resumes the host activity while the Custom Tab is still alive →
`UserCancelled` → pending request wiped. The user then finishes in the still-open tab; that
redirect is "stale" and drained by the next `authorize()`. Inherent to the heuristic; worth
stating in the KDoc and in `BrowserOutcome.UserCancelled`, and worth keeping the slot for a
grace period (e.g. 30 s) after a detector-reported cancel so a redirect that follows can still
be matched by `resumePendingAuthorization()`.

#### L5. `VersolaRedirectActivity` has no `onNewIntent`

With `launchMode="singleTask"`, a redirect that arrives while an instance exists (the window
between `startActivity(launch)` and `finish()`, or two tabs redirecting back to back) is
delivered to `onNewIntent`, which is not overridden — the redirect is dropped. Add
`override fun onNewIntent(intent: Intent) { intent.data?.let(RedirectDispatcher::deliver); finish() }`.

#### L6. Double-checked `restored` / `expiredOnRestore` without `@Volatile`

`AuthorizationFlow.kt:107-108,454-488`. `restored` is read outside `restoreLock` and written
inside; `expiredOnRestore` is written under `restoreLock` and read under `AUTHORIZE_LOCK`. No
happens-before edge connects the two locks or the plain read. On ARM a reader can see
`restored == true` before `state.value` — publishing a brief `Unauthenticated` on cold start,
the exact thing scenario 12 forbids. Mark both `@Volatile`.

#### L7. `logout()` with a failing `credentialStore.clear()` reports `Unauthenticated` with the grant still on disk

`SessionCoordinator.kt:459-473`: `wipe()`'s `finally` runs `completeLogout()` even when
`clear()` threw; the next cold start restores `Authenticated`. Either retry the clear (it is a
DataStore `updateData`) or set `Locked`/`Authenticated` and surface the failure.

#### L8. Uncommitted edits: dead duplicate `isLoopback`, cleartext issuer in release builds, unconditional `offline_access`

`VersolaConfiguration.kt` (working tree) adds `isLoopback` to both companions; the one in
`RedirectUri.Companion` is unused (warning under `-Werror`). Allowing
`http://{localhost,127.0.0.1,[::1],10.0.2.2}` issuers is a debug affordance shipped in the
release artifact; gate it behind a constructor flag or `ApplicationInfo.FLAG_DEBUGGABLE`.
`SessionCoordinator.login()` now sends `scopes + "offline_access"` unconditionally; the server
does require it for a refresh token (`OAuthTokenService.scala:646`), but a client registration
lacking it now fails every login with `invalid_scope` rather than the previous
`TokenResponseMalformed("refresh_token is missing")` — a clearer error either way, but the
behaviour change should be in the changelog and `VersolaConfigurationTest` only covers the
loopback half.

#### L9. Shared `ClockSkew` learned from every origin — plausible

`DpopProofFactory.kt:60-61`, `ClockSkew.kt:31`, `Versola.kt:287-291` (one factory, by design).
`observe()` is called for every response the interceptor sees, including an application
response behind edge if edge forwards its `Date`. A backend with a skewed clock would then
poison `iat` for proofs to auth and edge, costing one `invalid_dpop_proof` retry per call until
an edge/auth response re-learns. Confirming needs a look at whether `EdgeService`'s proxy path
preserves the upstream `Date`. Fix regardless: learn the offset only from responses whose
origin is auth's or edge's (the interceptor knows `edgeBaseUrl`; the token clients know the
`htu`), or keep one offset per origin.

### Nit

- `VersolaInterceptor.kt:205` `HttpUrl.origin()` always prints the port (`https://h:443`),
  `Origin.of` normalises it away: `NonceLoop.origin` strings differ by path.
- `BackChannel.kt:309-311` `nativeEndpointUrl` uses form encoding for a path segment (`*`
  unencoded, `~` → `%7E`); harmless against this server, but use a path-segment encoder.
- `AuthorizationFlow.encode` duplicates `AuthorizationRequest.encode`.
- `Versola.call()` builds a new `OkHttpClient` per call (`httpClient()`); cache it.
- `SessionCoordinator.tokenOrigin()` names auth's origin for the budget under
  `BackChannel.Edge`, where the request goes to edge; the per-origin cap is mis-attributed.
- `FileProviderMetadataCache.save` / `FileNativeEndpointsStore.save` swallow a failed
  `renameTo` silently (the pending store raises); no `fsync` on any of the three — acceptable
  for caches, worth a comment.
- Two `HardwareKeyProvider()` instances share one alias (`Versola.kt:293,328`); a first-use
  race in `key()` can generate the alias twice, orphaning whichever blob was wrapped first.
  Generate once under a lock in the companion.

## 3. Checked and found correct

- **Single-flight coalescing** (`refresh(rejected, onlyIfStale)`): the re-read under the lock
  closes the stale-verdict race; `WeakHashMap` keyed by store identity is correct for the
  stated purpose (two coordinators, one store) and cannot leak (values hold no reference to
  keys). Abandoned-winner takeover via `null` outcome is right.
- **Rotation slot ordering**: step 1 before send, step 2 before any caller sees the response,
  step 3 after; idempotency key = SHA-256(refresh token) reused on replay; matches
  `OAuthTokenService.resolveRetry`/`findIdempotentRetry` and `V0004__tokens_tables.sql`
  (`idempotency_key BYTEA`, no uniqueness constraint, so the same key on every DPoP
  `BoundRenewal` refresh is harmless).
- **`BoundRenewal`**: the server echoes the same `refresh_token` (`boundRenewal = Option.when(cnf.isDefined …)`);
  the SDK stores it again unchanged and tolerates omission.
- **Refresh skew** `min(30 s, expires_in/10)`, monotonic clock, `expires_in ≤ 0` = unknown,
  overflow guard at `Long.MAX_VALUE / 1000`.
- **Redirect validation order** state → iss → error → code, constant-time `state` compare
  (length folded in, empty-`b` guard), `iss` trailing-slash tolerant exactly as
  `NativeService.openBlob` compares it, duplicate parameters rejected, `URISyntaxException` and
  bad percent-escapes mapped to `Configuration`.
- **PKCE**: 32 random bytes → 43-char verifier, S256 only, no `plain`, no opt-out.
- **Both nonce shapes**: auth's `400` + JSON `use_dpop_nonce` + `DPoP-Nonce`, edge's `401` +
  `WWW-Authenticate: DPoP error="use_dpop_nonce"`; read by parameter, never scheme; one retry
  per origin per operation; a challenge with no nonce terminates. Nonce cached under the
  `htu` origin, so a relayed auth nonce lands under auth's origin and `/native/start`'s under
  edge's (scenario 23). Edge applies its own nonce policy to `/native/start` only
  (`checkOwnNonce = true` there and only there) — the SDK's model matches.
- **`htu`** = `scheme://rawAuthority + rawPath`, identical to `util.Dpop.normalizeHtu` and to
  edge's `DpopVerifier.htu` construction; `%2F` preserved; query stripped. `/native/*` proofs
  are signed for the `token_endpoint`/`revocation_endpoint` from `/native/start`
  (`authUri(native, "token"|"revoke")`), persisted across logout, with the
  `mtls_endpoint_aliases` → plain fallback in the right order. `ath` = base64url(SHA-256(ASCII))
  matches `Dpop.ath`.
- **`/token` ordering**: `verifyDpopProof` runs before the exchange, so `invalid_dpop_proof`
  and `use_dpop_nonce` do not spend the code; the SDK's one-retry-each on the exchange is safe.
  `invalid_grant` never retried; the code exchange has no transport retry.
- **`/native/*` contract**: form fields (`code,state,iss,blob`; `grant_type,refresh_token`;
  `token,token_type_hint`), no `client_id` (edge appends it), 404 → `EdgeClientUnknown`,
  `Idempotency-Key` and `DPoP` are the forwarded headers, `NativeStart` validated for the five
  required fields, bearer answer refused under `requireHardware`.
- **Edge 401 shapes**: bare, `Bearer error="insufficient_user_authentication" acr_values max_age`,
  `DPoP error="invalid_dpop_proof"`, `DPoP error="use_dpop_nonce"` — all four read correctly;
  403/404/429/5xx passed through; one refresh + one replay; non-replayable bodies not replayed;
  the cache is re-checked before a forced renewal.
- **Revocation**: `token`, `token_type_hint`, `client_id`, no proof, 2xx is the whole answer,
  missing `revocation_endpoint` skipped; `RevocationController` accepts a public client by
  `client_id` in the form.
- **Logout URL**: `id_token_hint`, `post_logout_redirect_uri`, random `state`, acknowledgement
  = redirect carries the same `state` (constant-time); revoke before browser; wipe
  unconditional on cancellation and browser failure (modulo H2).
- **Redirects not followed** on every token-shaped client; 3xx reported without `Location`.
- **Response bodies** are closed on every path (`.use {}` in the token clients; explicit
  `close()` before every throw and loop iteration in the interceptor).
- **Error-code → category** table matches `spec/errors.md` for `/token`, `/authorize`,
  `/native/*` and edge (apart from 408/429, M8).
- **DER → R‖S**: sign byte stripped, leading zeros stripped then re-padded to 32, long-form
  length read, trailing bytes rejected; canonical JWK is `{"crv","kty","x","y"}` in
  lexicographic order with fixed-width coordinates (leading-zero coordinates covered by a test).
- **Keys**: DPoP key `setUserAuthenticationRequired(false)`, StrongBox → TEE fallback,
  attestation read back from `KeyInfo`; storage key AES-256-GCM, Keystore-generated IV
  (`setRandomizedEncryptionRequired(true)`), 12-byte IV prefix, 128-bit tag; the two aliases
  are distinct; files under `noBackupFilesDir`.
- **No secret in logs or `toString`**: `AuthorizationGrant`, `TokenResponse`, `AccessToken`,
  `CodeVerifier` redact; `PendingAuthorizationRequest.toString` prints `state` only; logger
  messages carry `e.message` of `VersolaError`s, which never embed a token.
- **`lowercase()`/`uppercase()`** are the locale-invariant Kotlin stdlib versions throughout; no
  `toLowerCase()`.
- **No nested-comment hazard** in KDoc (everything compiles under `-Werror`-free settings; no
  `/*` inside comment bodies).
- **`explicitApi()`** on every module; `apiCheck` green for all six modules; the `sdk.api` dump
  was momentarily stale against the uncommitted `browser` parameter and was updated during
  the review window — it is in sync now.
- **Retry policy bounds** refused rather than clamped, `NaN` rejected, full jitter, wall-clock
  ceiling on a monotonic clock, exhaustion carries attempts and elapsed.

## 4. Test gaps worth closing

1. **Cancellation at every suspension point of `refresh()`** — a test that cancels the winner
   during `sessionState.first()` and during `endFlight`, then asserts a second `refresh()`
   completes (H1). The existing cancellation tests all cancel inside `performRefresh`.
2. **`logout()` / `invalid_grant` racing an in-flight refresh or exchange** — assert the store
   stays empty and the state stays `Unauthenticated` after the late response lands (H2).
3. **Interceptor exception hygiene** — a `DpopProofSource` that throws a non-`VersolaError`
   and a request URL containing `{`/`|`; assert the failure is a `VersolaHttpException`
   (H3). Today only `VersolaError` sources are tested.
4. **Two `Versola.configure()` calls in one Robolectric process** followed by
   `sessionState.first()` and `login()` on the second instance (H4); the current suite
   constructs one per test with a fresh `TemporaryFolder`, which hides the rule.
5. **`VersolaRedirectActivity` with an explicit intent carrying a foreign URI** — assert it is
   not delivered (M1); `onNewIntent` delivery (L5).
6. **Failed exchange → state and slot** — `a failed exchange leaves the pending request exactly
   where authorize left it` asserts implementation, not the spec's `Authorizing →
   Unauthenticated: authorization error`; replace with a test of M3's expected behaviour and
   of `resumePendingAuthorization()` not blocking forever after one.
7. **Step-up state** — no test enters `StepUpRequired`; no test covers cancel during a
   `stepUp()` over a live grant (M4).
8. **`FilePendingAuthorizationStore.load` with a provider that throws `UnlockRequired`** —
   assert the slot survives (M5); and `HardwareKeyProvider.wrap` after
   `KeyPermanentlyInvalidatedException` regenerating the key (M6; instrumented).
9. **Budget sharing across a 401-triggered refresh** — scenario 19's "at most four in total"
   has no unit test; `RetryPolicyTest` tests the budget in isolation (M7).
10. **408/429 on `/token`, `/native/start`, `/revoke`** (M8).
11. **Flaky patterns**: `a stale-cache read that a concurrent refresh has already outrun …`
    relies on `Thread.currentThread().name.startsWith("caller-A")` and real threads with
    10 s latches — robust enough, but it is the only real-parallelism test and would be the
    first to go red under CI load; consider a deterministic seam (a `CompletableDeferred`
    between the cache read and the lock). `ForegroundReturnDetectorTest` and
    `CustomTabsAuthorizationSessionTest` share the process-wide `RedirectDispatcher`; they
    drain in `@Before` but a redirect delivered by a failing test still leaks into the next
    class run in the same JVM — drain in `@After` too.
12. **Zeroization tests assert the request path only**; add a documentation-level note or a
    test that `pendingRotation()`'s `String` is accepted as a known copy (L1).
13. **No unit test for `AuthenticateChallenge` with a very long header** (L2) or for
    `Origin.of`/`htu` on OkHttp-canonical URLs containing `{ } | ^` (H3).
