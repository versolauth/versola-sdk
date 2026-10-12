# Architecture review: Versola mobile SDKs

Date: 2026-10-12. Reviewed: `versola-sdk` at branch `sdk/android-conformance-driver` (working tree;
the review started at HEAD `eeb3e2b` and was reconciled against `d1b54c5`, which landed the
conformance driver while the review was in progress), against `versolauth/versola` at the working
tree of `versola-main`. Grounding document: issue #1 and its three addenda. Scope: the Android
implementation (`android/*`, 5,874 lines of main code, 6,716 lines of tests, 313 unit and 11
instrumented test methods, plus the 978-line `conformance-android` driver), the normative spec
(`spec/*`, 23 conformance scenarios), the iOS and Flutter placeholders, and the CI.

Every claim about the state of the art below is backed by a source that was fetched during this
review; the list is in section 6. Nothing was taken from memory.

## 1. Executive summary

The design is unusually well-founded for a 0.x SDK. The decision to make the *specification plus a
conformance suite* the shared artefact — rather than a shared code core — is the right one in 2026
and is the thing to protect. The protocol core is correct on the points most SDKs get wrong: DPoP
nonces are per origin and refreshed from every response (RFC 9449 §8.2), the pending authorization
request is persisted *before* the browser opens (the exact failure AppAuth-Android issue #104
describes and `flutter_appauth` #635 still reports in 2025), refresh is single-flight with
coalesced results, retries are bounded by construction, the refresh token is zeroed after one
request, and the error taxonomy is sealed and exhaustive. `BackChannel.Edge` is a sound answer to
FAPI 2.0 §5.1.1's exclusion of public clients.

Seven things should change before a 1.0, in this order of impact:

1. **The user-cancel heuristic is wrong on every current Chrome.** `ForegroundReturnDetector`
   reads "host activity resumed without a redirect" as a user cancel and wipes the pending
   request. Chrome 122+ lets the user *minimize* a Custom Tab to picture-in-picture; the host
   resumes, the tab stays alive, the SDK reports `UserCancelled` and destroys the slot the tab's
   later redirect needs. Auth0 hit exactly this bug (react-native-auth0 #1584) and fixed it by
   moving to Chrome's Auth Tab, which returns the redirect as an activity result and has no
   minimize button. Adopt `AuthTabIntent` (androidx.browser 1.9+, Chrome 137+) as the primary
   path and demote the resume heuristic in the Custom Tabs fallback.
2. **`VersolaInterceptor` can deadlock the process.** `runBlocking` inside an OkHttp interceptor,
   reached from `Versola.call()` on `Dispatchers.IO`, while the refresh it waits on needs
   `Dispatchers.IO` threads of its own. Sixty-four concurrent calls on a stale token will hang.
3. **`UnlockPolicy.OnAppUnlock` is unreachable** from `Versola.configure()`, so the `Locked`
   state and scenario 20 cannot be exercised through the public API; and the spec's demand that
   the app's prompt be bound to a `CryptoObject` contradicts the time-bound key it specifies
   (Android does not allow a `CryptoObject` with a key that admits `DEVICE_CREDENTIAL`).
4. **`SessionState.StepUpRequired` is never entered.** The interceptor throws `StepUp`; nothing
   sets the state. Scenario 14 would fail its state assertion the day the harness exists.
5. **The ID token is stored but never validated** — the `nonce` the SDK generates and persists is
   never compared, and `iss`/`aud`/`exp` are not checked (OIDC Core §3.1.3.7 MUSTs).
6. **The public surface is too wide to be frozen.** `Versola.dpop` hands any caller a proof
   minter for the session key — a bigger escape hatch than `accessToken()` — and `core.api` is
   855 lines of wiring types that `apiCheck` will now hold you to.
7. **There is no release engineering** — no publishing plugin, no version, no dependency
   locking or verification, unpinned actions, and binary-compatibility validation that works only
   because of an AGP opt-out that is on borrowed time.

Two larger items are correctly *not* in phase 1 but need a seam now: an attestation story
(`draft-ietf-oauth-attestation-based-client-auth-11`, Standards Track, in WGLC as of September
2026, with a `dpop_combined` mode that maps exactly onto `/native/start`), and PAR under
`BackChannel.Auth`, which the server already advertises and which turns the spec's own worst
first-run failure (scenario 17) into an HTTP error the app can see.

For phase 2 the single most consequential decision is the iOS floor: `ASWebAuthenticationSession`
only accepts an https callback on iOS 17.4+, and an edge-fronted client is registered with https
redirect URIs only, so the current iOS 16 floor cannot run the FAPI path at all. Raise it to 17.4.

## 2. What the architecture gets right

Stated once so the findings do not read as a verdict on the whole.

- **Spec-first, two native cores, thin bindings** (#1 §3). In October 2026 Kotlin Swift export is
  still Alpha ("breaking changes expected", Xcode 26.4 required; sealed-class and `Flow` →
  `AsyncSequence` support landed only in 2.4.x), and Okta's KMP-first SDK is the only major
  identity vendor that has gone that way. The rejection stands. Keeping `:core` and `:okhttp`
  free of `android.*` imports — which they are today — is what keeps the door open.
- **DPoP implementation.** `DpopProofFactory` strips query and fragment from `htu` exactly as the
  server's `Dpop.normalizeHtu` does, builds the RFC 7638 JWK canonical form once and hashes the
  same bytes, converts DER to fixed-width `R‖S` with the leading-zero cases handled, learns the
  clock offset from every `Date` header, and caches nonces per origin with default-port
  normalisation. `observe()` runs on every response, success included, which is what RFC 9449
  §8.2 asks for and what the MCP conformance suite had to fix after getting wrong.
- **Nonce loop guard and the retry budget.** The one-retry ceilings on `use_dpop_nonce` and
  `invalid_dpop_proof`, the per-operation budget, full jitter, and refusing out-of-range values
  at `configure()` instead of clamping are all correct and better reasoned than AppAuth, Auth0 or
  Okta, none of which bound retries per operation.
- **Process death.** `PendingAuthorizationRequest` persisted before the launch intent, the
  rotation slot written before the refresh request, the redirect delivered through a buffered
  channel that outlives collectors, and the "stored grant outranks a pending request" rule are
  all right. AppAuth-Android fixed its static-map version of this in 2016 (#104) and still gets
  the report in 2025 through `flutter_appauth`.
- **Single-flight refresh** with result coalescing and cancellation that hands the flight to the
  next waiter rather than failing all of them. The lock-then-recheck in `refresh(rejected,
  onlyIfStale)` and the interceptor's "did someone already refresh while I was in flight" check
  close the two classic double-rotation races.
- **Idempotency key.** Derived from the generation being spent; the server's
  `OAuthTokenService.continueRefresh` only consults it on the retired-row path, so a constant
  key under `BoundRenewal` is harmless.
- **Error taxonomy.** Four sealed categories with the instruction to the app in the type; parse
  `WWW-Authenticate` on the `error` parameter and never the scheme; convert only 401s from edge.
  This is cleaner than any of the peer SDKs reviewed.
- **Credential hygiene.** Refresh token unwrapped inside the request that spends it and zeroed;
  byte-level form body so no `String` copy; `noBackupFilesDir`; `Theme.NoDisplay` redirect
  activity with no state; `toString()` redaction on every credential-shaped type; no
  `security-crypto`.
- **`BackChannel.Edge`.** The right structural answer to FAPI 2.0 §5.3.2.1 ("shall only support
  confidential clients"): edge is the confidential client, the device key still binds every
  token, and the device never holds the PKCE verifier. Signing the proof for auth's mTLS listener
  while posting to edge is subtle and correctly reasoned.
- **The conformance plan, and now its first two scenarios.** Transcript comparison against the
  server's own reference client, fault injection by proxy, and a scenario catalogue that every
  issue cites is the strongest testing design among the SDKs compared in section 5. As of
  `d1b54c5` the Android driver (`android/conformance-android`) runs scenarios 01 and 21 green
  against a staged `auth` + `central` + `edge`, provisioning the tenant through Central and
  driving auth's login conversation over HTTP (`HttpLoginBrowser`) through the new
  `configure(browser = …)` seam. That seam is also the right shape for the Auth Tab
  implementation F1 asks for.

## 3. Findings, ranked by impact

Effort is in engineer-days for one engineer who knows the codebase. "Blocker" means: should not
tag 1.0 without it.

### F1. Custom Tab minimize is reported as a user cancel and destroys the pending request — adopt Auth Tab

**Concern.** The only signal the SDK has for "the user closed the tab" is the host app resuming
without a redirect having been delivered. Since Chrome 122 a Custom Tab has a minimize button that
puts the tab into picture-in-picture and *resumes the host app* while the tab stays alive. The SDK
then reports `Recoverable(UserCancelled)` and — per `AuthorizationFlow.complete()` — wipes the
pending request. If the user then finishes signing in inside the minimized tab, the redirect
arrives for a `state` nobody holds, and the app, which has already shown a "cancelled" UI, gets a
`Configuration(StateMismatch)` on its next `login()` only if the stale redirect is still buffered.
This is not an edge case: Chrome ships the button by default and the user has to go *past* it to
reach the close button.

**Evidence.** `android/browser/src/main/kotlin/kz/versola/sdk/browser/ForegroundReturnDetector.kt`
`onActivityResumed` (any resume after a stop, with no redirect, fires `onReturnedWithoutRedirect`);
`CustomTabsAuthorizationSession.authorize()` wires that to `RedirectDispatcher.deliverUserCancelled()`;
`android/core/src/main/kotlin/kz/versola/sdk/core/AuthorizationFlow.kt` `complete()` clears the
store on `BrowserOutcome.UserCancelled`. `spec/state-machine.md` "cancel" table describes the
heuristic as the Android definition of a user cancel.

**State of the art.** The identical bug was filed against Auth0's React Native SDK on Android 16
(react-native-auth0 #1584, "minimize PiP keeps the Custom Tab task alive while the host app
resumes") and closed in September 2026 by adopting Auth0.Android v4's Auth Tab implementation,
"which uses the Custom Tabs Activity Result API instead of inferring cancellation from app
lifecycle events". Chrome's Auth Tab (androidx.browser 1.9.0, July 2025; Chrome 137+) removes the
minimize button, delivers the redirect to an `ActivityResultCallback` as `AuthTabIntent.AuthResult`
(`RESULT_OK`, `RESULT_CANCELED`, `RESULT_VERIFICATION_FAILED`, `RESULT_VERIFICATION_TIMED_OUT`),
verifies an https redirect host through Digital Asset Links, needs no intent filter, and falls
back to a Custom Tab automatically. AppAuth-Android has an open proposal for the same (#1146,
duplicate of #1128). Auth0.Android shipped it in 4.0.0-beta.1 (May 2026) and added ephemeral
browsing on top in 4.1.0 (August 2026).

**Recommendation.**

1. Add `AuthTabAuthorizationSession : BrowserAuthorizationSession` in `:browser`. Auth Tab needs
   an `ActivityResultLauncher`, which needs an `ActivityResultCaller` — so the SDK cannot keep
   "holds no Activity" as an absolute. Two options; prefer the first:
   - an SDK-owned trampoline `VersolaAuthorizationActivity` (`Theme.NoDisplay`, `singleTask`,
     saved-state aware) that registers the launcher and finishes when the result lands, as
     Auth0's `AuthenticationActivity` does; or
   - `login()` accepting an optional `ActivityResultRegistryOwner`.
   Either way keep the persisted `PendingAuthorizationRequest`: the activity result API survives
   process death, but `state` and the verifier do not without the slot.
2. Choose by `CustomTabsClient.isAuthTabSupported()`; keep the current Custom Tabs path as the
   fallback. Note Chrome's documented quirk: when `AuthTabIntent` itself falls back, the result
   is `RESULT_CANCELED` on close, so the fallback must still use the redirect activity for the
   actual code.
3. In the Custom Tabs fallback, stop treating resume-without-redirect as terminal. Surface
   `Recoverable(UserCancelled)` to the waiting caller — the UI must unblock — but **keep the
   pending request** and let a redirect that arrives within the ten-minute window complete it via
   `resumePendingAuthorization()`. Wipe on the next `login()` or on expiry. This is a change to
   `spec/state-machine.md` ("pending request is wiped on user cancel"); the spec is the right
   place to record why the Android definition of a user cancel is weaker than iOS's.
4. Offer `setEphemeralBrowsingEnabled` as an opt-in on both paths. #1 §4's reason for refusing
   ephemeral sessions (passkeys and SSO) is correct as the default; it is not a reason to deny a
   shared-device deployment the option, and Chrome now has it (Chrome 136+).

**Effort.** 4–6 days including an instrumented test that drives the minimize button with UI
Automator. **Blocker: yes.**

### F2. `runBlocking` in the OkHttp interceptor can deadlock under load

**Concern.** `Versola.call()` runs `httpClient().newCall(request).execute()` inside
`withContext(Dispatchers.IO)`. The interceptor then calls `runBlocking { authenticated(...) }` on
that IO thread. When the token is stale, `authenticated` → `tokens.accessToken()` →
`SessionCoordinator.refresh()` → `performRefresh()` → `TokenRequestExecutor.attempt()`, which
itself does `withContext(Dispatchers.IO)`, as do `KeystoreDpopKey.sign()` and
`HardwareKeyProvider.unwrap()`. `Dispatchers.IO` is capped at 64 threads. Sixty-four concurrent
`call()`s on a stale token occupy all 64 blocked in `runBlocking`; the single refresh they are all
waiting on cannot get a thread; nothing ever completes. The in-code justification ("OkHttp's
Dispatcher caps `enqueue`d calls only") is true and irrelevant: the starved pool is the coroutine
one, not OkHttp's.

**Evidence.** `android/okhttp/src/main/kotlin/kz/versola/sdk/okhttp/VersolaInterceptor.kt:52`;
`android/sdk/src/main/kotlin/kz/versola/sdk/Versola.kt` `call()`;
`android/core/src/main/kotlin/kz/versola/sdk/core/TokenClient.kt` `attempt()`;
`android/dpop/src/main/kotlin/kz/versola/sdk/dpop/KeystoreDpopKey.kt` `sign()`;
`android/storage/src/main/kotlin/kz/versola/sdk/storage/HardwareKeyProvider.kt` `unwrap()`.

**State of the art.** The community consensus for OkHttp is a thin interceptor that only attaches
the token plus an `Authenticator` for the reactive 401 path, with one lock shared by both — but
every one of those designs blocks too; the difference is that they do not run on a dispatcher the
refresh also needs. Auth0.Android had to add "prevent DPoP replay protection error due to OkHttp
retry" (3.13.0, February 2026) — a reminder that OkHttp's own retry machinery re-enters
interceptors in ways a DPoP proof must not tolerate; the SDK's choice of an application
interceptor and `retryOnConnectionFailure` left to OkHttp is correct on that point.

**Recommendation.**

1. Make the primary path suspend-first: `Versola.call()` should obtain the token and proof
   *before* entering OkHttp (`accessToken()`, `dpop.proof(...)`), attach them, and await the call
   with `Call.enqueue` bridged by `suspendCancellableCoroutine` (OkHttp 5 ships
   `okhttp-coroutines` with `executeAsync()`), so no coroutine thread blocks. The 401 branch then
   runs as ordinary suspend code around a second `enqueue`.
2. Keep `interceptor()` for integrators with an existing client, but move every
   `withContext(Dispatchers.IO)` on the refresh path (`TokenRequestExecutor.attempt`,
   `KeystoreDpopKey.sign`, `HardwareKeyProvider.wrap`/`unwrap`, the DataStore reads) behind one
   `CoroutineDispatcher` the coordinator is given, defaulting to
   `Dispatchers.IO.limitedParallelism(4)`. That works because of a documented property of
   `Dispatchers.IO`: its `limitedParallelism` views "are not restricted by the `Dispatchers.IO`
   parallelism" — they share threads but have their own allowance — so the refresh can always
   run even when all 64 base-pool slots are held by callers blocked in `runBlocking`. Document
   that the interceptor blocks the calling thread.
3. Add a unit test: 100 concurrent `call()`s on `Dispatchers.IO` against `MockWebServer` with the
   first response 401; assert completion within a timeout.

**Effort.** 2–3 days. **Blocker: yes.**

### F3. `UnlockPolicy.OnAppUnlock` is unreachable, and the biometric contract contradicts itself

**Concern.** `Versola.configure()` has no `unlockPolicy` parameter and constructs
`HardwareKeyProvider()` twice with the default `UnlockPolicy.None`. Nothing an integrator can do
through the facade reaches `SessionState.Locked`, `Recoverable(UnlockRequired)` or scenario 20.
Separately, `spec/state-machine.md` says "The prompt must be bound to the crypto operation
(`BiometricPrompt.CryptoObject` …) rather than gating on a boolean", but the key it specifies is
`setUserAuthenticationParameters(300, AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL)`. Android's
own guidance: "If allowing fallback to device credentials (PIN/pattern/password), you cannot pass
`CryptoObject` to `authenticate()`" — and for a time-bound key the documented pattern is to catch
`UserNotAuthenticatedException`, call `authenticate(promptInfo)` *without* a `CryptoObject`, and
retry. The spec's binding requirement is correct for an auth-per-use key (`timeout = 0`), which
the spec explicitly removed. The two halves cannot both hold, and the SDK exposes no `Cipher` for
the app to bind in any case.

**Evidence.** `android/sdk/src/main/kotlin/kz/versola/sdk/Versola.kt` `configure()` (the two
`HardwareKeyProvider()` calls); `android/storage/.../HardwareKeyProvider.kt` `keySpec()`;
`spec/state-machine.md` "Authenticated → Locked → Authenticated".

**State of the art.** Android biometric docs: time-bound keys are "general data encryption, once
per validity period"; per-use keys "for high-value transactions"; `setInvalidatedByBiometricEnrollment`
defaults to true. Auth0's `SecureCredentialsManager` and Okta's biometric-backed storage both take
the app's `FragmentActivity` and present the prompt themselves — the opposite of this SDK's
"holds no Activity" choice, which is defensible but has to be documented honestly.

**Recommendation.**

1. Add `unlockPolicy: UnlockPolicy = UnlockPolicy.None` to `configure()` and thread it into one
   shared `HardwareKeyProvider` (also fixes the unsynchronised first-generation between the two
   instances; see M3).
2. Rewrite the spec paragraph: under `OnAppUnlock` the key is time-bound, so the app's prompt is
   *not* bound to a `CryptoObject`; what makes it tamper-resistant is that the Keystore enforces
   the window in hardware (`isUserAuthenticationRequirementEnforcedBySecureHardware`), not the
   prompt's return value. The `device_lock.dart` anti-pattern is still wrong, for the reason that
   its boolean gates nothing; this SDK's version gates the key, and that should be the sentence.
3. Ship a small `BiometricUnlock` helper in `:sdk` (optional dependency on `androidx.biometric`)
   that takes a `FragmentActivity`, shows the prompt with `BIOMETRIC_STRONG or DEVICE_CREDENTIAL`,
   and retries the failed operation — so integrators do not each rediscover the
   `setNegativeButtonText` / `DEVICE_CREDENTIAL` incompatibility.

**Effort.** 1 day for the parameter and spec; 2 days for the helper. **Blocker: yes** (public
API shape).

### F4. `SessionState.StepUpRequired` is defined, specified, asserted — and never entered

**Concern.** `VersolaInterceptor` throws `VersolaHttpException(StepUp(...))`; `Versola.call()`
unwraps it; nothing calls `flow.setState(SessionState.StepUpRequired)`. The state exists only in
`SessionState.kt`. The state machine says `Authenticated → StepUpRequired → Authorizing`; the
observability section says the stream carries "the seven above"; scenario 14 is the step-up
scenario. An app observing `sessionState` to drive UI will never see it.

**Evidence.** `grep -rn StepUpRequired android/*/src/main` matches only the type declaration and a
comment in `UnlockPolicy.kt`. `android/okhttp/.../VersolaInterceptor.kt` "insufficient_user_authentication"
branch. `spec/state-machine.md` transitions table.

**Recommendation.** Either enter the state (the interceptor has `AccessTokenSource`, not the
coordinator — add `onStepUpRequired()` to the interface, and have `SessionCoordinator.login()`
leave it on `Authorizing`), or remove the state from the spec and the type. Entering it is the
right call: it is what lets UI distinguish "needs a step-up" from "signed out" without catching
the exception on every call site. Also decide what the state means after process death — the
originating request is memory-only, so restore should settle on `Authenticated`, which is what
`ensureRestored()` already does.

**Effort.** 1 day plus a scenario-14 assertion in the harness. **Blocker: yes** (conformance).

### F5. The ID token is never validated; the `nonce` the SDK generates is never checked

**Concern.** `AuthorizationRequest` always sends a `nonce`, persists it, and `AuthorizationGrant`
carries it through to the exchange. `SessionCoordinator.login()` then stores `response.idToken`
raw for `id_token_hint` and never parses it. No `iss`, `aud`, `exp` or `nonce` check exists; there
is no JWKS client. OIDC Core §3.1.3.7 makes `iss`, `aud` and `exp` MUSTs, and "if a nonce value
was sent in the Authentication Request, a nonce Claim MUST be present and its value checked".
Signature validation is the one step the spec relaxes for the code flow ("the TLS server
validation MAY be used to validate the issuer in place of checking the token signature"). The
practical risk today is low — the token comes over TLS from a discovered endpoint and the SDK
exposes no claims — but the moment #18's account surface or an integrator reads `sub` or `acr`
from the stored ID token, it is reading unverified data, and the step-up flow is exactly where
`acr` matters.

**Evidence.** `android/core/.../AuthorizationRequest.kt` (`nonce` generated);
`android/core/.../AuthorizationResponse.kt` (`AuthorizationGrant.nonce`);
`android/core/.../SessionCoordinator.kt:171` and `:342` (`credentialStore.save(..., idToken)`);
no file under `android/` references `jwks`, `aud` or ID-token claims.

**State of the art.** Auth0.Android and Auth0.swift validate ID tokens (Auth0.swift's 3.0.0
changelog includes thumbprint-mismatch handling for DPoP alongside it); `kotlin-multiplatform-oidc`
documents that it does *not* validate signatures as a stated limitation — which is the honest
alternative.

**Recommendation.** Add `IdTokenClaims` parsing in `:core` (kotlinx-serialization, no signature
check) with the four MUST checks, run inside `login()` and on every refresh that returns an
`id_token`; fail with `Configuration(TokenResponseMalformed)` on mismatch (it is a deployment
fault, never a user one). Expose `Versola.idTokenClaims(): IdTokenClaims?` and document that the
signature is not verified and why. Signature verification via `jwks_uri` is a later improvement.

**Effort.** 2 days. **Blocker: yes** — the nonce check is a MUST and a few lines.

### F6. The public API is too wide to freeze at 1.0

**Concern.** Three things are on the ABI that should not be:

- `Versola.dpop: DpopProofFactory?` is a public `val`. Anyone with the `Versola` instance can mint
  a proof for any method and URL with the session's hardware key, and `DpopProofFactory.nonces`
  and `clockSkew` are public too. Combined with `accessToken()` this is complete impersonation
  from app code — a larger escape hatch than the one the `accessToken()` KDoc warns about.
- `core.api` is 855 lines: `AuthorizationFlow`, `SessionCoordinator`, `HttpTokenClient`,
  `EdgeNativeTokenClient`, `HttpNativeAuthorizationStarter`, `TokenRequestExecutor`'s
  collaborators, `FileNativeEndpointsStore`, `FormBody`-adjacent types. These are wiring. Once
  published they are what `apiCheck` and semantic versioning hold you to.
- `KeystoreDpopKey.Companion.destroy(alias)` is a public static that deletes a Keystore entry.

**Evidence.** `android/sdk/api/sdk.api` (`getDpop`); `android/core/api/core.api` (855 lines);
`android/dpop/api/dpop.api`.

**State of the art.** Okta's SDK marks its wiring with a KMP-internal package and tells integrators
"new code should use the KMP APIs in `…kmp.*`"; Firebase gates its surface with Metalava `api.txt`
plus a `metalavaSemver` task that computes the required version bump from the diff. Kotlin's own
convention for this is a `@RequiresOptIn` marker.

**Recommendation.**

1. Make `dpop` `internal`; keep `keyAttestation()` as the only DPoP-shaped public call.
2. Introduce `@VersolaInternalApi` (`@RequiresOptIn(level = ERROR)`) and apply it to every type in
   `:core`, `:dpop`, `:storage`, `:browser` and `:okhttp` that exists for wiring or for the
   harness. The conformance driver opts in; apps cannot without saying so. Keep
   `VersolaError`, `SessionState`, `RetryPolicy`, `TokenBinding`, `BackChannel`, `UnlockPolicy`,
   `VersolaLogger`, `VersolaConfiguration`, `ProviderMetadata`, `KeyAttestation`,
   `VersolaHttpException`, `VersolaInterceptor` and — since `d1b54c5` added it to `configure()` —
   `BrowserAuthorizationSession` public: it is the seam the harness and the Auth Tab
   implementation both need, and its URI-only contract is what keeps a `WebView` unrepresentable.
3. Write the 0.x versioning policy down: `0.MINOR.PATCH`, breaking changes bump MINOR, `apiCheck`
   enforced on every PR, and the dump committed. Say in the README that 1.0 freezes the opted-out
   surface only.

**Effort.** 1–2 days. **Blocker: yes** — surface can only shrink before 1.0.

### F7. No attestation seam: FAPI 2.0 excludes public clients, and `BackChannel.Edge` authenticates edge, not the app

**Concern.** FAPI 2.0 §5.1.1: "The OpenID FAPI Working Group is not currently aware of any
mechanisms that would allow public clients to be secured to the same degree and hence their use is
not within the scope of this document." `BackChannel.Edge` puts a confidential client (edge, mTLS)
between the app and auth — but anything that knows a `clientId` can `POST /native/start` with any
DPoP key and obtain a `request_uri`. The device key proves *continuity* (the same key from start
to token to resource) and nothing about *what* is holding it. The server has no attestation code
at all (the only "attestation" in `auth/src/main` is WebAuthn), `KeystoreDpopKey` generates its key
without `setAttestationChallenge`, and there is no App Attest counterpart in the iOS plan.

**Evidence.** `android/core/.../BackChannel.kt` `HttpNativeAuthorizationStarter.start()` (proof
only); `android/dpop/.../KeystoreDpopKey.kt` `generate()` (no challenge, no
`getCertificateChain`); `versola-main/edge/src/main/scala/versola/edge/nativeapp/NativeController.scala`.

**State of the art.** `draft-ietf-oauth-attestation-based-client-auth-11` (3 September 2026,
Standards Track, WGLC feedback thread open since 15 September 2026) defines
`OAuth-Client-Attestation` (a JWT from a *Client Attester* with `cnf` over the *Client Instance
Key*) plus a PoP, usable at PAR and the token endpoint, with a `dpop_combined` PoP method in which
"a single Proof of Possession (PoP) JWT [satisfies] the role of both" the attestation PoP and the
DPoP proof, and a server-driven `use_attestation_challenge` mechanism. That is structurally the
`/native/start` exchange: edge is the natural Client Attester. The device-side evidence is
Android Keystore key attestation (`setAttestationChallenge`; chain rooted at Google; extension OID
1.3.6.1.4.1.11129.2.1.17 with `attestationSecurityLevel`, `verifiedBootState`,
`attestationApplicationId`; Remote Key Provisioning on Android 12+) — which Google now says is
best consumed through Play Integrity ("the recommended way to benefit from hardware-backed Android
platform key attestation", October 2025), using standard requests with `setRequestHash` bound to
the request and verified via `decodeIntegrityToken` — and App Attest on iOS. The attestation
chain must be verified on a server; relay attacks against apps that treat a valid chain as a
boolean are documented, so the attested key must *also* be the DPoP key that signs every request,
which is exactly what this design already has.

**Recommendation.** Do not build the server side in phase 1. Do put the seam in before 1.0,
because a key generated without a challenge cannot be attested later and `DpopKey` is public API:

1. `DpopKey.attestation(challenge: ByteArray): KeyAttestationEvidence?` (certificate chain on
   Android; App Attest object on iOS; `null` where unsupported). `KeystoreDpopKey` generates with
   `setAttestationChallenge` when a challenge is supplied; the key is already regenerated on every
   login, so a challenge from `/native/start` fits the existing lifecycle.
2. Reserve the wire shape now: `/native/start` may return `use_attestation_challenge` and the
   SDK answers with `OAuth-Client-Attestation` headers in `dpop_combined` mode. Record it in
   `spec/server-dependencies.md` as open server work.
3. Play Integrity is a *separate* signal with a quota (10,000/day by default) and a Play Services
   dependency; make it an optional module, not core.

**Effort.** SDK seam 3 days; server work is a separate project. **Blocker: no** (later
improvement), but the seam is cheap and should land before 1.0.

### F8. PAR is not used under `BackChannel.Auth`, though the server advertises it

**Concern.** `AuthorizationRequest.toUri()` builds a full front-channel query; `ProviderMetadata`
does not even read `pushed_authorization_request_endpoint`. The server advertises it
(`ServedMetadata.scala`). The spec itself names the cost: an unregistered `redirect_uri` is an
error page the SDK cannot see (scenario 17, "the single most common first-run mistake"), and
"only PAR (RFC 9126) can [fix it], by moving the check to a plain HTTPS response the app makes
itself". RFC 9449 §10.1 lets the client put the `DPoP` header on the PAR request and have the
server "behave as if the contained public key's thumbprint was provided using `dpop_jkt`";
OAuth 2.1 and FAPI 2.0 both require PAR. RFC 9126 §2.1 permits public clients at the PAR
endpoint with `client_id`.

**Evidence.** `android/core/.../AuthorizationRequest.kt`; `android/core/.../ProviderMetadata.kt`;
`spec/errors.md` authorization-endpoint section; `versola-main/auth/src/main/scala/versola/oauth/metadata/ServedMetadata.scala:85`.

**Recommendation.** When discovery advertises the PAR endpoint, push the request with a DPoP
proof for the PAR URL, open the browser with `client_id` and `request_uri` only, and persist the
same pending slot. Map a 4xx from `/par` to `Configuration(AuthorizationRejected)` exactly as
`HttpNativeAuthorizationStarter` already does. Fall back to the front channel when the field is
absent. Also honour `require_pushed_authorization_requests` and `request_uri` lifetime
(`expires_in`, typically 5–600 s) as the pending-request ceiling instead of the fixed ten
minutes.

**Effort.** 2–3 days. **Blocker: no**, but it is the single biggest first-run-experience win
available and reuses code that already exists for the edge path.

### F9. Release engineering does not exist yet, and API validation is on borrowed time

**Concern.**

- No `maven-publish`/`signing` configuration; `release.yml` runs `./gradlew publish` behind
  `if: false`, which would fail if flipped on. No `version` anywhere.
- No dependency locking (`gradle.lockfile`) and no `gradle/verification-metadata.xml`; no
  Dependabot/Renovate; GitHub Actions referenced by tag, not SHA (Auth0 pins by SHA).
- No SBOM, no provenance attestation.
- `kotlinx-binary-compatibility-validator` works only because `gradle.properties` sets
  `android.builtInKotlin=false` and `android.newDsl=false`. The plugin is in maintenance mode; the
  Kotlin Gradle plugin's `abiValidation {}` is still `@ExperimentalAbiValidation`; and support for
  AGP's built-in Kotlin is tracked under KT-83410, "planned for 2.5.0-Beta2". When AGP removes the
  opt-out, `apiCheck` silently stops checking — the failure mode a November 2025 write-up
  documents on AGP 9.2 ("applies cleanly and then does nothing at all").
- No R8-enabled consumer in CI. The SDK needs no consumer rules of its own (its `@Serializable`
  classes have unnamed companions; kotlinx-serialization, OkHttp and DataStore bundle theirs), but
  Android's library-author guidance is to prove that with a minified sample app and the R8
  Configuration Analyzer, because "R8 breakage is release-only and runtime-only".

**Evidence.** `.github/workflows/release.yml`; `android/build.gradle.kts` (no publishing);
`android/gradle.properties`; absence of `android/gradle.lockfile`, `gradle/verification-metadata.xml`,
`.github/dependabot.yml`, any `consumer-rules.pro`, any sample app.

**State of the art.** Sonatype's Central Portal has no official Gradle plugin ("Gradle support is
on our roadmap") and lists `vanniktech/gradle-maven-publish-plugin`, `GradleUp/nmcp` and JReleaser
as community options; signing, sources and javadoc jars and full POM metadata are required. Gradle
dependency verification bootstraps with `--write-verification-metadata sha256,pgp` into
`gradle/verification-metadata.xml` and "trusts whatever is currently in your repositories", so the
generated file must be reviewed. CycloneDX's Gradle plugin 3.x emits per-project and aggregate
SBOMs; Maven Central validates Sigstore bundles since January 2025. Firebase's build runs
`apiInformation` and `metalavaSemver` on every change.

**Recommendation.**

1. `com.vanniktech.maven.publish` with `publishToMavenCentral()` and `signAllPublications()`;
   coordinates `kz.versola:versola-android` for `:sdk` and `kz.versola:versola-android-<module>`
   for the rest; version from a Git tag.
2. `--write-verification-metadata sha256,pgp`, review, commit; Dependabot for Gradle and Actions;
   pin actions by SHA.
3. CycloneDX SBOM attached to the release; GitHub `attest-build-provenance` on the AARs.
4. Add a `:sample` application module with `minifyEnabled true` to the `build` job; run the R8
   analyzer and assert the SDK's classes shrink.
5. Plan the BCV migration: when KT-83410 ships, move to `abiValidation {}`; until then, add a CI
   step that fails if `apiCheck` ran zero tasks (grep the Gradle output), so the silent-no-op
   failure cannot pass.

**Effort.** 2–3 days. **Blocker: yes** — there is no 1.0 without a publish.

### F10. Android 15/16 redirect-path hardening

**Concern.** `VersolaRedirectActivity` is `exported="true"`, `singleTask`, `Theme.NoDisplay`,
and on receipt starts the app's launcher activity with `CLEAR_TOP | SINGLE_TOP` from `onCreate`.
Three platform changes touch this:

- *Activity Security Model.* Apps that opt in with
  `android:allowCrossUidActivitySwitchFromBelow="false"` (application-level; the rules apply to
  apps targeting the current preview API) block cross-UID launches into their task. A browser
  (another UID) delivering the redirect creates or fronts the app's task from the foreground,
  which Rule 2 permits; but an integrator who opts in and whose task is *below* the browser's is
  on the edge of Rule 1. Google's own warning: "enabling this protection can block legitimate
  apps that need to launch activities into your task … You must test these user flows thoroughly".
- *TapTrap.* Exported activities that do not override transition animations are the attack
  surface; browsers and Custom Tabs were affected (8 of 10 browsers tested); platform fix shipped
  in the December 2025 security update for Android 13–16. AppAuth-Android's `RedirectUriReceiverActivity`
  has an open issue (#1147). `Theme.NoDisplay` with an immediate `finish()` means this activity
  itself is not a target, but the launcher activity it brings forward is.
- *Android 15 BAL and Intent hardening.* `startActivity` from a foreground `onCreate` is fine;
  Android 16's default Intent-redirection protection concerns nested intents in extras, which the
  SDK does not use. Android 15 also throws on network requests "outside of a valid process
  lifecycle", which matters for any future background refresh.

**Evidence.** `android/browser/src/main/AndroidManifest.xml`;
`android/browser/.../VersolaRedirectActivity.kt`; `.github/workflows/android.yml` instrumented
matrix `[28, 34]`.

**Recommendation.** Call `setAllowCrossUidActivitySwitchFromBelow(true)` in
`VersolaRedirectActivity.onCreate` (API 35+, guarded) and document why; override the entry
transition to none (`overrideActivityTransition` on 34+, `overridePendingTransition(0, 0)` below)
on both the redirect activity and the future Auth Tab trampoline; add API 36 to the instrumented
matrix; add a manifest-merger test that the integrator's `tools:node="merge"` snippet produces one
exported activity with one filter. Auth Tab (F1) removes most of this surface because the
redirect is no longer an intent at all.

**Effort.** 1 day. **Blocker: no.**

### F11. The iOS floor (16.0) cannot run the FAPI path

**Concern.** `Package.swift` declares `.iOS(.v16)`. `ASWebAuthenticationSession` accepts an https
callback only through `Callback.https(host:path:)`, which Apple's engineers confirm "is only
available on iOS 17.4 and later"; before that, "you must use a custom URL scheme". An edge-fronted
native client is registered with https redirect URIs only (`spec/server-dependencies.md`), and
`AuthorizationFlow` refuses `BackChannel.Edge` without an App Link. So on the server's *default*
tenant profile, the planned iOS SDK has no browser leg on iOS 16.0–17.3. The https callback also
requires the `webcredentials` associated-domains service, not `applinks` — "apps with only
`applinks:` won't work" — which must be in the integrator documentation from day one.

**Evidence.** `Package.swift`; `spec/server-dependencies.md` registration constraints;
`android/core/.../AuthorizationFlow.kt` `init` block.

**State of the art.** Auth0.swift added https callbacks in 2.6.0 (March 2024) and keeps a
custom-scheme fallback for < 17.4 with both callback types registered; AppAuth-iOS documents the
`webcredentials` requirement; `kotlin-multiplatform-oidc` checks the OS version at runtime.
Apple's own June 2026 numbers quoted in #1 put iOS 18+ at ~97%.

**Recommendation.** Raise the floor to iOS 17.4 for the SDK (not merely for `BackChannel.Edge`),
state the `webcredentials` requirement in the README next to the Android `assetlinks.json` one,
and keep custom-scheme redirects supported under `BackChannel.Auth` only, with the same warning
Android emits. Do not implement a < 17.4 custom-scheme fallback for the edge path; the server
will refuse the registration anyway.

**Effort.** Zero now; a decision. **Blocker: yes** for phase 2.

### F12. Caches that never expire

**Concern.** `DiscoveryService.metadata()` returns the on-disk document forever; `forceRefresh` is
not reachable from the facade. `FileNativeEndpointsStore` likewise. A provider that rotates its
`token_endpoint`, adds `dpop_signing_alg_values_supported` (the bearer-fallback signal) or moves
its mTLS alias is never noticed by an installed app. The code's own comment on
`request_uri_parameter_supported: false` shows discovery documents do change.

**Evidence.** `android/core/.../Discovery.kt` `DiscoveryService`; `android/core/.../BackChannel.kt`
`FileNativeEndpointsStore`; `spec/state-machine.md` persistence summary ("Discovery metadata —
Disk, unencrypted — survives logout").

**Recommendation.** Store `fetchedAt`; treat the cache as fresh for 24 h; on any
`Configuration(TokenRequestRejected)`/`DiscoveryFieldMissing` or a 404 from a cached endpoint,
refetch once and retry the operation once inside the same budget. Keep the across-logout
behaviour.

**Effort.** 1 day. **Blocker: no.**

### Minor findings (later improvements)

| # | Concern | Evidence | Recommendation |
|---|---|---|---|
| M1 | `Idempotency-Key` is sent under DPoP, where the server says it is "only meaningful for a bearer grant"; under `BoundRenewal` the value is constant for the session's 180-day life — a stable identifier in two servers' logs. | `HttpTokenClient.refresh()`; `OAuthTokenService.refreshAccessToken` doc comment | Omit the header when `TokenResponse.isDpopBound`. |
| M2 | `sessionState` is a cold `Flow`; Compose and `StateFlow` consumers need an initial value the spec's seven states do not include. | `AuthorizationFlow.sessionState` | Document `stateIn(scope, SharingStarted.Eagerly, Unauthenticated)` is *wrong* (it publishes a false signed-out) and offer `suspend fun currentState()`; consider `StateFlow<SessionState?>` with `null` as "not restored" if the spec is amended. |
| M3 | Two `HardwareKeyProvider` instances share an alias; `key()` is generate-if-absent without a lock, so two first-wraps in parallel can generate twice and orphan one ciphertext. | `Versola.configure()`; `HardwareKeyProvider.key()` | One instance; `synchronized` generation. Folds into F3. |
| M4 | Access token is memory-only, so every cold start costs a token request; mobile apps cold-start many times a day. | `SessionCoordinator.cachedAccessToken` | Acceptable under `BoundRenewal`; if traffic matters, persist the access token encrypted with its wall-clock expiry and accept the clock caveat. |
| M5 | `VersolaLogger` has `info`/`warn` only; there is no way for an integrator to get the attempt-by-attempt detail the retry budget records without catching exceptions. | `BrowserAuthorizationSession.kt` `VersolaLogger` | Add `debug` and an opt-in `VersolaEvent` sink (request started/ended, refresh, nonce retry) with no credential payloads; the harness's OkHttp transcript listener is the same thing. |
| M6 | `Recoverable.Cause.SystemCancelled` is declared and specified but never produced on Android (the code comment explains why); iOS will produce it. | `BrowserAuthorizationSession.kt` KDoc on `UserCancelled` | Record in `spec/errors.md` that Android never emits it, so the Flutter bridge does not wait for it. |
| M7 | `AuthenticateChallenge.parse` flattens multiple challenges, first occurrence wins; a future edge that emits `DPoP …, Bearer …` on one response would be misread. | `AuthenticateChallenge.kt` | Parse per challenge and prefer the one whose scheme matches the token presented; cheap now, awkward later. |
| M8 | `Versola.call()` returns an OkHttp `Response` the caller must close; a suspend API that hands back a closeable is a leak magnet. | `Versola.kt` `call()` | Offer `callWith(request) { response -> }` or a `use`-returning overload; keep `call()` for parity. |
| M9 | Since `d1b54c5`, `VersolaConfiguration.create` accepts a cleartext `http://` issuer for `localhost`, `127.0.0.1`, `[::1]` and `10.0.2.2` in shipping code, to let the harness use `adb reverse`. `10.0.2.2` is only the emulator's host alias; on a physical device it is a routable `10/8` address, so an issuer string copied from a test fixture into a release build talks OAuth in cleartext to whatever answers there. | `VersolaConfiguration.kt` `isLoopback` (duplicated in two companions) | Keep the exemption but make it explicit: `configure(allowCleartextLoopbackIssuer = true)` (or the harness passing its own `VersolaConfiguration`), drop `10.0.2.2` from the production list, and deduplicate the helper. |
| M10 | `login()` now appends `offline_access` unconditionally (OIDC Core §11). Correct for this session model, but an app that deliberately wants a one-shot authorization (no refresh token, e.g. a step-up that should not extend the grant) has no way to say so, and the scope set the app sees in `TokenResponse.scopes` differs from what it asked for. | `SessionCoordinator.login()` | Document it in the README (done) and in `spec/state-machine.md` (not yet); consider leaving `stepUp()` without it. |

## 4. Cross-platform recommendation

### Keep two native cores; make the shared half shareable anyway

The #1 §3 rejection of KMP still holds in October 2026: Swift export is Alpha, requires Xcode
26.4, uses `Dispatchers.Default` by default, and "is still incomplete; incompatible changes are
expected". Okta is the only vendor shipping a KMP identity core, and it still ships
`web-authentication-ui` as an Android-only module — the browser, keystore and keychain halves do
not share. But the repository already has the property that makes a later KMP move cheap:
`:core` and `:okhttp` contain no `android.*` import. Two concrete steps now:

1. Convert `:core` from `com.android.library` to a plain Kotlin/JVM module (`kotlin("jvm")`).
   It loses nothing (it uses `java.net`, `java.security`, OkHttp, kotlinx), its tests stop
   needing AGP, and it becomes a `commonMain` candidate when Swift export reaches Beta (Kotlin
   2.5 per the roadmap).
2. Keep the Swift core a separate implementation for phase 2, but write it against the same
   conformance transcripts, not against the Kotlin code. The transcript diff is what proves
   equivalence; sharing source would only prove that one bug exists twice.

### iOS (phase 2) — specific design decisions

- **Floor iOS 17.4** (F11). `ASWebAuthenticationSession(url:callback: .https(host:path:))`;
  `webcredentials` associated domain; `prefersEphemeralWebBrowserSession = false` by default with
  an opt-in, mirroring the Android ephemeral opt-in so the state machine stays one machine.
- **Swift 6 language mode from the first commit** (`swiftLanguageMode(.v6)` in `Package.swift`,
  as Auth0.swift did in 3.0, July 2026). The public surface should be: `struct`/`enum` value
  types that are implicitly `Sendable`; `SessionCoordinator` as an `actor` (the single-flight
  logic is the textbook case: non-`Sendable` state, atomic operations, no existing actor to live
  on); `VersolaError` as a `Sendable` `enum` with associated values; callbacks only as
  `@Sendable` closures. Avoid `@unchecked Sendable` entirely.
- **State stream.** The spec says `AsyncStream<SessionState>`. `AsyncStream` is single-consumer;
  two observers (a view model and a logger) would starve one another. Expose
  `func sessionStates() -> AsyncStream<SessionState>` that creates a stream per call backed by
  an actor-held set of continuations, with `onTermination` removing the continuation — the
  standard adapter pattern.
- **DPoP key.** CryptoKit `SecureEnclave.P256.Signing.PrivateKey`; persist `dataRepresentation`
  (an encrypted blob, not the key) in the Keychain; `SecureEnclave.isAvailable` decides the
  software fallback and the `KeyAttestation` value; `signature(for:).rawRepresentation` is
  already `R‖S`, so the Android DER conversion has no iOS twin. `accessControl` is *not* user-gated,
  per #1 §4.
- **Storage.** `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and `kSecAttrSynchronizable =
  false` for the refresh token and pending request (Apple: "apps that use background refresh
  services can use `kSecAttrAccessibleAfterFirstUnlock`"; `ThisDeviceOnly` items are "unusable if
  restored to different devices" — the `noBackupFilesDir` equivalent). `OnAppUnlock` maps to
  `SecAccessControl` with `.userPresence` and an `LAContext` whose
  `touchIDAuthenticationAllowableReuseDuration = 300`. Treat `errSecInteractionNotAllowed`
  (-25308) as `UnlockRequired`, never as sign-out. Write the new token before deleting the old
  (`SecItemUpdate`), not delete-then-add.
- **Background refresh.** Do not schedule anything. The SDK refreshes when asked; the app owns
  `BGAppRefreshTask`. Document that Android 15 throws on network outside a valid process
  lifecycle and iOS gives ~30 s, so a refresh in a background task must be cancellable.
- **Attestation seam.** `DCAppAttestService` (`generateKey`, `attestKey(challenge)`,
  `generateAssertion(clientDataHash)`) behind the same `attestation(challenge:)` protocol
  requirement as Android (F7).
- **Distribution.** Source SPM package, not a binary XCFramework: the licence is Apache-2.0, there
  is nothing to hide, and a binary would force `BUILD_LIBRARY_FOR_DISTRIBUTION` (library
  evolution), which "changes your framework's performance characteristics" and makes every
  dependency's ABI part of the contract. Keep `Package.swift` at the root as decided; drop
  CocoaPods from `release.yml` unless a customer asks.
- **Cancel detection.** The spec's lifecycle-paired reading of `canceledLogin` is right. Note that
  iOS *does* give the signal Android lacks, so `SystemCancelled` is iOS-only in practice (M6).

### Flutter (phase 3)

Pigeon 29 with **platform channels**, not the new Native Interop mode: Native Interop is
experimental, does not support event channels, and both sides must pin the same Pigeon version.
Three design points:

- Return `Result`-shaped sealed classes from host API methods rather than throwing: Pigeon now
  generates sealed classes for Dart, Kotlin and Swift, so `VersolaError`'s four categories arrive
  typed — satisfying `spec/errors.md`'s rule that a `StepUp` must not degrade to a
  `PlatformException`.
- `Stream<SessionState>` through a Pigeon event channel, fed from `Flow`/`AsyncStream`.
- Never expose Pigeon-generated types in the public Dart API ("subject to change without
  warning"); wrap them.
- `mobile-demo` migration (#17) is the first real consumer and should run the conformance
  scenarios through the bridge, not only the native SDK.

### React Native (conditional)

If it is built, use Nitro Modules: the SDK is a stateful object (`Versola` instance, state stream),
and Nitro's `HybridObject` models objects where TurboModules model modules; Nitro also generates
Swift/Kotlin bindings directly, which matters for a Swift-6 core. The cost is a third-party
dependency with a single maintainer; the New Architecture being mandatory since RN 0.82 removes
the old-bridge option either way.

## 5. Testing and CI recommendations

### Where the repository stands against peers

| SDK | Unit | Android-host / Robolectric | Emulator in CI | Device farm | API surface check | Conformance against a real server |
|---|---|---|---|---|---|---|
| **versola-sdk** (today) | 313 methods, MockWebServer | yes | `:storage`, `:dpop` on API 28/34 | planned (FTL) | BCV `apiCheck` | scenarios 01 and 21 green against a staged stack; `conformance.yml` on demand until a checkout token exists; login driven over HTTP, so Custom Tabs are not exercised |
| AppAuth-Android | `check jacoco` only | — | no | no | no | no |
| Auth0.Android | `testReleaseUnitTest`, lint, CodeQL, SCA, SHA-pinned actions | yes | no | no | no | no |
| Okta mobile Kotlin | `testDebugUnitTest`, `testAndroidHostTest` (KMP) | yes | no | FTL mentioned | no | no |
| MSAL Android | unit | — | `msalautomationapp` with broker flavours, lab accounts, real Authenticator/Company Portal APKs | Pixel devices | no | yes, against Entra lab tenants |
| Firebase Android | Robolectric `check` | yes | `connectedCheck` | `deviceCheck` on FTL (`panther`, API 33) | Metalava `api.txt`, `apiInformation`, `metalavaSemver` | emulator suite |

The plan in `conformance/README.md` is closer to MSAL's automation app than to anything AppAuth,
Auth0 or Okta do, and that is the right company to keep. Two of twenty-three scenarios run; the
proxy, the transcript comparison with the reference client, and every fault-injection scenario
are still ahead. One consequence of the driver's design to keep in view: `HttpLoginBrowser`
replaces the browser leg with an HTTP conversation, which is the right call for determinism but
means the three findings that live in the browser leg — F1, F10 and the cancel semantics — are
provable only at the device tier, which does not exist yet.

### Concrete additions

1. **Keep the driver's order of work** (08, 14, 15–17, 20 next; then the proxy for 03–06, 09, 13,
   23; then 12 through `am kill`), add the `VERSOLA_CHECKOUT_TOKEN` secret and drop the
   `workflow_dispatch` gate so the nightly runs, and make the transcript comparison with
   `NativeAppFlowSpec`'s reference client the next milestone after 08 — it is what turns "green"
   into "equivalent".
2. **Scenario traceability.** Annotate every test with `@Scenario("12")` (a tiny runtime
   annotation in a test-fixtures module) and generate a scenario-coverage matrix in CI that fails
   when a scenario has no test at any tier. The README already asks PR authors to say what is
   proven against stubs only; make the build say it.
3. **Add the two tests this review would have failed on:** 100 concurrent `call()`s on
   `Dispatchers.IO` with a 401 first response (F2); and an instrumented UI Automator test that
   taps the Custom Tab minimize button mid-login and then completes the login (F1).
4. **Emulator matrix:** add API 36 (`google_apis`, since Auth Tab needs Chrome) to the
   instrumented job; keep 28 for the pre-R `setUserAuthenticationValidityDurationSeconds` branch.
5. **R8 sample app** in the `build` job with `minifyEnabled true` and a smoke test that runs
   discovery and a proof mint (F9).
6. **Property tests** for the parsers that face untrusted input — `AuthorizationResponseValidator.parseQuery`,
   `AuthenticateChallenge.parse`, `wwwAuthenticateError`, `CredentialBlob.decode`, `Jose.derToJose` —
   with jqwik or kotest-property; `derToJose` is the one the KDoc itself says "fails one signature in
   every few hundred" when wrong.
7. **Firebase Test Lab** for the StrongBox and biometric rows of #37 once a project exists; a
   Pixel with StrongBox and one Samsung device cover the two Keystore implementations that differ
   in practice. Firebase's own `deviceCheck` task is the pattern.
8. **iOS CI:** the current job builds and tests the placeholder; when real code lands, add
   `-strict-concurrency=complete` as a CI gate (PowerSync added exactly this), and run the Swift
   conformance driver against the same staged stack through the Docker Compose file.
9. **Spec CI** already validates scenarios against the schema; add a check that every state and
   error named in a scenario exists in `SessionState.kt` and `VersolaError.kt` (a Python script
   over the `.api` dumps), so F4-style drift is caught by `spec.yml`.

## 6. Sources

Every source below was fetched or returned with content during this review.

IETF / OpenID specifications

- RFC 9449, OAuth 2.0 Demonstrating Proof of Possession — <https://www.rfc-editor.org/rfc/rfc9449.html>
- RFC 8252, OAuth 2.0 for Native Apps — <https://www.rfc-editor.org/rfc/rfc8252.html>
- RFC 9126, OAuth 2.0 Pushed Authorization Requests — <https://www.rfc-editor.org/rfc/rfc9126.html>
- RFC 9207, OAuth 2.0 Authorization Server Issuer Identification — <https://www.rfc-editor.org/rfc/rfc9207.html>
- draft-ietf-oauth-v2-1-16, The OAuth 2.1 Authorization Framework — <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1>
- draft-ietf-oauth-attestation-based-client-auth-11 — <https://datatracker.ietf.org/doc/html/draft-ietf-oauth-attestation-based-client-auth>
- FAPI 2.0 Security Profile (Final, February 2025) — <https://openid.net/specs/fapi-security-profile-2_0-final.html>
- OpenID Connect Core 1.0 (§3.1.3.7 ID Token Validation) — <https://openid.net/specs/openid-connect-core-1_0.html>
- OpenID Foundation guest blog, "Implementing App-to-App Authorisation in OAuth2/OpenID Connect" — <https://openid.net/guest-blog-implementing-app-to-app-authorisation-in-oauth2-openid-connect/>
- Daniel Fett, "Improving OAuth App-to-App Security" — <https://danielfett.de/2020/11/27/improving-app2app/>

Android

- androidx.browser release notes (1.9.0, 1.10.0) — <https://developer.android.com/jetpack/androidx/releases/browser>
- Chrome, "Simplify authentication using Auth Tab" — <https://developer.chrome.com/docs/android/custom-tabs/guide-auth-tab>
- Chrome, "Improve web privacy for users with Ephemeral Custom Tabs" — <https://developer.chrome.com/docs/android/custom-tabs/guide-ephemeral-tab>
- Android, Activity security (Activity Security Model, `allowCrossUidActivitySwitchFromBelow`) — <https://developer.android.com/guide/components/activities/secure-bal>
- Android 15 behavior changes (all apps) — <https://developer.android.com/about/versions/15/behavior-changes-all>
- Android 15 behavior changes (targeting 35) — <https://developer.android.com/about/versions/15/behavior-changes-15>
- Android 16 behavior changes (all apps) — <https://developer.android.com/about/versions/16/behavior-changes-all>
- Android, Biometric authentication (`CryptoObject`, `setUserAuthenticationParameters`) — <https://developer.android.com/identity/sign-in/biometric-auth>
- Android Keystore system — <https://developer.android.com/privacy-and-security/keystore>
- AOSP, Key and ID attestation — <https://source.android.com/docs/security/features/keystore/attestation>
- Play Integrity API, standard requests — <https://developer.android.com/google/play/integrity/standard>
- Android Developers Blog, "Stronger threat detection, simpler integration: Protect your growth with the Play Integrity API" (October 2025) — <https://android-developers.googleblog.com/2025/10/stronger-threat-detection-simpler.html>
- Android, Credential Manager — <https://developer.android.com/identity/sign-in/credential-manager>
- Android, Optimization for library authors (R8 consumer rules) — <https://developer.android.com/topic/performance/app-optimization/library-optimization>
- Android Developers Blog, "Configure and troubleshoot R8 Keep Rules" (November 2025) — <https://android-developers.googleblog.com/2025/11/configure-and-troubleshoot-r8-keep-rules.html>
- TapTrap: Animation-Driven Tapjacking on Android (USENIX Security 2025) — <https://taptrap.click/>
- HackTricks, Play Integrity attestation bypass / Keystore chain relay — <https://hacktricks.wiki/en/mobile-pentesting/android-app-pentesting/play-integrity-attestation-bypass.html>
- Quarkslab, "Bypassing Android Hardware Attestation from the Analyst's Chair" — <https://blog.quarkslab.com/bypassing-android-hardware-attestation.html>

iOS

- Apple Developer Forums, ASWebAuthenticationSession + https on iOS < 17.4 (Apple engineer reply) — <https://developer.apple.com/forums/thread/769749>
- Apple Platform Security, Keychain data protection — <https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web>
- CryptoKit, `SecureEnclave.P256.Signing.PrivateKey` — <https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey>
- Apple Developer Forums, `errSecInteractionNotAllowed` in background with AfterFirstUnlock — <https://developer.apple.com/forums/thread/766206>
- Swift.org, Library Evolution in Swift — <https://www.swift.org/blog/library-evolution/>
- Apple Developer Forums, binary targets with dependencies (DTS answer) — <https://developer.apple.com/forums/thread/799438>
- SwiftPM issue #10552, building and publishing binary XCFrameworks — <https://github.com/swiftlang/swift-package-manager/issues/10552>
- PowerSync Swift SDK strict-concurrency PR — <https://github.com/powersync-ja/powersync-swift/pull/70>

Cross-platform

- Kotlin, Interoperability with Swift using Swift export — <https://kotlinlang.org/docs/native-swift-export.html>
- What's new in Kotlin 2.4.0 — <https://kotlinlang.org/docs/whatsnew24.html>
- What's new in Kotlin 2.4.20 — <https://kotlinlang.org/docs/whatsnew2420.html>
- KT-53877, Support Swift Package Manager in Kotlin Multiplatform — <https://youtrack.jetbrains.com/projects/KT/issues/KT-53877>
- Pigeon on pub.dev (29.0.8) — <https://pub.dev/packages/pigeon>
- Flutter issue #182230, Pigeon native interop — <https://github.com/flutter/flutter/issues/182230>
- Dominik Roszkowski, "jnigen and swiftgen in 2026" — <https://roszkowski.dev/2026/swiftgen-jnigen/>
- Margelo, "Rewriting Rive React Native with Nitro Modules" — <https://margelo.com/blog/rewriting-rive-react-native-with-nitro-modules>
- React Native Relay, "Turbo vs Nitro Modules: RN Guide 2026" — <https://reactnativerelay.com/article/building-native-modules-2026-turbo-expo-nitro-compared>
- kalinjul/kotlin-multiplatform-oidc README and PR #187 — <https://github.com/kalinjul/kotlin-multiplatform-oidc> , <https://github.com/kalinjul/kotlin-multiplatform-oidc/pull/187>

SDK engineering

- Kotlin binary-compatibility-validator — <https://github.com/Kotlin/binary-compatibility-validator>
- Kotlin, Binary compatibility validation in the Kotlin Gradle plugin — <https://kotlinlang.org/docs/gradle-binary-compatibility-validation.html>
- KT-83410, Expose API to configure Binary Compatibility validator — <https://youtrack.jetbrains.com/projects/KT/issues/KT-83410>
- "Binary Compatibility Validation Silently Stops Working on AGP 9's Built-in Kotlin" — <https://medium.com/@tjokinen/binary-compatibility-validation-silently-stops-working-on-agp-9s-built-in-kotlin-974162978780>
- Sonatype, Publishing via Gradle to the Central Portal — <https://central.sonatype.org/publish/publish-portal-gradle/>
- Gradle, Dependency verification — <https://docs.gradle.org/current/userguide/dependency_verification.html>
- CycloneDX Gradle plugin — <https://github.com/CycloneDX/cyclonedx-gradle-plugin>
- "Maven Central Sigstore Validation Defender Guide 2026" — <https://safeguard.sh/resources/blog/maven-central-sigstore-validation-2026>
- kotlinx.serialization README (ProGuard/R8 section) — <https://github.com/Kotlin/kotlinx.serialization>
- Takahiko Kawasaki, "DPoP Nonce" — <https://darutk.medium.com/dpop-nonce-9787b9d276d1>
- MCP conformance PR #529 (DPoP-Nonce newest-wins fix) — <https://github.com/modelcontextprotocol/conformance/pull/529>
- Sangsoo Nam, "OkHttp: How to Refresh Access Token Efficiently" — <http://sangsoonam.github.io/2019/03/06/okhttp-how-to-refresh-access-token-efficiently.html>
- kotlinx.coroutines, `Dispatchers.IO` (64-thread limit, elastic `limitedParallelism` views) — <https://kotlinlang.org/api/kotlinx.coroutines/kotlinx-coroutines-core/kotlinx.coroutines/-dispatchers/-i-o.html>
- Maven Central, `com.squareup.okhttp3:okhttp-coroutines` (5.5.0) — <https://central.sonatype.com/artifact/com.squareup.okhttp3/okhttp-coroutines>

Peer SDKs

- AppAuth-Android README, issues #104, #1146, #1147 — <https://github.com/openid/AppAuth-Android> , <https://github.com/openid/AppAuth-Android/issues/104> , <https://github.com/openid/AppAuth-Android/issues/1146> , <https://github.com/openid/AppAuth-Android/issues/1147>
- AppAuth-iOS README and PR #978 — <https://github.com/openid/AppAuth-iOS> , <https://github.com/openid/AppAuth-iOS/pull/978>
- flutter_appauth issue #635 (process death, November 2025) — <https://github.com/MaikuB/flutter_appauth/issues/635>
- Auth0.Android README, CHANGELOG, `AuthTabResultHandler.kt`, `AuthenticationActivity.kt`, `.github/workflows/test.yml` — <https://github.com/auth0/Auth0.Android>
- Auth0.swift CHANGELOG and Package.swift — <https://github.com/auth0/Auth0.swift>
- react-native-auth0 issue #1584 (Custom Tab minimize → USER_CANCELLED) — <https://github.com/auth0/react-native-auth0/issues/1584>
- Auth0 support, "HTTPS Scheme Fails for iOS Universal Link in ASWebAuthenticationSession" — <https://support.auth0.com/center/s/article/auth0-https-scheme-does-not-work-for-ios-universal-link>
- okta-mobile-kotlin README and `.circleci/config.yml` — <https://github.com/okta/okta-mobile-kotlin>
- MSAL Android README and `android-complete/docs/Automation/how_to_run_tests.md` — <https://github.com/AzureAD/microsoft-authentication-library-for-android> , <https://github.com/AzureAD/android-complete/blob/master/docs/Automation/how_to_run_tests.md>
- Firebase Android SDK README (testing, Metalava, `metalavaSemver`) — <https://github.com/firebase/firebase-android-sdk>
- Keycloak, Securing applications with DPoP; OIDC layers — <https://www.keycloak.org/securing-apps/dpop> , <https://www.keycloak.org/securing-apps/oidc-layers>
- Ory Kratos, self-service flows — <https://www.ory.com/docs/kratos/self-service>
