# Conformance harness

Issue #15. Runs the scenario catalogue under [`../spec/conformance/`](../spec/conformance/)
against a **real staged `auth` + `central` + `edge`** from `versolauth/versola`, once per SDK,
and asserts identical observable behaviour.

**Status.** The Android driver exists as `android/conformance-android` (instrumented tests;
nothing is published from it) and runs scenarios 01 and 21 — with the refresh, revocation and
logout steps of 02, 11 and 18, the edge-nonce half of 04 and the blob-less replay of 22 — green against a stack staged
from `versolauth/versola` at `d6203f93`, from an emulator. The rest of the catalogue, the
fault-injection proxy and the transcript comparison with the reference client are the order
of work at the bottom. iOS has no driver for the Versola facade yet.

The generic facade has its own drivers, `android/conformance-oauth` (Robolectric unit tests,
real network) and `ios/Tests/OAuthConformanceTests` (XCTest, on the Mac host or an iOS
simulator), which run scenarios 24 to 33 green against Keycloak 26.4 and Ory Hydra 26.2 staged
from [`providers/`](providers/); see [Providers](#providers) below.

## Why it is not more unit tests

Everything under `android/*/src/test` proves a rule against a stub. The wiring — Central's
registration API, auth's configuration cache, the exact `WWW-Authenticate` edge emits, the
`Idempotency-Key` auth MACs and looks up, the Postgres round trip behind `detectReplay` —
cannot disagree with the SDK in a stub, and so cannot confirm it either. Issues #36, #37
and #39 list, scenario by scenario, what is currently proven against stubs only.

## Three tiers

| Tier | Runs where | Proves | Status |
|---|---|---|---|
| Unit | JVM, Robolectric | the rule | `android.yml`, `build` job |
| Instrumented | Emulator, real Keystore | the platform half: key tiers, GCM wrapping, the auth window | `android.yml`, `instrumented` job (#30, #37) |
| Conformance | Emulator + staged stack | the wiring: every scenario, against the server | **this directory, not built** |
| Device | Firebase Test Lab | StrongBox, biometrics, Custom Tabs on real OEM builds | not started; needs a project and credentials |

## Shape

```text
 GitHub Actions runner (ubuntu, KVM)
 ┌───────────────────────────────────────────────────────────────────────┐
 │  postgres:18 (service container)                                      │
 │  auth :9003/:9007/:9008   central :9001   nginx :9443   edge :9005    │  ← staged exactly as
 │        ▲                       ▲                            ▲         │    versola's ci-cd.yml
 │        │  10.0.2.2 from the emulator's point of view         │         │
 │  ┌─────┴───────────────────────────────────────────────────────┴──┐    │
 │  │  Android emulator                                              │    │
 │  │  conformance-android (androidTest APK)                         │    │
 │  │    · provisions a tenant + client through Central's API        │    │
 │  │    · drives Versola.configure/login/call/logout                │    │
 │  │    · signs in through the browser leg with the test user       │    │
 │  │    · records every request the SDK emitted (OkHttp listener)   │    │
 │  │    · asserts the scenario's expectations                       │    │
 │  └────────────────────────────────────────────────────────────────┘    │
 └───────────────────────────────────────────────────────────────────────┘
```

**The stack is staged from a checkout of `versolauth/versola`, not from images**, for one
reason: the e2e fixtures the harness reuses (`EdgeFixture`, `CentralApi`, `EdgeApi`,
`NativeAppFlowSpec`'s reference client) live in that repository and expect the same
`gen-env.scala` configuration the server's own CI generates. [`stack/docker-compose.yml`](stack/docker-compose.yml)
is the alternative for local runs against published images, and is what the Flutter and iOS
harnesses will point at when they do not have an sbt toolchain to hand.

## Running the Android driver

The stack is reached at the loopback addresses auth was configured with (`gen-env.scala`'s
`local` target: `http://localhost:9003`), so the issuer the SDK validates is the one auth
announces. `adb reverse` makes the emulator's `localhost` the host's; `adb forward` lets edge
reach the upstream `MockWebServer` the driver runs on the device for the proxied resource.

```bash
# In a versola checkout: develop.md's local stack (central 9001, auth 9003/9007/9008,
# the internal TLS terminator, edge 9005), with Postgres on 5432.
adb reverse tcp:9001 tcp:9001 && adb reverse tcp:9003 tcp:9003 && adb reverse tcp:9005 tcp:9005
adb forward tcp:18080 tcp:18080
cd android && ./gradlew :conformance-android:connectedDebugAndroidTest
```

Instrumentation arguments override the defaults (`Stack.kt`): `authUrl`, `centralUrl`,
`edgeUrl`, `centralSecret`, `edgeInternalSecret`, `upstreamPort`, `upstreamUrlFromEdge`.

The browser leg is `HttpLoginBrowser`: auth's login conversation driven over HTTP, the way
the e2e reference client drives it, handed to the SDK through `Versola.configure(browser = …)`.
Custom Tabs, App Link delivery and the foreground-return detector are therefore not what this
tier proves; they are the device tier's.

## What the driver does per scenario

1. **Provision** through Central (`CentralApi` on the Scala side, or its HTTP equivalent):
   a tenant with the profile the scenario's `mode`/back channel needs — `standard` for
   scenarios 01–20, `fapi2` with an edge-fronted native client for 21–23 — a resource on edge,
   a test user with a role. The SDK's redirect URI is an https App Link the harness owns
   (`https://conformance.versola.test/oauth`), verified on the emulator by
   `pm set-app-links` rather than by a real `assetlinks.json`.
2. **Drive** the SDK the way an app does. The browser leg is a Custom Tab; the harness drives
   it with UI Automator against auth's login form (username, password, submit), which is the
   one place the device tier cannot be avoided.
3. **Record** every request the SDK emits through an OkHttp `EventListener` plus an application
   interceptor installed on the client `configure()` was given — method, URL, headers, form
   parameters, the decoded DPoP proof claims — into a per-scenario JSON transcript.
4. **Assert** the scenario's `assertions:` against the transcript and the server's state
   (through Central's and auth's own APIs: was the family revoked, how many rotations did the
   server record, is the refresh token still live).
5. **Compare** the transcript with the reference client's for the same scenario
   (`e2e/.../support/OAuthClient`, `NativeAppFlowSpec`), ignoring `jti`, `iat` and nonce
   values. A divergence is a failure, and the diff is the report (#15, "one report").

## Providers

Issue #46 (B4): the scenarios tagged `facade: [oauth]` run the generic `OAuthClient` facade
against an OpenID Provider other than Versola, staged in Docker from `providers/<name>/`. The
driver is `android/conformance-oauth`: Robolectric is there only because `OAuthClient.create`
takes a `Context` for its storage directory; the network is real.

```bash
docker compose -f conformance/providers/keycloak/docker-compose.yml up -d --wait
cd android && OAUTH_CONFORMANCE_ISSUER=http://localhost:8080/realms/conformance \
  OAUTH_CONFORMANCE_PROVIDER=keycloak ./gradlew :conformance-oauth:testDebugUnitTest

docker compose -f conformance/providers/hydra/docker-compose.yml up -d
cd android && OAUTH_CONFORMANCE_ISSUER=http://localhost:4444 \
  OAUTH_CONFORMANCE_PROVIDER=hydra ./gradlew :conformance-oauth:testDebugUnitTest
```

Without `OAUTH_CONFORMANCE_ISSUER` every test is skipped (a JUnit assumption), so the build
job's `./gradlew test` stays a unit run. `OAUTH_CONFORMANCE_USERNAME` / `_PASSWORD` default to
the provider's test user. Keycloak imports its realm at container start and leaves an existing
realm alone, so `down` before `up` after editing `realm.json`; Hydra keeps everything in memory
and a one-shot container imports `clients.json` after each start.

The iOS driver is the same design in Swift, run from the repository root against the same
containers, on the host or on a simulator (`xcodebuild` forwards `TEST_RUNNER_`-prefixed
variables to the test process):

```bash
OAUTH_CONFORMANCE_ISSUER=http://localhost:8080/realms/conformance OAUTH_CONFORMANCE_PROVIDER=keycloak \
  swift test --filter OAuthConformanceTests
TEST_RUNNER_OAUTH_CONFORMANCE_ISSUER=http://localhost:4444 TEST_RUNNER_OAUTH_CONFORMANCE_PROVIDER=hydra \
  xcodebuild test -scheme Versola -destination "platform=iOS Simulator,name=iPhone 17" \
  -only-testing:OAuthConformanceTests
```

Its proxy is in process: a `URLProtocol` on the SDK's and the browser leg's sessions
(`VirtualNetwork`) forwards the proxy origin `http://localhost:14444` to the real provider
with that origin as `Host` (`URLSession` honours a custom `Host` header), so no listener is
opened and the same code runs on a simulator; the resource origins are virtual too. The
login conversation, the provider profiles and the scenario assertions are the Android
driver's, ported one to one. The virtual network is one per process, reset by each test, so
this target runs serially only: do not enable parallel testing for it (`swift test
--parallel`, Xcode's parallel testing). It has no CI job: GitHub's macOS runners have no
Docker daemon, so the iOS driver runs locally and the PR says which provider it ran against.

What differs per provider is a `Provider.Profile` in the driver: the issuer's path, the proxy's
port, the scopes that buy a refresh token, the login conversation. Keycloak derives its issuer
from the request, so the proxy takes any free port; Hydra builds every URL from `urls.self` in
`hydra.yml`, which therefore names the proxy's fixed port 14444 (`OAUTH_CONFORMANCE_PROXY_PORT`
overrides it), and its login and consent redirects go through the proxy as well. Hydra's
user-facing half is Ory's reference login-consent app (`foo@bar.com` / `foobar`, consent
granted for every requested scope, logout confirmed), driven by `HydraLogin`. A refresh token on
Hydra needs `offline_access`, so the main client's scopes include it there and the
refresh-less client's do not; Hydra 26.2 advertises no PAR, so scenario 29's two PAR tests skip
by assumption and its two `ProviderUnsupported` tests run.

How it drives the provider:

- **`ProviderProxy`**, a MockWebServer in front of the provider that forwards every request
  with its own origin as `Host`. Keycloak in development mode derives its issuer, endpoints
  and login-form action from the request, so it announces the proxy as itself and the SDK's
  issuer check, the ID token's `iss` and the redirect's `iss` agree. The proxy is also the
  fault-injection seam: `omit-discovery-field` is a rewrite of the discovery document, an
  ID-token fault is a re-signed `id_token` under a substituted JWKS, a dead revocation endpoint
  is a canned 503, and the server's clock is a `Date` header it adds.
- **`HttpLoginBrowser`**, the browser leg over HTTP: follows the provider's redirects, submits
  the test user's credentials through the provider's `ProviderLogin` (Keycloak's
  `kc-form-login`), and hands the SDK the redirect to the client. It keeps cookies per name
  and sends them `Secure` or not, as a browser does on loopback.
- **`ResourceServer`**, a protected resource that accepts the provider's access tokens by
  asking its UserInfo endpoint, and answers 401 with a `Bearer` challenge otherwise.
- **`DpopResourceServer`** (scenario 33), a resource that verifies DPoP itself, holding only the
  provider's public keys: the access token's RS256 signature, issuer, expiry and `cnf.jkt`; the
  `DPoP` scheme and exactly one proof; the proof's `typ`, `alg`, public `jwk`, signature, `htm`,
  `htu`, `iat` window, unseen `jti`, `ath` and the `jwk` thumbprint against `cnf.jkt`; and,
  when told to, a nonce (`force-dpop-nonce` / `always-demand-dpop-nonce` for a resource). It
  records a verdict with the reason for every request, so a negative test asserts which check
  refused, and it shares no code with the SDK's proof builder. Its `assertStolenTokenIsRefused`
  holds the cases (no proof, Bearer, another key, wrong `ath` / `htu` / `htm` / `iat`, two proofs,
  a re-bound token) and a control request that is accepted; the proofs of those cases are signed
  with the SDK's own key, reached through the driver's key store (below), so each refusal is one
  claim's and not a forger's.
- **The DPoP key** (scenario 33). A JVM has no Android Keystore, so the Android driver registers
  `SoftwareAndroidKeyStore` as the `AndroidKeyStore` JCA provider: the SDK's own `KeystoreDpopKey`
  runs unmodified and is handed a plain P-256 key pair, with StrongBox refused as on a phone without
  it and no security level to read back. The tier it reports, and so the tier the scenario proves,
  is **Software**. The iOS driver passes the SDK's `SecureEnclaveDpopKey` an in-memory store and
  tells it no Secure Enclave exists (an unsigned host's Keychain refuses it, -34018, and a
  simulator has none): software again. The Keystore's StrongBox and TEE tiers and the Secure
  Enclave tier are the device tier's, and a scenario 33 run says nothing about them.
- **`Transcript`**, a network interceptor on the SDK's client; the assertions read it, and the
  browser leg uses a separate client so its traffic never appears there.

What this tier does not prove for the generic facade: Custom Tabs / Auth Tab and redirect
delivery (the browser leg, [below](#the-browser-leg)); the Keystore and Secure Enclave key tiers under DPoP (scenario 33 proves the
protocol with a software key; the tiers are device tier); the DPoP case of scenario 32 (the
authenticated client's `htu` and `ath` are asserted by scenario 33); the `http`
origin case of scenario 32 (the facade allows `http` on loopback, where the proxy and the
resources live); scenario 31's clock step, which is real time against ten-second tokens rather
than a moved device clock; and the comparison with a reference transcript. Keycloak sends no
`Date` header on its token response, so the server-time path is exercised through the
proxy's header only.

### Through the Flutter bridge

The Flutter plugin (`flutter/versola_oauth`) is a binding over the native generic facades, so
scenarios 24 to 33 run once more through it: a scenario that passes natively and fails through the
bridge is a finding in the bridge (`.claude/rules/flutter.md`). Dart cannot reach the driver's
wiring (the replaced browser leg and stores sit behind `@VersolaInternalApi` on Android and
`package` access on iOS), so the drivers live natively in the example app's test targets and send
every operation through the plugin's generated Pigeon host API the way Dart does:

- **Android**: Robolectric tests in `flutter/versola_oauth/example/android/app/src/test`. The
  plugin's `VersolaOAuthPlugin` is attached to a fake `BinaryMessenger`; `DartSide` encodes each
  call with the plugin's own codec on the channel name the generator derives, and decodes the typed
  result. The state stream is subscribed through the event channel with the `listen` and `cancel`
  calls Dart makes.
- **iOS**: XCTest in `flutter/versola_oauth/example/ios/RunnerTests`, the same shape over a fake
  `FlutterBinaryMessenger` and `FlutterPluginRegistrar`, run on a simulator.

**Shared, not copied.** The support classes of the native drivers (`Provider`, `ProviderProxy` /
`VirtualNetwork`, `HttpLoginBrowser`, `Transcript`, `ResourceServer`, `DpopResourceServer`,
`SoftwareAndroidKeyStore`, `HarnessSigner`, `ProviderConformance`) are compiled from `android/conformance-oauth/src/test/kotlin` and
`ios/Tests/OAuthConformanceTests` where they live: the Gradle test source set of the example app
names that directory and filters out its `Scenario*` files, and `RunnerTests` references the Swift
files in place. A support module or symlinks would move or alias the native driver's files, which other changes
are editing. A file added to or removed
from `ios/Tests/OAuthConformanceTests` must also be added to or removed from the `RunnerTests`
target (the project lists the files by name; the Scenario files stay out), and the example's Gradle
test pins and plugin versions follow `android/conformance-oauth` and `android/build.gradle.kts`
(`develop.md`). The bridge scenarios are the native ones, test for test (27 on each platform for
scenarios 24 to 32; eleven of scenario 33's fourteen, so 38 per platform against Keycloak), so the pass counts
are comparable; the tests whose assertions differ from their native twin (24, 31's second test, 32 and
33) carry `bridge` in their names, and the next paragraphs say how.

**How the wiring gets in.** The test builds the native client first, with the driver's browser,
key provider or stores, and then calls the plugin's `create` through the host API with the
equivalent `ConfigurationMessage`. The SDK keeps one instance per configuration and returns the
first to a second `create` with the same configuration, so the plugin ends up holding the driver's
client. A message that converts any field differently from the native configuration is not found
there and `create` is refused, which fails the test at its first line. What the bridge does not
carry (`metadata()`, the retry policy) is read off the native instance and never used to drive.
The plugin itself is unmodified and never calls the opt-in wiring. Every test also checks that no
refresh token, raw ID token, authorization code or PKCE verifier appeared in any reply or event,
and that the access token appeared only in the reply of `accessToken()`.

**What is not the same as natively.** Flutter's authenticated client is `OAuthClient.httpClient()`
(`spec/oauth-sdk-api.md` section 10): the Dart client sends one `httpRequest` call and the plugin runs
it with `OAuthClient.call` (Android) or `authenticatedSession` (iOS). The bridge tests of scenarios 32
and 33 therefore send the request as the Dart client does (`DartSide.httpRequest`) and read what
reached the wire off the SDK's transcript, which is the native tests' own observation. Scenario 32
asserts through it: the token goes to the configured origin with any path and query and to no other
(another port, another host name: no `Authorization`, no refresh), a redirect is returned with its
`Location` and not followed, per-client `origins` replace the configured ones, an empty or non-https
set (and a configuration with no `protectedOrigins` that names none) is `InvalidConfiguration` before
anything is sent, an `Authorization` or `DPoP` header the app set is replaced on a protected origin and
left as written elsewhere, a 401 refreshes once and replays the request with its body, a second 401 is
`sessionRejected`, a step-up challenge is `StepUp` with no refresh, a 503 with `Retry-After` is the
response after one request, request and response bytes cross unchanged, and a call that produced no
HTTP response is a transport failure naming the exception class only. Two tests keep the older shape on
purpose (the token `accessToken()` returns is accepted at the resource; `create` refuses a
`protectedOrigins` entry that is not an origin). `create` accepts an empty `protectedOrigins`, so the
scenario's "constructing with an empty set" assertion is the first request through the client. A
repeated response header keeps both values on Android; on iOS the virtual network answers with a
header dictionary and `URLSession` folds repeated headers, so that assertion is Android's alone.
Scenario 31's second test waits for the expiry through `userInfo()` instead of the authenticated
client. The spec follows: `32-protected-origins.yaml` lists `flutter` with its notes, and
`24-generic-happy-path.yaml` notes which of its assertions the native facades make.

Scenario 33 is the same: its bridge tests named `HttpRequest` send a request to the harness's DPoP
resource server through the client and assert the DPoP scheme, the proof's `htm`, `htu` without the
query, `ath` and `jwk` thumbprint equal to `cnf.jkt`, the server's own verdict (accepted), the
resource's nonce challenge retried once and remembered for the origin, a server that keeps challenging
ending in `NonceLoop` after two requests, and an app-supplied `Authorization` or `DPoP` replaced so the
resource sees exactly one of each, with no token ever handed to Dart. Flutter mints no proof, and the
replay of a proof the SDK itself sent needs the harness to reach the SDK's request, so that one stays
the native drivers' alone (`33-dpop-end-to-end.yaml` says so in its `notes`). The rest is asserted with
the token `accessToken()` returns (`tokenType` `DPoP`, which a Flutter app cannot present): the
binding on the wire, the key kept across a refresh, `userInfo()` and `logout()` under DPoP, the
provider's nonce challenge and the `dpop_jkt` refusal, the stolen-token refusals, `requireHardware`
(`dpopRequireHardware`) refused as `hardwareBindingUnavailable`, and a Bearer-configured client
against the DPoP-requiring one.

Two things about what the state-stream check can see. Its `cancel` assertion reads the native
side, not Dart's receipts: the messenger counts every message the plugin sends on the channel, kept
after the test's own listener is gone. On Android the engine's event channel itself drops what a
cancelled sink is sent, so the count alone could not tell a cancelled collection from a live one;
the Android test also reads how many collections the plugin's scope has running (its private
`scope`, so a rename fails the test).

Run commands are in `develop.md` ("Provider containers"). Like the native drivers, both skip
without `OAUTH_CONFORMANCE_ISSUER`, and neither has a CI job: the Android one could run beside
`:conformance-oauth`, the iOS one cannot (no Docker on GitHub's macOS runners), so the pull request
names which tier ran.

## The browser leg

The conformance tier above replaces the browser with an HTTP conversation (`HttpLoginBrowser`), so
it cannot say whether the system browser does what the SDK assumes of it. This tier does: the
generic facade signs in against **Keycloak only** (one provider is enough to prove the platform
half; a second adds a login form to maintain and nothing to the leg) through the real system
browser on an emulator and a simulator, driven the way a user drives it.

| | Android | iOS |
|---|---|---|
| Host app | `android/conformance-browser-app`: a debug-only app whose screen is a log of what the SDK did (`state: ...`, `login: ok`, `claims: ...`, `logout: ...`) and which writes the same lines to `files/log.txt` | `ios/BrowserLegHost`, same log on screen |
| Tests | `android/conformance-browser`: UI Automator, a separate instrumentation package, so a test can kill the host app's process and keep running | `ios/BrowserLegHost/UITests`: XCUITest |
| Browser | Chrome: Custom Tabs fallback, and Auth Tab where Chrome offers it | `ASWebAuthenticationSession`, the system's "wants to use localhost to sign in" prompt answered |
| Redirect | the private-use scheme `com.example.versola.devicetier://app/oauth` (`RedirectUriKind.CustomScheme`) | the same scheme |
| Provider side | Keycloak's admin API: whether alice holds a session at the provider after sign-in and after sign-out | the same |

The host apps are also small example apps over the whole public surface (sign in, ephemeral
sign in, access token, refresh, sign out, with the session state on screen), usable by hand: launch
them with the issuer and press the buttons.

What each test asserts, and runs:

- **Sign-in, claims, token, logout** (scenarios 01 and 18): the tab opens on the provider's own
  login page, alice's credentials from `realm.json` are typed into it, the redirect returns to the
  app, the state goes `Authorizing` then `Authenticated`, `claims` hold alice, `accessToken()`
  returns a token the provider's UserInfo accepts, and `logout()` reports `sessionEnded` and
  `tokenRevoked` while Keycloak's admin API shows the session gone.
- **Cancel** (the cancel table of `spec/state-machine.md`): back, or the tab's close button
  (Android), the sheet's Cancel (iOS), is `Recoverable(UserCancelled)`, and the pending request is
  wiped: a cold start afterwards reports `Unauthenticated`, where a kept request would report
  `Authorizing`.
- **Background and back**: the app sent to the background with the tab open and returned to
  through the recent apps (Android) or `activate()` (iOS) is not a cancel; the pending request is
  kept and the sign-in completes.
- **Process death with the browser open** (scenario 12): on Android the process is killed with
  the tab open (`run-as ... kill -9`), the sign-in is finished in the tab, and the redirect
  cold-starts the app, which observes `Authorizing` and never `Unauthenticated`, and the sign-in
  completes on its own (`provider keycloak`, Custom Tabs leg). On iOS the app is terminated with
  the sheet open and a redirect is opened against it by the system.
- **A redirect that is not the request's** (scenario 15): a redirect for the configured redirect
  URI with a made-up `state`, or none, is ignored: no token request, no failure, and the login
  waits on. On Android it is fired at the exported redirect activity of a live login (both
  browser legs): the tab stays in front, the genuine sign-in in it still completes, and the user
  closing the tab afterwards is still a cancel. On iOS it is opened by the system against a
  terminated app that the redirect cold-starts: the restored request survives, in this process and
  the next. On Android an intent for a URI that is not the redirect at all is ignored the same
  way (Custom Tabs leg). A redirect that ends the browser surface itself (an Auth Tab result, an
  `ASWebAuthenticationSession` completion) cannot be produced by a third party and is proven one
  tier down only (`ended(_:expectedState:logger:)` on iOS, the trampoline's result on Android).

What it does not prove, and why (each is also a row in the PR's "Gaps left"):

- **Scenario 12's last assertion, on iOS, through the real browser leg.** The cold-started app
  restores `Authorizing` and the redirect reaches it, and a redirect with a made-up `state` is
  refused, but the test cannot deliver a genuine redirect: the `state` is the SDK's secret and the
  sheet dies with the app, so the UI test proves delivery and refusal, not completion. Completion
  is proven one tier down, against the same Keycloak, by `Scenario12ProcessDeathBrowserTest` in
  `ios/Tests/OAuthConformanceTests`: a second client over the first one's stores, the redirect
  produced by the HTTP login conversation, the restored `code_verifier` and `nonce` accepted by the
  provider and by the ID-token check. That test replaces the system browser and the process death
  with a second client; the pieces it does not run are the ones this tier does.
- **Auth Tab.** The emulator's Chrome (133, the Play Store image) answers that it has no Auth Tab
  support even with its `cct-auth-tab` flag enabled, so the SDK falls back to Custom Tabs, which is
  what ran. The Auth Tab rows exist and skip by assumption when the log says so.
- **A system cancel** (iOS `canceledLogin` while the app is in the background): the simulator offers
  no way to make the OS tear the session down, so only the user-cancel half of the rule runs.
- **A verified App Link or Universal Link.** Both need a host this machine does not control
  (`assetlinks.json`, `apple-app-site-association` over https), so the redirect kind proven is the
  private-use scheme.
- **Hydra and the Versola facade.** One provider on purpose; the Versola facade's browser leg is
  the same code but its stack is not staged here.

Run it (`develop.md`, "The browser leg on an emulator and a simulator", has the recipes): the
tests are skipped, not failed, without the issuer in the instrumentation arguments (Android) or
the test runner's environment (iOS), so `connectedDebugAndroidTest` elsewhere and a plain
`xcodebuild test` stay unchanged. `conformance.yml` runs the Android half in its `browser-leg` job
(Keycloak, an API 36 emulator); the iOS half has no CI job, because GitHub's macOS runners have no
Docker daemon, so it runs locally and the PR says what it ran against.

## Fault injection

The capabilities `spec/conformance/README.md` lists, and where each lives:

| Capability | Mechanism |
|---|---|
| `drop-response` | A small TCP proxy in front of auth and edge (`stack/chaos`) that, on a control call from the driver, lets the next matching request through and discards the response. |
| `force-dpop-nonce`, `always-demand-dpop-nonce` | The same proxy, answering a scripted `use_dpop_nonce` for the next N requests to an origin. For the generic facade, a resource that demands a nonce (`DpopResourceServer(nonce = …)`, which answers `use_dpop_nonce` to every proof without it, and with `offered` different from `nonce` keeps challenging a client that retries), and, for the provider's token endpoint, the proxy answering a canned 400 `use_dpop_nonce` with a `DPoP-Nonce` header once or on every request (`ProviderProxy.intercept` / `VirtualNetwork.intercept`; scenario 33). |
| `clock-skew` | `adb shell date` on the emulator before the scenario, restored after. For the generic facade's JVM driver, a `Date` header the proxy adds (the server's clock) and short-lived tokens (scenario 31); the device clock is not moved. |
| `process-death` | `adb shell am kill` on the harness package at the named point; the test re-launches through `am instrument` with the scenario's second half. |
| `omit-discovery-field` | The proxy rewriting `/.well-known/openid-configuration`. For the generic facade, `ProviderProxy.rewriteJson` in `android/conformance-oauth`. |
| `network-partition` | `adb shell svc wifi disable` / `svc data disable` for a bounded window. |

## Running it

In CI, the `scenarios` job of `.github/workflows/conformance.yml` stages the stack the way
`versola`'s own CI does, boots the emulator, installs the driver and runs it with the stack's
addresses as instrumentation arguments. It is on demand only, and has not run yet: the checkout of
the private server repository needs the `VERSOLA_CHECKOUT_TOKEN` secret, which does not exist, and
the nightly trigger takes over once it does. The same run by hand against a stack on the host (the
emulator reaches it at `10.0.2.2`, or through `adb reverse`, `develop.md`):

```bash
./gradlew :conformance-android:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.authUrl=http://10.0.2.2:9003 \
  -Pandroid.testInstrumentationRunnerArguments.centralUrl=http://10.0.2.2:9001 \
  -Pandroid.testInstrumentationRunnerArguments.edgeUrl=http://10.0.2.2:9005
```

## Order of work

1. ~~The driver skeleton and scenario 01 on `BackChannel.Auth` against a `standard` tenant.~~
   Done; the browser leg is the HTTP conversation rather than UI Automator, which turned out
   to be both deterministic and enough.
2. ~~Scenario 21 on `BackChannel.Edge`: a `fapi2` tenant, a native client with an edge
   certificate issued by Central (`issueEdgeClientCertificate`), edge's `native` block.~~ Done.
3. Scenarios 08 (concurrent refresh, asserting one rotation server-side), 10 and 14 (step-up
   through a resource with `stepUpAcr`), 15–17 and 20 — no fault injection needed.
4. The proxy, then scenarios 03–06 and 23 (nonces, skew), 09 and 13 (dropped responses,
   process death), 12 (process death mid-browser, through `am kill` and a second
   instrumentation run).
5. The reference-transcript comparison, which is what turns the above from "it works" into
   "it is equivalent".
6. `conformance.yml` on a schedule once a `VERSOLA_CHECKOUT_TOKEN` secret exists.
7. iOS, unchanged scenarios, once #11–#14 exist.
8. ~~The generic facade against Keycloak (scenarios 24–33, `android/conformance-oauth`).~~ Done.
9. ~~The generic facade against Ory Hydra (`providers/hydra/`, `HydraLogin`).~~ Done; 25 of
   27 tests, the two PAR tests skipped by assumption.
10. ~~The iOS driver for the generic facade (`ios/Tests/OAuthConformanceTests`).~~ Done, local
    runs only (no Docker on the macOS runners).
11. The hosted providers on demand (`spec/providers.md` section 4).
