# Conformance harness

Issue #15. Runs the scenario catalogue under [`../spec/conformance/`](../spec/conformance/)
against a **real staged `auth` + `central` + `edge`** from `versolauth/versola`, once per SDK,
and asserts identical observable behaviour.

**Status.** The Android driver exists as `android/conformance-android` (instrumented tests;
nothing is published from it) and runs scenarios 01 and 21 — with the refresh, revocation and
logout steps of 02, 11 and 18 and the blob-less replay of 22 — green against a stack staged
from `versolauth/versola` at `d6203f93`, from an emulator. The rest of the catalogue, the
fault-injection proxy and the transcript comparison with the reference client are the order
of work at the bottom. iOS has no driver yet.

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

## Fault injection

The capabilities `spec/conformance/README.md` lists, and where each lives:

| Capability | Mechanism |
|---|---|
| `drop-response` | A small TCP proxy in front of auth and edge (`stack/chaos`) that, on a control call from the driver, lets the next matching request through and discards the response. |
| `force-dpop-nonce`, `always-demand-dpop-nonce` | The same proxy, answering a scripted `use_dpop_nonce` for the next N requests to an origin. |
| `clock-skew` | `adb shell date` on the emulator before the scenario, restored after. |
| `process-death` | `adb shell am kill` on the harness package at the named point; the test re-launches through `am instrument` with the scenario's second half. |
| `omit-discovery-field` | The proxy rewriting `/.well-known/openid-configuration`. |
| `network-partition` | `adb shell svc wifi disable` / `svc data disable` for a bounded window. |

## Running it

Not yet. When it exists: `.github/workflows/conformance.yml` (nightly and on demand) stages
the stack the way `versola`'s own CI does, boots the emulator, installs the driver and runs
it with the stack's addresses as instrumentation arguments:

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
