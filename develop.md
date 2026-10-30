# Developing the SDKs locally

How to build, test and run this repository on a development machine. CI runs the same
commands (`.github/workflows/`); if a command here and a workflow disagree, the workflow is
right and this file is stale.

## Toolchains

| Tool | Version | Used for |
|---|---|---|
| JDK | 17 | Gradle, the Android modules (`sourceCompatibility` is 17) |
| Android SDK | platform 37.0, build-tools 36.0.0 | `compileSdk` 37 in every module; `minSdk` is 26 |
| Android Gradle Plugin | 9.5.0 | pinned in `android/build.gradle.kts` |
| Kotlin | 2.4.21 | pinned in `android/build.gradle.kts`; `explicitApi()` is on |
| Gradle | 9.7.1 | through the wrapper, never a system Gradle |
| Xcode | 16.3 or newer, with an iOS simulator | `Package.swift` (swift-tools 6.0, Swift 6 language mode) |
| Flutter | 3.47.8 (Dart 3.13.7) | pinned in `flutter/.fvmrc`, run through [fvm](https://fvm.app) (`brew install fvm`, then `fvm install` in `flutter/`) |
| Python | 3.12 | `tools/validate-scenarios.py` |
| Docker | any recent | the conformance stack and, once #46 lands, the provider containers |
| jq | any recent | the agent hooks under `.claude/` |
| Node | 22 | `npx markdownlint-cli2` |

Gradle needs a JDK 21 on `JAVA_HOME` (Robolectric's android-all image for API 36 requires
it; the artefacts' bytecode stays Java 17). A different JDK as the default breaks the Android
build in ways that look like plugin errors, so point `JAVA_HOME` at 21 explicitly:

```bash
export JAVA_HOME=~/Library/Java/JavaVirtualMachines/corretto-21.0.4/Contents/Home
export ANDROID_HOME=~/Library/Android/sdk
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"
```

Install the Android platform once. `compileSdk` is 37, so the build needs `platforms;android-37.0`
(the sdkmanager id carries the minor version; there is no `platforms;android-37`) and
`build-tools;36.0.0`, AGP 9.5.0's default. CI installs exactly this pair in every workflow that
builds Android. API 36 is separate: the emulator image of the instrumented job and the API level
Robolectric emulates, neither of which needs the platform package:

```bash
yes | "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" "platforms;android-37.0" "build-tools;36.0.0"
```

## Layout

```text
spec/            normative: state machine, errors, retry policy, conformance scenarios
android/         Gradle multi-project: oauth-core (protocol engine, plain Kotlin/JVM), core (the
                 edge back channel), dpop, storage, browser, okhttp, sdk (the Versola facade),
                 oauth (the generic OAuthClient facade)
ios/Sources/     Swift targets (OAuthCore, OAuthClient; Versola* placeholders); the manifest is Package.swift at the repo root
flutter/         versola_oauth: the Flutter binding (Pigeon bridge over the native facades)
conformance/     harness driving every SDK against a staged Versola stack
tools/           validate-scenarios.py, the release scripts, verify-consumer/ (throwaway consumer apps, below)
```

`Package.swift` is at the root because SPM cannot resolve a manifest from a subdirectory. Its
targets point into `ios/`.

## Commands

### Android

Run from `android/`. The first three are what `android.yml` runs on every pull request.

```bash
cd android
./gradlew assemble test lint apiCheck   # the whole CI job
./gradlew :sdk:test                     # one module's unit tests (Robolectric, MockWebServer)
./gradlew apiDump                       # regenerate android/*/api/*.api after a public change
./gradlew :storage:connectedDebugAndroidTest   # device tier: real Keystore, needs an emulator
```

`apiCheck` fails when a public signature differs from the committed `.api` dump. If the change
is intended, run `apiDump` and commit the dump in the same pull request; the diff of the dump
is the public API change the PR template asks you to declare. AGP 9's built-in Kotlin is opted
out in `android/gradle.properties` because it does not work with
kotlinx-binary-compatibility-validator; do not remove that without checking the upstream issue
named there.

`connectedDebugAndroidTest` needs the `androidTest` source sets, which arrive with the
instrumented job (PR #44). Until then it has nothing to run on `main`.

### iOS

Run from the repository root. These are the `ios.yml` steps.

```bash
swift package resolve
xcodebuild build -scheme Versola-Package -destination "platform=iOS Simulator,name=iPhone 17"
xcodebuild test  -scheme Versola-Package -destination "platform=iOS Simulator,name=iPhone 17"
```

`swift build` and `swift test` on the Mac host work too (the manifest lists macOS 14.4, so the
AuthenticationServices, Keychain and CryptoKit APIs compile there), and are the fast loop; the
Keychain round-trip test runs only with `OAUTH_KEYCHAIN_TESTS=1`. `xcodebuild` with a simulator
destination is what CI runs and is the run to report. The simulator name is whatever your Xcode ships. CI's name drifts on
Xcode upgrades (it moved from "iPhone 16" to "iPhone 17"); list yours with
`xcrun simctl list devices available` and use the same name if it exists.

### Flutter

Run from `flutter/versola_oauth/`. Flutter is pinned in `flutter/.fvmrc`; `fvm install` in
`flutter/` fetches it once, and every command goes through `fvm` so the system Flutter, if any,
is never used. No protocol logic lives in Dart: the binding calls the native SDKs through Pigeon.

```bash
fvm dart run pigeon --input pigeons/messages.dart   # regenerate the bridge after editing the contract
fvm dart format --set-exit-if-changed .
fvm flutter analyze
fvm flutter test                                    # Dart unit tests, bridge mocked
cd example && fvm flutter build apk --debug          # the example app on Android
cd example && fvm flutter build ios --no-codesign    # and on iOS
cd example/ios && xcodebuild test -workspace Runner.xcworkspace -scheme Runner \
  -destination "platform=iOS Simulator,name=iPhone 17" -only-testing:RunnerTests   # the Swift glue's unit tests
cd example/android && ./gradlew :versola_oauth:testDebugUnitTest                  # the Kotlin glue's unit tests
```

The example's Android build includes `android/` as a composite build and substitutes the
`io.versola:oauth-android` artefact, which is not published yet, with the `:oauth` project; it
needs the same `JAVA_HOME` (21) and `ANDROID_HOME` as the Android build. The iOS half depends on
the repository package by path (Swift Package Manager only; the SDK is not on CocoaPods).

The bridge conformance tests are the example app's native tests (below, "Provider containers"):
Robolectric unit tests under `example/android/app/src/test` and XCTest in `example/ios/RunnerTests`.
Both are skipped without a provider in the environment, so `flutter build` and a plain
`xcodebuild test` of the example stay unit runs.

### Publishing (a local look only)

Releasing is the maintainer's (`docs/releasing.md`). What a developer can run, from `android/`,
publishes nowhere: it writes the Maven bundle that would be uploaded to a local directory.

```bash
./gradlew centralBundle -PreleaseVersion=0.1.0 -PallowUnsignedBundle   # android/build/central-bundle/versola-0.1.0.zip
tools/check-release-version.sh 0.1.0                                     # from the repository root; reads files only
```

### What a consumer installs (throwaway apps)

`tools/verify-consumer/` builds an app outside the repository from what is *published*, which no
build of the checkout can show. Run from the repository root; each exits non-zero on failure and
needs no secrets. `verify-release.yml` runs the three after a release; `flutter.yml` runs the Flutter
one against every pull request's commit.

```bash
tools/verify-consumer/android.sh 0.1.0   # app with mavenCentral() + google() only, io.versola:oauth-android:0.1.0, assembleDebug (JDK 21, ANDROID_HOME)
tools/verify-consumer/ios.sh 0.1.0       # SwiftPM package on the public repository at exactly 0.1.0, product VersolaOAuth, xcodebuild for the iOS simulator
tools/verify-consumer/flutter.sh 0.1.0   # flutter create + versola_oauth as a git dependency at that ref, flutter build apk and (macOS) ios
VERIFY_REPO_URL="file://$PWD" tools/verify-consumer/flutter.sh "$(git rev-parse HEAD)"   # the same, against your committed work
```

`flutter.sh` takes any git ref and finds Flutter in `~/fvm/versions/<pinned>` when it is not on
`PATH`; `VERIFY_KEEP=1` keeps the generated app for a look. The Android and iOS scripts take a
version, which must already be published (Maven Central, a pushed tag).

### Spec and Markdown

```bash
pip install -r tools/requirements.txt
python3 tools/validate-scenarios.py          # every spec/conformance/*.yaml against schema.json
npx markdownlint-cli2 "**/*.md"              # rules in .markdownlint-cli2.jsonc
```

Both run in `spec.yml`. A scenario file that does not validate fails CI, and a spec change
without a scenario change needs a reason in the pull request.

## Emulator

Create or reuse an AVD on API 36; the maintainer's is `Medium_Phone_API_36.0`.

```bash
emulator -list-avds
emulator -avd Medium_Phone_API_36.0 -no-snapshot-save &
adb wait-for-device
adb devices
```

The emulator's `localhost` is its own. To reach a stack running on the host at the addresses
its configuration announces, forward those ports with `adb reverse` rather than rewriting URLs
to `10.0.2.2`: the SDK holds the discovery document to the issuer it was configured with, so
an issuer that differs from the one the server announces is rejected, correctly.

```bash
adb reverse tcp:9001 tcp:9001
adb reverse tcp:9003 tcp:9003
adb reverse tcp:9005 tcp:9005
```

`adb reverse` is cleared when the emulator restarts. Run it again after every cold boot.

## Running the conformance driver against a staged Versola stack

The harness (issue #15, `conformance/README.md`) runs the scenario catalogue in
`spec/conformance/` against a real `auth` + `central` + `edge` and asserts the observable
behaviour the spec describes. The Android driver is `android/conformance-android`; it arrives
with PR #44 and is not on `main` until that merges. It runs scenarios 01 and 21 today.

The stack is staged from a checkout of `versolauth/versola` following that repository's
`develop.md` (central 9001, auth 9003/9007/9008, the internal TLS terminator, edge 9005,
Postgres on 5432). It is staged from a checkout rather than images because the e2e fixtures
the harness reuses live there and expect the `gen-env.scala` configuration that repository's
own CI generates.

With the stack up and an emulator booted:

```bash
# In a versola checkout: develop.md's local stack (central 9001, auth 9003/9007/9008,
# the internal TLS terminator, edge 9005), with Postgres on 5432.
adb reverse tcp:9001 tcp:9001 && adb reverse tcp:9003 tcp:9003 && adb reverse tcp:9005 tcp:9005
adb forward tcp:18080 tcp:18080
cd android && ./gradlew :conformance-android:connectedDebugAndroidTest
```

`adb forward` lets edge reach the upstream `MockWebServer` the driver runs on the device for
the proxied resource. Instrumentation arguments override the defaults in `Stack.kt`:
`authUrl`, `centralUrl`, `edgeUrl`, `centralSecret`, `edgeInternalSecret`, `upstreamPort`,
`upstreamUrlFromEdge`. Pass one with
`-Pandroid.testInstrumentationRunnerArguments.<name>=<value>`.

The browser leg in this tier is auth's login conversation driven over HTTP, not an Auth Tab or
Custom Tab. Those, App Link delivery and the foreground-return detector are the device tier's to
prove, so a green conformance run does not cover them. For the generic facade against Keycloak that
proof exists: "The browser leg on an emulator and a simulator" below.

A scenario with no driver yet is proven against stubs only. Say so in the pull request.

## Provider containers

The generic facade (`OAuthClient`, issue #46) is proven against providers other than Versola
from `conformance/providers/<name>/`: a compose file plus the provider's pre-provisioned
configuration (Keycloak's `realm.json`: the `conformance` realm, the public clients
`conformance-app`, `conformance-app-norefresh` and `conformance-app-dpop` (the provider refuses it a
token that is not DPoP-bound; scenario 33), the user `alice`; Hydra's `hydra.yml` and
`clients.json`, with Ory's reference login-consent app as the user). The driver is
`android/conformance-oauth`, Robolectric unit tests over a real network, skipped unless the
provider's issuer is in the environment.

```bash
docker compose -f conformance/providers/keycloak/docker-compose.yml up -d --wait
cd android && OAUTH_CONFORMANCE_ISSUER=http://localhost:8080/realms/conformance \
  OAUTH_CONFORMANCE_PROVIDER=keycloak ./gradlew :conformance-oauth:testDebugUnitTest
docker compose -f conformance/providers/keycloak/docker-compose.yml down -v   # also before re-importing an edited realm.json

docker compose -f conformance/providers/hydra/docker-compose.yml up -d   # ports 4444, 4445, 3000; the proxy takes 14444
cd android && OAUTH_CONFORMANCE_ISSUER=http://localhost:4444 \
  OAUTH_CONFORMANCE_PROVIDER=hydra ./gradlew :conformance-oauth:testDebugUnitTest
```

The iOS driver runs against the same containers from the repository root, on the host
(`OAUTH_CONFORMANCE_ISSUER=… OAUTH_CONFORMANCE_PROVIDER=… swift test --filter OAuthConformanceTests`)
or on a simulator (the same variables with a `TEST_RUNNER_` prefix and
`xcodebuild test … -only-testing:OAuthConformanceTests`).

The Flutter plugin has the same scenarios through its bridge: the plugin's own Pigeon host API
is driven by native tests in the example app, with the driver's wiring underneath (see
`conformance/README.md`, "Through the Flutter bridge"). Against Keycloak, from
`flutter/versola_oauth/example/`:

```bash
export JAVA_HOME=$(/usr/libexec/java_home -v 21) ANDROID_HOME=~/Library/Android/sdk   # your SDK path
cd android && OAUTH_CONFORMANCE_ISSUER=http://localhost:8080/realms/conformance \
  OAUTH_CONFORMANCE_PROVIDER=keycloak ./gradlew :app:testDebugUnitTest

fvm flutter build ios --config-only --simulator   # once, and after a plugin change: writes the Swift package Xcode resolves
cd ios && TEST_RUNNER_OAUTH_CONFORMANCE_ISSUER=http://localhost:8080/realms/conformance \
  TEST_RUNNER_OAUTH_CONFORMANCE_PROVIDER=keycloak xcodebuild test -workspace Runner.xcworkspace -scheme Runner \
  -destination "platform=iOS Simulator,id=<udid from: xcrun simctl list devices available>" -only-testing:RunnerTests
```

The iOS target lists the native driver's support files by name: a file added to or removed from
`ios/Tests/OAuthConformanceTests` is also added to or removed from the `RunnerTests` target of
`flutter/versola_oauth/example/ios/Runner.xcodeproj` (the `Scenario*` files stay out). The Android
example takes the directory by itself, but its six test pins in `example/android/app/build.gradle.kts`
are a second copy of `android/conformance-oauth/build.gradle.kts`'s, as are its AGP and Kotlin plugin
versions in `example/android/settings.gradle.kts` of `android/build.gradle.kts`'s; change them together.

Name the simulator by `id` when two devices share a name. Hydra is the same with its issuer and
`hydra`. Do not enable parallel testing for `RunnerTests` (the scheme sets it off): the virtual
network is one per process, as in the native iOS driver.

A Keycloak container started before `conformance-app-dpop` was added to `realm.json` does not have
the client (the import leaves an existing realm alone): `down -v` and `up` it again, or scenario 33
fails at its first login. Scenario 33 skips itself on a provider that does not advertise ES256 DPoP
proofs (Hydra), with that reason. Its DPoP key is software-tier in every run described here (the JVM
and the iOS host or simulator have no secure element), so the Keystore's StrongBox and TEE tiers and the
Secure Enclave remain the device tier's; the run says so, the PR says so. The counts to expect:
Keycloak 41 tests on each native driver (27 + scenario 33's fourteen) and 38 through each Flutter bridge
(the iOS one runs 3 wire-mapping tests more); Hydra 25 passed and 16 skipped natively.

A run takes about a minute per provider, most of it scenario 31 waiting for ten-second tokens
to expire. `conformance/README.md` ("Providers") says how the proxy, the HTTP browser leg and the
resource server work, what differs per provider, and what this tier does not prove.

## The browser leg on an emulator and a simulator

The generic facade's real system-browser leg, against Keycloak: Chrome on an emulator and
`ASWebAuthenticationSession` on a simulator, driven by UI Automator and XCUITest the way a user
drives them (`conformance/README.md`, "The browser leg", says what is asserted and what is not
proven). Only Keycloak, on purpose. Both halves need the realm's `conformance-device` client, which
`realm.json` gained, so a Keycloak container started before that change needs `down -v` first:

```bash
docker compose -f conformance/providers/keycloak/docker-compose.yml down -v
docker compose -f conformance/providers/keycloak/docker-compose.yml up -d --wait
```

**Android.** An AVD on API 36 with Chrome (`google_apis` or `google_apis_playstore`), at least four
cores and 4 GB (the Pixel profile's default of one core and 2 GB made the system UI stop
responding under Chrome; the runs reported here had four and 4 GB). Create one with `avdmanager` if `Medium_Phone_API_36.0` is smaller, boot
it, and forward the provider's port so the issuer is the one its discovery announces:

```bash
emulator -avd Medium_Phone_API_36.0 -no-snapshot-save -no-window &
adb wait-for-device
adb reverse tcp:8080 tcp:8080
cd android && ./gradlew :conformance-browser:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.issuer=http://localhost:8080/realms/conformance
```

The tests drive `android/conformance-browser-app`, which `connectedDebugAndroidTest` installs next
to the test package. Without the `issuer` argument every test is skipped, so nothing else changes.
`adminUser` and `adminPassword` arguments override the compose file's throwaway `admin`/`admin`.
The first sign-in on a fresh Chrome profile answers its account and notification prompts; the
tests do that. A `[default]` row that reports skipped means the emulator's Chrome has no Auth Tab
(the host's log says "no Auth Tab support"); the `[customtabs]` rows run either way. Chrome 133,
as the Play Store image ships it, is such a Chrome.

**iOS.** A simulator, named by `id` when two share a name; the project resolves the repository
package by path, so no `swift package resolve` is needed first:

```bash
cd ios/BrowserLegHost
TEST_RUNNER_ISSUER=http://localhost:8080/realms/conformance xcodebuild test \
  -project BrowserLegHost.xcodeproj -scheme BrowserLegHost \
  -destination "platform=iOS Simulator,id=<udid from: xcrun simctl list devices available>"
```

`localhost` from the simulator is the host's, so nothing is forwarded. The app is signed ad hoc
(`CODE_SIGN_IDENTITY = -`): unsigned, it has no entitlements and the Keychain answers -34018. The
system asks "Open in ...?" the first time a custom-scheme URL is opened in a session; the tests
answer it. Without `ISSUER` in the runner's environment every test is skipped.

Both host apps double as small example apps over the generic facade: launch one with the issuer
(`adb shell am start -n versola.conformance.browser.app/.HostActivity --es issuer ...`, or the
`ISSUER` environment variable on iOS) and use the buttons by hand. `ios/BrowserLegHost` is not part
of `Package.swift`, and `xcodebuild -scheme Versola-Package` does not see it.

## Agent setup

Coding agents working in this repository read `AGENTS.md` (the shared policy; `CLAUDE.md`
imports it), `.claude/rules/` (rules scoped by path), `.claude/hooks/` (guards registered in
`.claude/settings.json` for Claude Code, run by hand from Codex as `AGENTS.md` describes; they need
`jq` on the `PATH`) and `REVIEW.md` (what a reviewer checks and what blocks a merge). The rules are
written so they keep holding after the planned `versola.*` package move (#46).

## Before you push

1. `cd android && ./gradlew test apiCheck` is green. Run `lint` too if you touched resources or
   the manifest.
2. `xcodebuild test -scheme Versola-Package -destination "platform=iOS Simulator,name=iPhone 17"`
   is green if anything under `ios/` or `Package.swift` changed.
3. `python3 tools/validate-scenarios.py` passes if anything under `spec/` changed, and
   `npx markdownlint-cli2 "**/*.md"` is clean if any Markdown did.
4. A public Kotlin change has its `apiDump` diff committed.
5. The pull request template is filled in: what changed, each test tier as ran, not run with a
   reason, or n/a, the public API change, the spec change, and the gaps left with links.

Work on a `feat/`, `fix/` or `chore/` branch, never on `main`. Commit messages are a short
imperative sentence in sentence case with no `feat:` prefix. Do not force-push.

## Security scans

The Security workflow runs on PRs, pushes to `main`, weekly on Monday at 05:00 UTC, and from
Actions → Security → Run workflow. TruffleHog checks PR/push ranges; Trivy and Semgrep also scan
on scheduled/manual runs. CodeQL covers Kotlin and Swift, and dependency review checks PRs.
See `SECURITY.md` for coverage limits and triage deadlines. Scanner failures must be investigated;
a skipped scanner is not a clean result.
