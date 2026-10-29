# Developing the SDKs locally

How to build, test and run this repository on a development machine. CI runs the same
commands (`.github/workflows/`); if a command here and a workflow disagree, the workflow is
right and this file is stale.

## Toolchains

| Tool | Version | Used for |
|---|---|---|
| JDK | 17 | Gradle, the Android modules (`sourceCompatibility` is 17) |
| Android SDK | platform 36, build-tools 36.0.0 | `compileSdk` 36 in every module; `minSdk` is 26 |
| Android Gradle Plugin | 9.4.1 | pinned in `android/build.gradle.kts` |
| Kotlin | 2.4.20 | pinned in `android/build.gradle.kts`; `explicitApi()` is on |
| Gradle | 9.7.1 | through the wrapper, never a system Gradle |
| Xcode | 16.3 or newer, with an iOS simulator | `Package.swift` (swift-tools 5.9) |
| Flutter | not installed yet | `flutter/` is a placeholder; the plan is to pin it with fvm |
| Python | 3.12 | `tools/validate-scenarios.py` |
| Docker | any recent | the conformance stack and, once #46 lands, the provider containers |
| jq | any recent | the agent hooks under `.claude/` |
| Node | 22 | `npx markdownlint-cli2` |

Gradle needs a JDK 17 on `JAVA_HOME`. A newer JDK as the default breaks the Android build in
ways that look like plugin errors, so point `JAVA_HOME` at 17 explicitly:

```bash
export JAVA_HOME=~/Library/Java/JavaVirtualMachines/ms-17.0.17/Contents/Home
export ANDROID_HOME=~/Library/Android/sdk
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"
```

Install the Android platform once, the way CI does:

```bash
yes | "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" "platforms;android-36" "build-tools;36.0.0"
```

## Layout

```text
spec/            normative: state machine, errors, retry policy, conformance scenarios
android/         Gradle multi-project: oauth-core (protocol engine, plain Kotlin/JVM), core (the
                 edge back channel), dpop, storage, browser, okhttp, sdk (the Versola facade),
                 oauth (the generic OAuthClient facade)
ios/Sources/     Swift targets; the manifest is Package.swift at the repo root
flutter/         plugin + Pigeon bridge (placeholder)
conformance/     harness driving every SDK against a staged Versola stack
tools/           validate-scenarios.py
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

Prefer `xcodebuild` with a simulator destination over `swift build` and `swift test`: it is
what CI runs, and the targets use iOS-only APIs (Keychain, Secure Enclave, ASWebAuthenticationSession)
that the host build target does not have. The simulator name is whatever your Xcode ships. CI's name drifts on
Xcode upgrades (it moved from "iPhone 16" to "iPhone 17"); list yours with
`xcrun simctl list devices available` and use the same name if it exists.

### Flutter

Not installed and not built yet. When the plugin lands, Flutter is pinned with fvm and this
section gets the `flutter analyze` and `flutter test` commands. No protocol logic lives in
Dart: the binding calls the native SDKs through Pigeon.

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
prove, so a green conformance run does not cover them.

A scenario with no driver yet is proven against stubs only. Say so in the pull request.

## Provider containers

Planned by #46, not present yet: `conformance/providers/` with compose files for Keycloak and
Ory Hydra, so the generic OAuth SDK can be exercised against providers other than Versola. When
they land this section gets the `docker compose up` commands and the realm and client setup. Until then
the only provider the harness runs against is a staged Versola stack.

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
