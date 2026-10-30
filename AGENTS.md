# Versola mobile SDKs

Native OAuth 2.0 / OpenID Connect SDKs for Android (Kotlin), iOS (Swift) and Flutter (a binding
over the native two), in one repository. Two families share one protocol core:

- the `Versola` facade, optimized for the Versola server (edge back channel, FAPI 2.0 security
  profiles, DPoP by default), and
- the generic `OAuthClient` facade, which works against any conforming provider (issue #46).

The shared artefact between platforms is not code. It is the specification under `spec/` (the
session state machine, the error taxonomy, the retry policy) and the conformance scenarios under
`spec/conformance/`, which every platform must pass. Issue #1 is the grounding document every
other issue assumes; read it before non-trivial work, then `README.md`, `spec/state-machine.md`,
`spec/errors.md` and `develop.md` (toolchains, running each tier locally).

This is an SDK that customers compile into shipped apps. A public type, parameter, default or
error case is a promise an app compiles against; `apiCheck` (Android), the Swift ABI and the Dart
API hold us to it. The API is production ready and the major version is still 0: interfaces
change only when a change is required, and every change to a public symbol is stated in the PR
together with the regenerated `android/*/api/*.api` dump. The versioning policy in
`.claude/rules/ci-release.md` applies. A secret (refresh token, key material) that leaks is a
vulnerability in every app that embeds the SDK, not a bug.

## Commands

```bash
cd android && ./gradlew assemble test lint apiCheck   # Android: every module; what android.yml runs
cd android && ./gradlew :oauth-core:test                 # one module (:core and the Android ones: :<module>:testDebugUnitTest)
cd android && ./gradlew apiDump                        # after a public API change; commit the .api files
cd android && ./gradlew :storage:connectedDebugAndroidTest   # device tier; needs a booted emulator
swift package resolve                                  # iOS: from the repo root (Package.swift lives here)
xcodebuild test -scheme Versola-Package -destination "platform=iOS Simulator,name=iPhone 16"   # pick a name from: xcrun simctl list devices available
python3 tools/validate-scenarios.py                   # spec: scenarios against spec/conformance/schema.json (pip install -r tools/requirements.txt once)
npx markdownlint-cli2 "**/*.md"                        # spec.yml's markdown job
```

Flutter commands (`flutter analyze`, `flutter test` in the plugin directory) apply once the plugin
exists; the toolchain pin is described in `develop.md`. JDK 21 is required for Gradle (`JAVA_HOME`);
the exact emulator and staged-stack recipes are in `develop.md`. Do not paste them from memory.

## Definition of Done

A change is done when all of these hold; if one does not, say which and why instead of
reporting the change as finished.

1. The checks of every platform the change touches pass locally: Android `./gradlew test lint
   apiCheck` (with `apiDump` committed), iOS `xcodebuild test`, Flutter `flutter analyze` and
   `flutter test`, and `python3 tools/validate-scenarios.py` when `spec/conformance/` changed.
2. Tests exist at the right tier (see Test Coverage Rules below), and the PR names the tier that
   was not run and why.
3. The spec and docs that describe the changed behaviour are updated in the same change: a
   behaviour change edits `spec/` first; a public API change updates its KDoc / DocC / dartdoc and
   the README sample if it shows it; a change to how the repo is run updates `develop.md`.
4. Nothing was reported as tested that was not run. The device and conformance tiers usually
   cannot run on the machine the change is made on; say so explicitly.

## Working Rules

- Read the code before claiming how it behaves. Never cite an RFC section, a discovery field, a
  platform API or a finding from memory: open the source, the spec under `spec/`, or the RFC.
- Ask before guessing only when the answer changes what you build and cannot be found in the
  repo. Otherwise pick the conventional option, state it, and proceed.
- Keep a change to one purpose. Do not refactor, reformat or rename unrelated code in it.
- Match the surrounding code: naming, comment density, error style. Comments explain why,
  not what. The existing files explain their reasons at length; a non-obvious decision without
  its reason is a trap for the next person.
- Fix the cause, not the symptom. Do not weaken, skip or delete a failing test to get green;
  if a test is wrong, say why.
- The platforms implement one state machine and one error taxonomy. A behaviour that one platform
  cannot express is recorded as a deviation in `spec/`, not hidden in platform code.

## Git

- Default branch is `main`. Work on a feature branch named `feat/...`, `fix/...`,
  `chore/...`; never commit to `main`.
- You may commit and push to a feature branch without asking. Ask first for anything else:
  force-push, merging or rebasing shared branches, tags, releases, deleting branches.
- Commit message: short, imperative, sentence case, says what changes and why it matters
  (`Persist the pending request before the browser opens`). A `module:` prefix is fine
  (`android core: ...`, `spec: ...`). No Conventional-Commits `feat:` prefixes.
- Stage files by explicit path, not by directory; check `git status --short` first so throwaway
  prototypes and build output never enter a commit.
- Hooks in `.claude/hooks/` (registered in `.claude/settings.json`) enforce, among other things:
  no force-push, no push to `main`, no hand edits of API dumps or generated bridge code, and no
  `android.*` import in the protocol core. A hook that blocks you is right until the operator says
  otherwise; do not work around it.
- Pull request: follow `.github/pull_request_template.md`: what changed, which tests at which
  tier (ran / not run with the reason), any public API change (dump, Swift, Dart), any spec change,
  and any gap you left.

## Ask Before

- Removing, renaming or changing the signature or default of a public symbol on any platform, or
  making a public type internal (see `.claude/rules/android-kotlin.md` on the opt-in marker).
- Raising or lowering a platform floor (`minSdk`, `compileSdk`, the `platforms:` list in
  `Package.swift`, the Flutter / Dart SDK constraint).
- Touching `.github/workflows/`, `.github/CODEOWNERS`, `SECURITY.md`, the product or platform
  lists in `Package.swift`, the plugin versions in `android/build.gradle.kts`, the Gradle wrapper.
- Adding a dependency anywhere: a module's `build.gradle.kts`, `Package.swift`, a `pubspec.yaml`,
  `tools/requirements.txt`. Check it is maintained and licence-compatible with Apache-2.0 first.
- Loosening a security check (`state`, `nonce`, PKCE, `iss`, ID-token validation, redirect URI
  verification, DPoP proof checks, Keychain / Keystore protection) for any reason, including to
  make a test or a provider work.
- Changing a normative rule in `spec/` that a merged implementation already follows.
- Tagging (a pushed `X.Y.Z` tag releases), publishing, or flipping a job in `publish-pubdev.yml` or the dormant jobs of `release.yml` from `if: false`.

## Test Coverage Rules

Three tiers, and each proves something the others cannot:

- **Unit** (`./gradlew test`, `xcodebuild test`, `flutter test`): the rule, against stubs. A
  MockWebServer or a fake store is a stub; a rule proven here has been proven against stubs.
- **Device** (`connectedDebugAndroidTest` on an emulator, XCTest on a simulator): the platform
  half that no JVM or macOS run models honestly: the Keystore and its tiers, the Keychain and its
  accessibility classes, the system browser and its cancel semantics, process death, intents.
- **Conformance** (`conformance/`, `spec/conformance/`): the wiring against a real provider: the
  exact headers, form encoding, error bodies and server-side state the scenario asserts.

Every behaviour change ships with a unit test and, when it touches a platform API or the wire, a
device or conformance test. A behaviour with no conformance scenario is proven against stubs only:
say so in the PR and open a follow-up; do not let the gap pass silently. Negative tests sit next
to every security check (wrong `state`, wrong `iss`, wrong `nonce`, bad signature, expired,
replayed, malformed). `.claude/rules/testing.md` says how.

## Agent instruction loading

`AGENTS.md` is the shared source of project instructions for Codex and Claude Code.
`CLAUDE.md` imports it. Keep project policy here rather than maintaining two copies.
Paths below are relative to the repository root, including when working in a subdirectory.

Before editing, read `.claude/rules/security.md` for every task. Also read every rule whose
`paths` frontmatter matches a file you inspect or change; multiple rules can apply. Rules without
`paths` apply everywhere. Recheck this when the scope grows. Codex must open these files explicitly:
Claude's `.claude/rules` discovery and `@` imports are not Codex instruction loaders.

| Area | Rule file under `.claude/rules/` |
|---|---|
| Everything (key material, storage, browser, validation, secrets) | `security.md` |
| `spec/`, `conformance/`, `tools/`: the normative spec and the scenarios | `spec-conformance.md` |
| `android/`: modules, API dumps, coroutines, intents, browser, toolchain | `android-kotlin.md` |
| `ios/`, `Package.swift`: Swift 6, actors, Keychain, `ASWebAuthenticationSession` | `ios-swift.md` |
| `flutter/`: the Pigeon binding | `flutter.md` |
| Tests at every tier | `testing.md` |
| `.github/`, `conformance/`, `tools/`: CI, scanners, release engineering | `ci-release.md` |

The table is an index; the frontmatter in each rule is the authoritative scope. A new rule must
be added to this index so agents that do not discover `.claude/rules/` can find it. Reviews follow
`REVIEW.md`.

## Codex permissions and guards

`.claude/settings.json` configures Claude Code only. Its permissions and hooks are not
registered with Codex. These equivalent working constraints apply to Codex too:

- Do not read `.env`, `.env.*` or `android/local.properties`, including through shell commands.
- Do not run `gh release`, `./gradlew publish`, `pod trunk push`, `flutter pub publish` or
  `npm publish`. Local build and test commands remain allowed.
- Ask before `git reset --hard`, tagging, recursive forced deletion, or erasing a simulator or
  emulator. Follow the Git and Ask Before sections above for other protected actions.
- Never hand-edit `android/*/api/*.api` (run `./gradlew apiDump`) or Pigeon-generated bridge
  files (regenerate them). Never import `android.*` or `androidx.*` in `android/core`,
  `android/okhttp` or `android/oauth-core`.

Run the existing guards from the repository root (Bash and jq required). They consume Claude's
JSON envelope, which can also be supplied by a shell; no Claude installation is needed.
Before each file edit, substitute the actual repository-relative path:

```bash
jq -n --arg path "$PWD/<file>" '{tool_input:{file_path:$path}}' | bash .claude/hooks/guard-paths.sh
```

After editing a Kotlin file under `android/core`, `android/okhttp` or `android/oauth-core`, run:

```bash
jq -n --arg path "$PWD/<file.kt>" '{tool_input:{file_path:$path}}' | bash .claude/hooks/check-core-purity.sh
```

After editing a scenario under `spec/conformance/`, run:

```bash
jq -n --arg path "$PWD/<scenario.yaml>" '{tool_input:{file_path:$path}}' | bash .claude/hooks/check-scenario-edit.sh
```

Before a push, supply the exact intended push command, for example:

```bash
jq -n --arg command 'git push -u origin chore/example' '{tool_input:{command:$command}}' | bash .claude/hooks/pre-push.sh
```

Inspect the JSON as well as the exit status: `permissionDecision: ask` requires authorization,
`deny` blocks the action even when the script exits zero, and a nonzero exit is a failed check.
Missing jq is not a passing check. Do not bypass a guard with another tool. These manual checks
are working instructions, not a Codex sandbox or an automatic hook install.
