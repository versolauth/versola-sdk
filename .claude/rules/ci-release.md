---
paths: [".github/**", "conformance/**", "tools/**"]
---

# CI and Release

## What each workflow proves

| Workflow | Runs | Proves | Does not prove |
|---|---|---|---|
| `android.yml` `build` | push to `main` and PRs touching `android/**` | `./gradlew assemble`, `test` (unit, Robolectric on API 36), `lint`, `apiCheck` on JDK 21 with `platforms;android-37.0` (compileSdk 37) | anything on a device or against a server |
| `android.yml` `instrumented` | `:storage` and `:dpop` on an emulator, API 36 (`google_apis`) | the platform half: real Keystore, GCM wrapping, key tiers | the browser leg, the server |
| `ios.yml` | push to `main` and PRs touching `ios/**`, `Package.swift` | `swift package resolve` from a clean checkout, `xcodebuild build` and `test` of scheme `Versola-Package` on a simulator | Secure Enclave, a real Keychain group, `-strict-concurrency=complete` until it is added to the step |
| `flutter.yml` `dart` | push to `main` and PRs touching `flutter/**`, the generic facades the plugin calls, `Package.swift` | `dart format`, `flutter analyze` (plugin and example), `flutter test` against a mocked channel, and that regenerating the Pigeon bridge reproduces the three generated files | the bridge on a device, the native SDKs' behaviour |
| `flutter.yml` `android` | same filter | the plugin compiles against the repository's `:oauth` through the example's composite build, the Kotlin glue's unit tests, `flutter build apk --debug` | a sign-in on a device, the bridge conformance driver (it is skipped without `OAUTH_CONFORMANCE_ISSUER`) |
| `flutter.yml` `ios` | same filter, macOS | the plugin compiles against the root package by path, `flutter build ios --no-codesign`, the Swift glue's tests on a simulator (the example app launches as the test host) | the Secure Enclave, a Universal Link delivered to a terminated app |
| `flutter.yml` `consumer` | same filter (and `tools/verify-consumer/**`), macOS | a throwaway app outside the checkout with `versola_oauth` as a git dependency on the PR's own commit (`file://` of the workspace, ref = SHA): `flutter build apk --debug` and `flutter build ios --no-codesign --debug`. This is the check that fails a pull request for a plugin manifest that only builds inside the checkout (the iOS symlink bug) | that the published release installs (`verify-release.yml`); its Android half takes `oauth-android` from Maven Central at the pinned version, not the PR's `android/` |
| `spec.yml` | every PR and push to `main` | `tools/validate-scenarios.py` (schema, `id` = file name, index rows) and markdownlint over `**/*.md` | that a scenario's states exist on every platform |
| `conformance.yml` `scenarios` | on demand (nightly once the checkout token exists) | scenarios against a staged `auth` + `central` + `edge` from `versolauth/versola`, driven from an emulator | everything the driver does not yet run (`conformance/README.md`, order of work) |
| `conformance.yml` `providers` | PRs touching the generic facade, the modules under it or the drivers, nightly, on demand | scenarios 24 to 32 of the generic facade against Keycloak and Ory Hydra in Docker (`android/conformance-oauth`), one matrix row each | the device tier, the iOS driver (local only: the macOS runners have no Docker daemon) and what `conformance/README.md` ("Providers") lists as not proven |
| `security.yml` | every PR, push to `main`, weekly and on demand | TruffleHog on PR/push, Trivy, Semgrep (gate); dependency review on PRs and CodeQL while public | Gradle transitive coverage from Trivy; a skipped scanner |
| `release.yml` | push of an `X.Y.Z` tag (no `v`) | the tagged commit is on `main`; tag/pubspec/plugin-pin/changelog agree; `test lint apiCheck`; the signed Central bundle uploaded as `USER_MANAGED`; a clean-checkout build of the tag; then the GitHub release and the dispatch of `verify-release.yml`. The CocoaPods and npm jobs are `if: false` | that the Portal accepts the bundle: it has never run (`docs/releasing.md`); that a consumer can install the result (that is `verify-release.yml`) |
| `verify-release.yml` | a published GitHub release (a person's), `release.yml`'s dispatch after its release job, and on demand with `version` | after the Central deployment is published (polls `repo1.maven.org` for the `oauth-android` POM, every 60 s up to 3 h): `android.sh` (an app with `mavenCentral()` and `google()` only resolves `io.versola:oauth-android:X.Y.Z` and its five modules and builds), `ios.sh` (a SwiftPM package resolves the tag by URL and builds `VersolaOAuth` for the simulator), `flutter.sh` (an app with the plugin as a git dependency at the tag builds for Android and iOS); a final job lists which passed | that the Portal accepted the bundle (`release.yml`); that a sign-in works (no device, no server); pub.dev (dormant) |
| `prepare-release.yml` | on demand, branch `main` | `tools/prepare-release.sh`: the version in pubspec, the plugin's Android pin and `version`, the changelog entry and `VERSION_NAME`, checked by `check-release-version.sh`, on a `release/X.Y.Z` branch | that the changelog is prose: a person edits it |
| `publish-pubdev.yml` | push of an `X.Y.Z` tag, `if: false` | nothing today: dormant. The `flutter pub publish` job pub.dev's tag-based OIDC login needs; the first publish is by hand | whether pub.dev's OIDC login works for a Flutter package (unverified) |

- A green check is exactly what is in its row. "CI is green" does not mean the scenario catalogue
  passed; say which workflow ran.
- Scope of `paths:` filters matters: a change to `spec/**` alone does not run `android.yml`. When a
  change spans areas, make sure each affected workflow runs, or run its commands locally.

## Changing a workflow

- You cannot run GitHub Actions locally. Say so, and say what proves the change: a PR run, or a
  `workflow_dispatch` run (the conformance workflow takes a `versola_ref` input). Do not report a
  workflow change as verified from reading it. Validate YAML syntax locally, and run the commands
  it contains (`./gradlew ...`, `swift package resolve`, `python3 tools/validate-scenarios.py`)
  where you can.
- Ask before editing `.github/workflows/*`, `CODEOWNERS`, `dependabot.yml` or `SECURITY.md`; the
  guard hook asks too.
- Least privilege: top-level `permissions: contents: read` (as `conformance.yml` has), widened per
  job only where a job needs it (`attestations`, `id-token` for provenance, `packages`). A new
  workflow without a `permissions:` block gets the repository default, which is wider than needed.
- Pin every new action to a full commit SHA with the version in a comment
  (`uses: owner/repo@<sha> # v4.2.1`). The existing workflows still use tags (`actions/checkout@v4`,
  `gradle/actions/setup-gradle@v4`, `reactivecircus/android-emulator-runner@v2`) because they
  predate this rule; pin the ones you touch, and do not replace a pin with a floating tag.
  Third-party actions that receive secrets or a write token get the most scrutiny.
- Never interpolate untrusted `${{ ... }}` (PR titles and bodies, branch names, issue text,
  `inputs.*` from `workflow_dispatch`) straight into a `run:` body. Pass it through `env:` and
  validate it, as the server repository does for `test_tag`. `inputs.versola_ref` is checked out
  through `with: ref:`, not through a shell; keep it that way.
- Secrets are named by reference (`secrets.VERSOLA_CHECKOUT_TOKEN`, `MAVEN_SIGNING_KEY`) and never
  echoed. A step that checks out another repository with a token does not persist it
  (`persist-credentials: false` unless a later step needs to push).
- Comments explain why, at length, in the existing style: the simulator-name drift in `ios.yml`,
  why `android.builtInKotlin=false` in `gradle.properties`, why `conformance.yml` is on demand.
  A non-obvious step without its reason is a trap for the next person.
- Keep path filters in step with what the workflow needs: `android.yml` filters on `android/**` and
  on itself, `ios.yml` on `ios/**`, `Package.swift` and itself.

## Emulator and conformance jobs

- Emulator jobs run on `ubuntu-latest` with KVM enabled (the udev rule step) and
  `reactivecircus/android-emulator-runner`, `arch: x86_64`, `google_apis` (Auth Tab needs
  Chrome). The API matrix is the latest release, 36; the pre-R
  `setUserAuthenticationValidityDurationSeconds` branch is proven at the unit tier (API 29
  under Robolectric), and a 28 row can return if a device below 30 disagrees. A job added to the
  matrix says in a comment what each level covers.
- `conformance.yml` stages the server exactly as `versolauth/versola`'s own `ci-cd.yml` does (JDK 25
  for the server, JDK 21 for the SDK, `gen-env.scala`, forms build, `sbt stage`, central, auth, the
  internal TLS terminator and edge). Keep the stack half a copy so the two cannot drift; when the
  server's CI changes how it stages, change this one in the same sweep.
- The checkout of the private server repository needs the `VERSOLA_CHECKOUT_TOKEN` secret. Until it
  exists the `scenarios` job is gated to `workflow_dispatch`; the nightly trigger takes over by
  dropping that `if:` line, which is the maintainer's decision, not a side effect of another change.
- Upload transcripts and the server logs as artifacts with `if: always()`: a failing scenario is
  diagnosed from them.
- The Docker compose files in `conformance/` are for local runs and the provider containers of
  issue #46; they use throwaway credentials only. A provider container is pinned to a release
  (`keycloak:26.4`, `hydra:v26.2.0`) so the matrix row in `spec/providers.md` names what was tested.

## Scanners and the private repository

- CodeQL and dependency review need GitHub Advanced Security on a
  private repository, so those jobs are wired but conditional on the repository being public
  (`if: github.event.repository.private == false` or equivalent), each commented with whether it
  gates or reports. Do not delete a conditional scanner because it is skipped, and do not make it
  gate without being asked. A skipped scanner is not a clean scan; say so in a security-relevant PR.
- Findings are fixed or accepted with a reason, an owner and a re-evaluation date
  (`security.md`); never suppress silently.

## Dependabot

`.github/dependabot.yml` covers `gradle` (`/android`, and the Flutter example's own build at
`/flutter/versola_oauth/example/android`, which ignores the two plugins that must equal
`android/build.gradle.kts`), `swift` (`/`), `pub` (`/flutter/versola_oauth`, with `pigeon` ignored:
its bump comes with the regeneration), `github-actions` and `pip` (`/tools`). Minor and patch updates are grouped into one PR per ecosystem
per week; majors are separate so a breaking major blocks only itself. A Dependabot PR is reviewed
like any other dependency change: licence, maintenance, what the release notes say. Known holds are
documented where they live (OkHttp 5.4.0 pinned below 5.5.0, `android/okhttp/build.gradle.kts`).

## Release engineering

- Versioning is `0.MINOR.PATCH` until 1.0: a breaking change to the public API bumps MINOR,
  compatible additions and fixes bump PATCH. `./gradlew apiCheck` runs on every PR, and the
  committed `android/*/api/*.api` dumps are the record of what changed (`android-kotlin.md`). A PR
  that changes a dump says so and says why it is acceptable at this version.
- Releases, tags and publishing are the maintainer's act, and pushing an `X.Y.Z` tag is what
  releases (`release.yml`). Never create or push a tag or a GitHub release, run `./gradlew publish`,
  `pod trunk push`, `flutter pub publish` or `npm publish`, push to Maven Central, or flip the
  `if: false` of the pub.dev, CocoaPods or npm jobs, even if asked to "prepare" a release; prepare
  the change and stop. The guard hook asks on `git tag` and denies `gh release`.
- `release.yml` fails on a tag until the matching credentials exist as repository secrets, and
  `publish-pubdev.yml` stays dormant until the first publish is done by hand. The secrets are (`MAVEN_SIGNING_KEY`, `MAVEN_SIGNING_PASSWORD`, `SONATYPE_USERNAME`,
  `SONATYPE_PASSWORD`, `COCOAPODS_TRUNK_TOKEN`, `NPM_TOKEN`; pub.dev authenticates by OIDC). The
  build side exists: every published Android module applies `android/gradle/publishing.gradle.kts`,
  and `./gradlew centralBundle` writes a signed or (with `-PallowUnsignedBundle`) unsigned zip to
  `android/build/central-bundle/` without contacting any server. Running it is allowed; running
  `./gradlew publish`, uploading the zip, or any `flutter pub publish`, including `--dry-run`, is
  the maintainer's. Credentials, the tag, the namespace verification and flipping a job from
  `if: false` are theirs too: `docs/releasing.md` is the runbook (B7 in issue #46).
- After the tag, `verify-release.yml` is the acceptance test of the release: its green is the proof
  that Maven Central, SwiftPM and the git-dependency Flutter install all work for a consumer, and
  it is the only check that builds from what is published rather than from the checkout. It
  waits for the maintainer's click in the Portal (up to three hours), so a run that timed out is
  started again with `workflow_dispatch` and the version, not by re-tagging. `release.yml`
  dispatches it because a release created with `GITHUB_TOKEN` does not fire `release: published`.
  A red run means that version cannot be installed by some consumer; Central releases are
  immutable, so the repair is the next version. Its scripts are `tools/verify-consumer/`
  (`develop.md` lists the commands); change a script and its workflow in the same pull request,
  and run the scripts locally against a published version (0.1.0 exists), since a workflow
  cannot be run locally.
- Every workflow that builds Android installs `platforms;android-37.0` and `build-tools;36.0.0`
  (`compileSdk` is 37; AGP 9.5.0 defaults to build-tools 36.0.0). When `compileSdk` or AGP moves,
  `grep -rn 'platforms;android-' .github develop.md` and change every hit together. API 36 elsewhere
  in the workflows is the emulator image and Robolectric, and stays.
- Maven coordinates keep the reverse-DNS groupId `io.versola` (Central verifies namespaces by DNS
  ownership) while code packages are `versola.*`; do not change either without a decision.
