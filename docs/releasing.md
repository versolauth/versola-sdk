# Releasing

How a release of the Versola SDKs is built, checked and published, and which parts are the
maintainer's. 0.1.0 is published: `release.yml` ran once, for that tag, and its Android artefacts are
on Maven Central under a GitHub release of the same name. The Flutter package `versola_oauth` 0.3.0 was published manually to pub.dev under the verified
publisher `versola.io`; later versions use `publish-pubdev.yml` after the pub.dev trust settings
below are configured. Release 0.3.0 passed `release.yml` and `verify-release.yml`.
The publishing side was written from the vendors' documentation (the sources are named where they
matter), and the steps below are ordered so that each can be looked at, and undone, before the next.

Releases, tags and publishing are the maintainer's act (`AGENTS.md`, `.claude/rules/ci-release.md`).
**A release is a tag**: pushing `X.Y.Z` (for example `0.1.0`, no leading `v`) runs `release.yml`,
which checks the version, builds, signs and uploads the Android artefacts, builds the Swift package at
the tag and creates the GitHub release. The separate pub.dev job (`publish-pubdev.yml`) runs on the same tag, checks that the commit is
on `main`, analyzes and tests Flutter, and waits for the matching Android POM on Maven Central
before publishing. CocoaPods and npm remain gated off with `if: false`.

## What is published

One version for every platform while the project is 0.x, written `X.Y.Z` and tagged `X.Y.Z`: the tag is the version.

| Platform | Published as | How | Workflow |
|---|---|---|---|
| Android | `io.versola:oauth-android`, one artefact (below) | Maven Central, through the Central Portal | `release.yml` `maven-central` |
| iOS | the repository itself: product `VersolaOAuth` | Swift Package Manager resolves the tag; nothing is uploaded | `release.yml` `swiftpm` verifies the tag builds |
| Flutter | `versola_oauth` on pub.dev | `flutter pub publish`, by hand for 0.3.0 and by workflow after | `publish-pubdev.yml` |

## One artefact

The Android SDK is published as **one** artefact, `io.versola:oauth-android` (an AAR). The build keeps
its modules (`:oauth`, `:oauth-core`, `:dpop`, `:storage`, `:browser`, `:okhttp`) because they enforce
the layering (the core has no `android.*` import, ADR 0001), keep the protocol tests plain JVM and
give `apiCheck` a dump per module. A Gradle project dependency would become a Maven dependency in the
published POM, so `android/gradle/publishing.gradle.kts` does not publish the modules: it builds
the one AAR (`:oauth:mergedReleaseAar`) from them.

- **`classes.jar`** is the classes of every module in `extra["publishing.mergeModules"]` in `:oauth`'s
  build file plus `:oauth`'s own. A file present in two modules fails the build; each module's
  `META-INF/*.kotlin_module` is kept.
- **The manifest** is `:browser`'s (the redirect activity, the Auth Tab trampoline and the package
  visibility query), under `:oauth`'s package.
- **What the merge does not carry** (resources, assets, native libraries, a ProGuard file in a merged
  module) fails the build instead of being dropped: no module has any today, and the day one does the
  merge has to learn it.
- **The POM** is generated from the third-party libraries the modules declare (`api` becomes compile
  scope, `implementation` runtime scope), so it names no `io.versola:*` and cannot drift from the build
  files. It has `packaging` `aar` and there is **no Gradle metadata file**: that describes a component,
  and this AAR is assembled from several. A Gradle or Maven consumer reads the POM.
- **Sources and javadoc:** the sources jar holds the sources of every merged module; the javadoc jar is
  the placeholder Central allows.

Anything an app can call is public API of this artefact, whichever module it is declared in; the
per-module `apiCheck` dumps are its record. The Versola facade (`:sdk`, `:core`) is not published; if it
ever is, it is a second artefact (for instance `versola-android`) that depends on `oauth-android`,
because generic code never depends on Versola code (ADR 0001).

0.1.0 and 0.2.0 published six artefacts (`oauth-android`, `oauth-core`, `dpop-android`,
`storage-android`, `browser-android`, `okhttp-android`). They stay on Central, where releases are
immutable, and are **no longer published from 0.3.0**.

The group `io.versola` is the one place reverse-DNS survives (`docs/adr/0001-generic-sdk-naming-and-layering.md`):
Central verifies a group by DNS ownership of `versola.io`. The samples and the conformance drivers
publish nothing.

## For the next release's notes

**The release that first publishes one artefact (0.3.0).** Say: "`io.versola:oauth-android` is now the
only Android artefact and contains what `oauth-core`, `dpop-android`, `storage-android`,
`browser-android` and `okhttp-android` contained. Those five are not published from this release. An app
that depends on `oauth-android` alone needs no change. An app that also declares one of the five
at 0.2.0 or earlier must remove that line: it would bring a second copy of the classes and fail with
a duplicate-class error."

0.1.0 shipped five SwiftPM library products that were empty placeholders (`VersolaCore`,
`VersolaDPoP`, `VersolaStorage`, `VersolaBrowser`, `VersolaURLSession`). They are removed from
`Package.swift`; nothing could import anything from them, but a dependency naming one of those
products fails to resolve. Say so in the notes of the release that first omits them (0.1.1 or 0.2.0):
the products are gone, `VersolaOAuth` is the only one.

## What the repository does for you

- `android/gradle/publishing.gradle.kts`, applied by each published module: a `release`
  publication with the POM Central requires (name, description, URL, Apache-2.0, developers, SCM), a
  sources jar, a javadoc jar, and PGP signatures when a key is given.
- `./gradlew centralBundle` in `android/`: publishes every module into one local repository and zips
  it as `android/build/central-bundle/versola-<version>.zip`. It never talks to a server. It refuses a
  `-SNAPSHOT` version and refuses to build an unsigned bundle unless `-PallowUnsignedBundle` is passed
  (Central rejects an unsigned deployment, so an unsigned zip is only for looking at).
- `tools/check-release-version.sh X.Y.Z`: fails unless the tag, the Flutter plugin's `pubspec.yaml`
  version, the `oauth-android` version the plugin pins, its `CHANGELOG.md` and the development version
  agree.
- `tools/flutter-prepare-publish.sh X.Y.Z`: rewrites the plugin's iOS `Package.swift` from the path
  dependency on the repository root (computed from the manifest's own location) to the tag by URL,
  which is what a published plugin needs; it also removes that computation.
- `tools/verify-consumer/` and `verify-release.yml`: before the upload, `release.yml` checks the signed
  bundle (`check-bundle.sh`: oauth-android present and alone under `io/versola`, with sources and javadoc,
  checksums and a signature beside every file, its POM naming the tag and no io.versola module) and builds a
  throwaway Android app against it (`android-bundle.sh`, below, step 5); after the tag, throwaway apps
  outside the repository install what was published (below, step 6). `android.sh X.Y.Z` builds an app with
  `mavenCentral()` and `google()` only against `io.versola:oauth-android:X.Y.Z`; `ios.sh X.Y.Z` builds a
  SwiftPM package that depends on the public repository at exactly that tag, for the simulator;
  `flutter.sh X.Y.Z` builds an app that takes `versola_oauth` as a git dependency at the tag, for Android
  and iOS. They run locally too (`develop.md`).
- `release.yml`, on a pushed `X.Y.Z` tag: the tagged commit must be on `main`, then the version check
  above, then (iOS) a clean-checkout build of the tag, which has to pass before the upload starts,
  (Android) `test lint apiCheck`, the signed bundle and the upload to the Central Portal, and last the
  GitHub release with generated notes and the dispatch of `verify-release.yml`. The
  Central job runs in the GitHub environment `maven-central`. `publish-pubdev.yml` is the pub.dev counterpart. It uses the repository
  checksum-verified Flutter setup action and the official, SHA-pinned `dart-lang/setup-dart` action
  for OIDC authentication. No permanent publishing token is stored in GitHub. The pub.dev admin
  settings must allow repository `versolauth/versola-sdk`, tag pattern `{{version}}` and required
  environment `pub.dev`. The first tag-triggered upload is the end-to-end verification of OIDC.
- **Release notes** are written by hand and kept in `docs/release-notes/X.Y.Z.md` (what is new, fixes,
  upgrading, requirements), because the generated notes are only a list of pull requests. The workflow
  creates the release with the generated ones; the maintainer replaces them after it:
  `gh release edit X.Y.Z --notes-file docs/release-notes/X.Y.Z.md`. Write the file in the pull request
  that prepares the release, from the merged pull requests since the previous tag.

- Provenance and the dependency graph. After the upload a separate `provenance` job of `release.yml` attests the build provenance
  of every AAR and JAR in the bundle (`actions/attest-build-provenance`, signed through GitHub's
  Sigstore, no secret involved, and not a gate of the GitHub release): they are the files Central serves, so
  `gh attestation verify oauth-android-X.Y.Z.aar --repo versolauth/versola-sdk` ties a downloaded
  artefact to the workflow run, tag and commit that built it (the first release that carries this is
  the one after 0.1.0). `security.yml` submits the Gradle dependency graph on `main`, weekly and on
  demand, which feeds Dependabot alerts and dependency review. An SBOM attached to the release is
  deferred: the dependency graph above can be exported as SPDX
  (`gh api repos/versolauth/versola-sdk/dependency-graph/sbom`), but a CycloneDX file per release
  needs a Gradle plugin, which is a new dependency to approve (`AGENTS.md`, "Ask Before"), and
  scanning the checkout with a generic tool misses the Gradle graph for the same reason Trivy does.
  `android/gradle/verification-metadata.xml` checks every artefact the build resolves against a
  recorded checksum (`develop.md`).

What was verified locally, before 0.1.0 was tagged, on `-PreleaseVersion=0.1.0`: all six modules publish (the layout before one artefact, see above); every POM names
only coordinates that are in the bundle; each artefact has sources, javadoc, POM and Gradle module
metadata with MD5 and SHA-1 checksums; a bundle signed with a throwaway key has a signature for every
file (40 of them) and one of them verifies with the matching public key. What was not verified
then (the Portal accepted 0.1.0's bundle):
that the Portal accepts the bundle (the Android javadoc jars are what AGP generates from Kotlin
sources, and `oauth-core`'s is empty, a placeholder Central's requirements allow), that it tolerates
the checksum files Gradle also writes next to the signatures, and the upload and status calls.
Use a `USER_MANAGED` deployment for the first upload so any of that fails in the Portal, where the
deployment can be dropped, rather than on Central.

## One-time setup (the maintainer)

1. **Central Portal account and namespace.** Sign in at `https://central.sonatype.com`, add the
   namespace `io.versola` ("View Namespaces", "Add Namespace"), copy its verification key, add it as a
   DNS TXT record on `versola.io`, and only then click "Confirm" (an early confirmation caches the
   missing record). Source: Central's namespace registration page, read 2026-10-30; it does not give
   the TXT host field, so expect to ask Central support if the automatic check fails. (Done for
   `io.versola` on 2026-10-30.)
2. **A Portal user token** (the account page), not the login. Its two halves are the two secrets below.
3. **A signing key.** Central requires PGP signatures from the *primary* key and says to delete any
   signing subkey, and the public key on a keyserver Central supports (`keyserver.ubuntu.com`,
   `keys.openpgp.org`, `pgp.mit.edu`). Create a key with a passphrase, publish the public half,
   export the private half armoured (`gpg --armor --export-secret-keys <KEYID>`), and note the expiry
   (the default is two years): an expired key means a new key and a new secret.
4. **Repository secrets** (names are what the workflow reads; values are never in the repository):
   `MAVEN_SIGNING_KEY` (the armoured private key), `MAVEN_SIGNING_PASSWORD`, `SONATYPE_USERNAME` and
   `SONATYPE_PASSWORD` (the Portal token's two halves).
5. **pub.dev.** The first manual upload, `versola_oauth` 0.3.0, is complete. In the package's
   Admin tab enable publishing from GitHub Actions for `versolauth/versola-sdk`, tag pattern
   `{{version}}`, and require the GitHub Actions environment `pub.dev`. Create that environment
   in GitHub before the tag. Required reviewers can be added if a release should wait for approval.
   Keep the repository and environment names exact: they are checked against the OIDC identity.
6. **A public repository.** The published Flutter plugin resolves the Swift package by URL, and a
   Swift Package Manager consumer resolves the tag by URL; neither works against a private repository.
   Making it public is a decision with its own checklist (scanners, history), not part of this one.

## A release, in order

1. **Main is green** for `android.yml`, `ios.yml`, `flutter.yml`, `spec.yml` and `security.yml`, and the
   conformance runs named in `conformance/README.md` have been run for the release candidate (the iOS
   and bridge drivers are local only).
2. **Set the version.** Run the `prepare-release` workflow from the Actions tab (branch `main`, input
   `X.Y.Z`), or `tools/prepare-release.sh X.Y.Z` locally. It edits the files below, runs the check and
   pushes `release/X.Y.Z` with a pull request (or a link to open one, when the repository does not let
   Actions create pull requests). Edit the changelog entry, which starts as the list of commit subjects
   since the last tag, and merge. By hand, it is one pull request: `flutter/versola_oauth/pubspec.yaml`, the
   `version` and the `io.versola:oauth-android:X.Y.Z` pin in `flutter/versola_oauth/android/build.gradle.kts`, a
   `## X.Y.Z` entry in `flutter/versola_oauth/CHANGELOG.md`, and `VERSION_NAME` in
   `android/gradle.properties` (still `-SNAPSHOT`, at or above the release). Run
   `tools/check-release-version.sh X.Y.Z`.
3. **Look at the bundle locally** before anything is uploaded:

   ```bash
   cd android
   ./gradlew centralBundle -PreleaseVersion=X.Y.Z -PallowUnsignedBundle
   unzip -l build/central-bundle/versola-X.Y.Z.zip | less
   ```

   The Gradle task is the only thing between the sources and what is signed: check the list of
   artefacts against the table above. To see what step 5 will see, unzip it and run the checks on
   the directory (`develop.md`, "What a consumer installs"):

   ```bash
   bundle="$(mktemp -d)" && unzip -q build/central-bundle/versola-X.Y.Z.zip -d "$bundle"
   cd .. && tools/verify-consumer/android-bundle.sh "$bundle" X.Y.Z
   ```

   (`check-bundle.sh` also reports the missing signatures of an unsigned bundle, as it should.)
4. **Tag**, from the merged commit on `main`: `git tag X.Y.Z && git push origin X.Y.Z`. This is the
   maintainer's act and starts `release.yml`, which creates the GitHub release when the Android bundle
   has validated and the Swift package has built. A run that fails leaves the tag and no release: fix
   the cause on `main`, delete the tag (`git push --delete origin X.Y.Z`; nothing reached Central
   unless the upload step passed, and a validated deployment can be dropped in the Portal) and tag
   again. For the first release, consider requiring reviewers on the `maven-central` environment
   (Settings, Environments) so that the upload waits for a click.
5. **Central.** `maven-central` runs the tests, builds the signed bundle, **checks it**
   (the zip is unzipped and `check-bundle.sh` wants oauth-android alone under `io/versola`, with sources and
   javadoc, checksums and a `.asc` beside every artefact file, its POM naming the tag and no io.versola
   module, and its AAR declaring the redirect activity), then **builds a consumer from it**: `android-bundle.sh` generates the same throwaway Android
   app as `android.sh` (outside the repository, `compileSdk` 37, one dependency,
   `io.versola:oauth-android:X.Y.Z`) with the unzipped bundle as a local Maven repository for
   `io.versola` and as the only place that group can come from, and Google and Maven Central for the
   third-party dependencies and the plugins. It resolves `oauth-android` at the tag
   by its POM, fails if anything else under `io.versola` is on the classpath, and runs `assembleDebug`
   (its Kotlin file names a type from each merged module, so the compiler has to find them all in the one AAR). A
   failure of either step stops the job before anything is uploaded, so the Publish click below is on a
   checked artefact. What this proves is that a consumer resolves and compiles the SDK from these files
   exactly as it will from Central. It does not prove that the signatures verify (the check above looks
   for their presence; Central verifies them), nor that Central accepts the bundle and serves it: only
   `verify-release.yml` after the publication shows that (step 6). The iOS and Flutter packages have no
   such step: the `swiftpm` job, which `maven-central` waits for, already builds the tag from a clean
   checkout before the upload, and the Flutter plugin resolves the tag by git, which does not exist
   before the tag is pushed. The job then uploads it as
   `USER_MANAGED` (or `AUTOMATIC`, below) and waits for validation. A rejected bundle fails the job. A validated one waits in
   the Portal: look at it, then publish it there (or drop it). Central releases are immutable: a
   published version is never replaced, only superseded. Once a `USER_MANAGED` release has gone
   through, set the repository variable `MAVEN_CENTRAL_PUBLISHING_TYPE` to `AUTOMATIC` (Settings,
   Secrets and variables, Actions, Variables) and later tags are published on validation, with no
   click; removing the variable returns to `USER_MANAGED`. Keep reviewers on the `maven-central`
   environment if a human should still stand between the tag and Central.
6. **Check what a consumer sees.** `release.yml` starts `verify-release.yml` when it has created the GitHub
   release (a dispatch, because a release made with the workflow's own token does not fire
   `release: published`). The run waits for you to publish the deployment in the Portal (step 5),
   polling `repo1.maven.org` for the `oauth-android` POM every minute for up to three hours, and then
   builds three throwaway apps outside the repository: `io.versola:oauth-android:X.Y.Z` from
   `mavenCentral()` and `google()`; a SwiftPM package at exactly the tag, product `VersolaOAuth`; and a
   Flutter app with the plugin as a git dependency at the tag, for Android and iOS. **Its green is
   the proof that Maven Central, SwiftPM and the Flutter git install all work.** If it timed out
   before you clicked, or you want to repeat it, run `verify-release` from the Actions tab with the
   version. If it is red, that version cannot be installed by some consumer; the version is
   immutable on Central, so the fix is the next one.
   Also read each AAR's `META-INF/com/android/build/gradle/aar-metadata.properties` (`unzip -p`): its
   `minCompileSdk` must be the module's own `aarMetadata` value (`develop.md`), not 37, which is what AGP
   writes when a module sets none and what it would then demand of every app.
7. **pub.dev.** For 0.3.1 onward `publish-pubdev.yml` runs automatically on the tag.
   It waits up to three hours for the Android dependency on Maven Central (including any Portal
   approval), then obtains a fresh OIDC token and publishes. If that wait expires, publish the
   Central deployment and rerun the failed job; do not retag.

   The first upload, 0.3.0, was done manually from a checkout of the tag:

   ```bash
   tools/flutter-prepare-publish.sh X.Y.Z
   cd flutter/versola_oauth
   flutter pub publish --dry-run   # read what it says about size, files and the pubspec
   flutter pub publish
   ```

   Do not commit the `Package.swift` change; `git checkout flutter/versola_oauth/ios` undoes it. Then
   configure automated publishing as described in setup step 5. The workflow uses the official
   Dart setup action to configure the pub token shared by Dart and Flutter. Check the first
   tag-triggered run and the package Activity log to verify the OIDC upload end to end.
8. **After:** raise `VERSION_NAME` to the next `-SNAPSHOT`, and add the next changelog heading to the
   plugin's changelog when its first change lands.

## Things that are not settled

- **Whether the Portal accepts the bundle exactly as Gradle writes it.** The first `USER_MANAGED`
  upload answers it. If the extra checksum files next to the signatures are refused, the fix is in
  `centralBundle` (drop them from the zip), not in the workflow.
- **The first OIDC upload.** Local analysis, tests and actionlint do not prove pub.dev accepts
  the GitHub identity. Verify the first tag-triggered upload and its Activity log entry.
- **A real javadoc.** The Android javadoc jars are what AGP produces for Kotlin sources and are not
  an API reference; the reference is the KDoc in the sources jar, `spec/oauth-sdk-api.md` and the
  platform READMEs. A Dokka build would be a new dependency and is a decision of its own.
- **CocoaPods** stays dormant: there is no podspec, and the Flutter plugin's iOS half is Swift Package
  Manager only.
- **`SECURITY.md`** names the supported Android coordinates; with one artefact it should name only
  `io.versola:oauth-android` (the file is edited in this change; the maintainer reviews it).
