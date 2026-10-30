# Releasing

How a release of the Versola SDKs is built, checked and published, and which parts are the
maintainer's. Nothing has been published yet, and nothing in this document has run against a real
Maven Central, pub.dev or GitHub release: the build side was exercised locally, the publishing side
only by reading the vendors' documentation (the sources are named where they matter). The first
release is therefore also the first test of every workflow, and the steps below are ordered so that
each can be looked at, and undone, before the next.

Releases, tags and publishing are the maintainer's act (`AGENTS.md`, `.claude/rules/ci-release.md`).
**A release is a tag**: pushing `X.Y.Z` (for example `0.1.0`, no leading `v`) runs `release.yml`,
which checks the version, builds, signs and uploads the Android artefacts, builds the Swift package at
the tag and creates the GitHub release. Only the pub.dev job (`publish-pubdev.yml`) is still gated off
with `if: false`, and the CocoaPods and npm jobs, which have nothing to publish.

## What is published

One version for every platform while the project is 0.x, written `X.Y.Z` and tagged `X.Y.Z`: the tag is the version.

| Platform | Published as | How | Workflow |
|---|---|---|---|
| Android | `io.versola:oauth-android` and the five modules it depends on (below) | Maven Central, through the Central Portal | `release.yml` `maven-central` |
| iOS | the repository itself: product `VersolaOAuth` (and the `Versola*` placeholders) | Swift Package Manager resolves the tag; nothing is uploaded | `release.yml` `swiftpm` verifies the tag builds |
| Flutter | `versola_oauth` on pub.dev | `flutter pub publish`, by hand for 0.1.0 and by workflow after | `publish-pubdev.yml` |

The Android SDK is not a single artefact: a Gradle project dependency becomes a Maven dependency
in the published POM, so every module `OAuthClient` needs is published too, under the same group and
version. The coordinates are chosen in each module's `build.gradle.kts` and are the contract once
released.

| Module | Coordinates | Kind |
|---|---|---|
| `:oauth` | `io.versola:oauth-android` | AAR, `OAuthClient` |
| `:oauth-core` | `io.versola:oauth-core` | JAR, plain JVM protocol engine |
| `:dpop` | `io.versola:dpop-android` | AAR |
| `:storage` | `io.versola:storage-android` | AAR |
| `:browser` | `io.versola:browser-android` | AAR |
| `:okhttp` | `io.versola:okhttp-android` | AAR |

The group `io.versola` is the one place reverse-DNS survives (`docs/adr/0001-generic-sdk-naming-and-layering.md`):
Central verifies a group by DNS ownership of `versola.io`. The samples and the conformance drivers
publish nothing.

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
  dependency on this checkout to the tag by URL, which is what a published plugin needs.
- `release.yml`, on a pushed `X.Y.Z` tag: the tagged commit must be on `main`, then the version check
  above, then (Android) `test lint apiCheck`, the signed bundle and the upload to the Central Portal,
  (iOS) a clean-checkout build of the tag, and last the GitHub release with generated notes. The
  Central job runs in the GitHub environment `maven-central`. `publish-pubdev.yml` is the dormant
  pub.dev counterpart.

What was verified locally, on `-PreleaseVersion=0.1.0`: all six modules publish; every POM names
only coordinates that are in the bundle; each artefact has sources, javadoc, POM and Gradle module
metadata with MD5 and SHA-1 checksums; a bundle signed with a throwaway key has a signature for every
file (40 of them) and one of them verifies with the matching public key. What was not verified:
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
5. **pub.dev.** Publish `versola_oauth` once by hand (below). Only then does the package's admin page
   offer "Automated publishing": enable it for `versolauth/versola-sdk` with the tag pattern
   `{{version}}`, and consider requiring the GitHub environment `pub.dev` with required reviewers
   (pub.dev's documentation warns that anyone who can push a tag can publish otherwise).
6. **A public repository.** The published Flutter plugin resolves the Swift package by URL, and a
   Swift Package Manager consumer resolves the tag by URL; neither works against a private repository.
   Making it public is a decision with its own checklist (scanners, history), not part of this one.

## A release, in order

1. **Main is green** for `android.yml`, `ios.yml`, `flutter.yml`, `spec.yml` and `security.yml`, and the
   conformance runs named in `conformance/README.md` have been run for the release candidate (the iOS
   and bridge drivers are local only).
2. **Set the version** in one pull request: `flutter/versola_oauth/pubspec.yaml`, the
   `io.versola:oauth-android:X.Y.Z` pin in `flutter/versola_oauth/android/build.gradle.kts`, a
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
   artefacts against the table above.
4. **Tag**, from the merged commit on `main`: `git tag X.Y.Z && git push origin X.Y.Z`. This is the
   maintainer's act and starts `release.yml`, which creates the GitHub release when the Android bundle
   has validated and the Swift package has built. A run that fails leaves the tag and no release: fix
   the cause on `main`, delete the tag (`git push --delete origin X.Y.Z`; nothing reached Central
   unless the upload step passed, and a validated deployment can be dropped in the Portal) and tag
   again. For the first release, consider requiring reviewers on the `maven-central` environment
   (Settings, Environments) so that the upload waits for a click.
5. **Central.** `maven-central` runs the tests, builds the signed bundle, uploads it as
   `USER_MANAGED` and waits for validation. A rejected bundle fails the job. A validated one waits in
   the Portal: look at it, then publish it there (or drop it). Central releases are immutable: a
   published version is never replaced, only superseded.
6. **Check what a consumer sees**, from a project outside this repository, once Central has it:
   `implementation("io.versola:oauth-android:X.Y.Z")` with `mavenCentral()` and `google()` resolves, and
   a Swift package depending on `.package(url: "https://github.com/versolauth/versola-sdk", from: "X.Y.Z")`
   resolves and builds the `VersolaOAuth` product.
7. **pub.dev, first release by hand.** From a clean checkout of the tag:

   ```bash
   tools/flutter-prepare-publish.sh X.Y.Z
   cd flutter/versola_oauth
   flutter pub publish --dry-run   # read what it says about size, files and the pubspec
   flutter pub publish
   ```

   Do not commit the `Package.swift` change; `git checkout flutter/versola_oauth/ios` undoes it. Then
   enable automated publishing (setup step 5). The `publish-pubdev.yml` job takes over for later
   tags; whether `flutter pub publish` authenticates through pub.dev's OIDC without the Dart setup
   action is unverified (the documentation covers `dart pub` only), so try it on a tag in a fork first.
8. **After:** raise `VERSION_NAME` to the next `-SNAPSHOT`, and add the next changelog heading to the
   plugin's changelog when its first change lands.

## Things that are not settled

- **Whether the Portal accepts the bundle exactly as Gradle writes it.** The first `USER_MANAGED`
  upload answers it. If the extra checksum files next to the signatures are refused, the fix is in
  `centralBundle` (drop them from the zip), not in the workflow.
- **The pub.dev workflow's authentication** for a Flutter package (above).
- **A real javadoc.** The Android javadoc jars are what AGP produces for Kotlin sources and are not
  an API reference; the reference is the KDoc in the sources jar, `spec/oauth-sdk-api.md` and the
  platform READMEs. A Dokka build would be a new dependency and is a decision of its own.
- **CocoaPods** stays dormant: there is no podspec, and the Flutter plugin's iOS half is Swift Package
  Manager only.
- **`SECURITY.md`** names two Android coordinates as the supported packages; with the building-block
  modules published it should say that every artefact in the table is in scope. That file is the
  maintainer's to edit.
