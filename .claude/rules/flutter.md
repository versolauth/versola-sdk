---
paths: ["flutter/**"]
---

# Flutter

`flutter/versola_oauth` is the generic SDK's binding (issue #46, B6); the Versola plugin comes
later. Flutter is pinned in `flutter/.fvmrc` and run through fvm (`develop.md`). Security rules are
in `security.md`; what the platform SDKs do is in `android-kotlin.md` and `ios-swift.md`.

## A binding, not a third implementation

- The plugin forwards to the native SDKs. No PKCE, `state` or `nonce` generation, DPoP proof,
  token request, refresh, retry, ID-token validation, discovery, storage or key logic in Dart. If
  Dart needs a behaviour, it is added to the native SDKs and the spec, then exposed through the
  bridge. A "small" Dart reimplementation is how three implementations drift.
- The Dart layer holds only the API shape (`Future`, `Stream<SessionState>`), argument validation
  that the native side would also do, and mapping from bridge types to public types.
- Native code in the plugin (`flutter/<plugin>/android`, `.../ios`) is glue: it calls the native
  SDK's public API (not its `@VersolaInternalApi` wiring) and converts types. It contains no
  protocol logic either, and it adds no second copy of the Android or iOS rules.
- The native SDKs are consumed as this repository's own builds: the Android half depends on
  `io.versola:oauth-android`, which the example app's `settings.gradle.kts` substitutes with the
  `:oauth` project through a composite build until the artefact is published; the iOS half depends
  on the root `Package.swift` by path (SwiftPM only, no podspec: CocoaPods is dormant). Flutter
  builds the plugin through a symlink into the app, so the plugin's `Package.swift` finds the
  repository root from its own symlink-resolved `#filePath`, never from a relative `path:` (which
  SwiftPM resolves against the symlink and which pointed into the app). That is what makes a git
  or path dependency on the plugin build; the example app, being inside the checkout, would not
  show a regression, so after touching that manifest build a throwaway app with both kinds of
  dependency. Both pins
  (AGP and Kotlin in the example, the iOS floor in the plugin's `Package.swift`) follow the
  native builds and change with them.

## Bridge

- Pigeon with platform channels, not the Native Interop mode: Native Interop is experimental, has no
  event channels, and requires both sides to pin the same Pigeon version (architecture review
  section 4). The Pigeon definition is the contract; the Pigeon version is pinned in
  `pubspec.yaml`, and generation is deterministic from the definition in the repository.
- Host API methods return `Result`-shaped sealed classes rather than throwing. Pigeon generates
  sealed classes for Dart, Kotlin and Swift, so the four categories of `spec/errors.md`
  (`Recoverable`, `Reauthenticate`, `StepUp`, `Configuration`) arrive typed. A `StepUp` that
  degrades to a `PlatformException`, or a category collapsed into a string, is a bug. Every
  platform error is mapped; an unmapped one is a `Configuration` with a detail, never a crash.
- `Stream<SessionState>` comes from an event channel fed by the native `Flow` / `AsyncStream`. The
  stream carries the seven states of `spec/state-machine.md` and no Flutter-only state. Cancel the
  native collection when the Dart subscription cancels. One channel per client: the Pigeon
  `instanceName` is the handle native's `create` answered with, so Dart derives no identity of its
  own. Pigeon's generated stream is single-listener per channel name (a second `EventChannel` of
  the same name replaces the first's handler), so the Dart client subscribes once and shares the
  subscription among its listeners.
- Every host method answers a Result, including the ones that look infallible (`sessionState`,
  `claims`, `logout`, `keyAttestation`), and native catches everything: an SDK error crosses as
  itself, any other exception as a `Configuration` naming only its class. A channel failure that
  still reaches Dart is turned into a `ConfigurationError` carrying the exception's code and none
  of its message. A native case Dart does not know is `unknown` with the name, never a different
  real case (a guessed `network` starts a retry loop).
- Registering an event channel's handler (`FlutterEventChannel.setStreamHandler`,
  `EventChannel.setStreamHandler`) happens on the platform thread; on iOS that is a `MainActor`
  hop out of any actor, or the engine aborts the process.
- Generated files (`*.g.dart`, the generated Kotlin and Swift) are never hand-edited, and the guard
  hook denies it; change the Pigeon definition (`pigeons/messages.dart`) and regenerate with
  `fvm dart run pigeon --input pigeons/messages.dart`. They are not exported from
  `lib/<package>.dart` and no generated type appears in the public Dart API ("subject to change
  without warning" upstream): public types are hand-written wrappers.

## What crosses the bridge

- Allowed: configuration values, session state, typed results and errors, the user's validated
  claims, and the short-lived access token, returned only from the call whose purpose is to hand
  the app a token (issue #46 decision 7). Apps call their API through `OAuthClient.httpClient()`, a
  `package:http` client that executes the request natively, so a DPoP-bound token is usable from Dart
  with no proof-minting capability crossing; `dio` uses it through a small adapter.
- Never: the refresh token, any private key, key material, a DPoP proof minting capability, the
  pending request, `state`, the PKCE verifier, or the ID token's raw form for storage. No secret
  in a `PlatformException` message, in `debugPrint`, in the example app's UI or in a test fixture.
- Do not add a Dart-side cache of the access token; ask the native side every time so single-flight
  refresh stays in one place.
- No `WebView` plugin dependency, ever (`security.md`). The browser leg is native.

## Commands (run from the plugin directory)

```bash
dart format --set-exit-if-changed .
flutter analyze
flutter test                      # Dart unit tests, bridge mocked
cd example && flutter build apk --debug      # the example app builds on Android
cd example && flutter build ios --no-codesign   # and on iOS
```

- `flutter test` proves the Dart mapping and the error categories against a mocked channel. It does
  not prove the bridge or the native SDKs; say which tier ran (`testing.md`).
- The example app builds on both platforms and exercises sign-in, refresh, sign-out and the error
  categories; a change to the Pigeon definition is not done until both example builds pass. Use
  `example.com` configuration and no real client ids.
- The generic SDK's scenarios 24 to 32 run through the bridge as native tests in the example app
  (`example/android/app/src/test`, `example/ios/RunnerTests`; `conformance/README.md`, "Through the
  Flutter bridge"), against the same provider containers as the native drivers. A scenario that
  passes natively but fails through the bridge is a finding in the bridge. The driver's wiring is
  never added to the plugin: the tests reach it by creating the native client first and letting
  the plugin's `create` resolve the same configuration.

## Packages and dependencies

- `pubspec.yaml` constraints are pinned tightly (a Dart SDK range, exact or caret-minor versions for
  `pigeon` and anything else); `pubspec.lock` is gitignored (`.gitignore`), so the constraints are
  what makes a build repeatable. A new dependency needs approval, with licence and
  maintenance noted (`security.md`).
  The exact-minor pin is for build tooling (`pigeon`, whose version is part of the generated
  contract). A package whose types appear in the public API and which integrators share (`http`)
  gets a range across the major, with the tested version as its floor: a one-minor pin in a library
  fails the integrator's own resolve, since such a package is in nearly every app's graph. Verify
  such a range against the floor and the newest release in range (`flutter pub upgrade <pkg>` in a
  scratch copy) when it is set and when Dependabot bumps it.
- Dependabot watches `pub` under `/flutter/versola_oauth` (with `pigeon` ignored: a bump comes with
  the regeneration) and the example's Gradle build; minors arrive grouped, majors separately
  (`ci-release.md`).
- `flutter.yml` runs the commands above on every PR that touches the plugin or the facades it
  calls: format, analyze, `flutter test`, the regenerate-and-diff check for the Pigeon files, the
  Kotlin and Swift glue tests and both example builds. The example's AGP and Kotlin plugin versions
  equal `android/build.gradle.kts` (an included build cannot load two); when Dependabot bumps the
  latter, that workflow fails on the PR until `example/android/settings.gradle.kts` follows.
- Publishing to pub.dev is dormant: `publish-pubdev.yml` is `if: false` and the first release is a
  manual `flutter pub publish` by the maintainer (`docs/releasing.md`). Do not run `flutter pub
  publish`, with or without `--dry-run`, do not remove the dormancy, and do not add a `publish_to`
  that would enable it by accident. The published plugin has no repository root to find, which the path dependency its iOS
  `Package.swift` has inside a checkout needs: `tools/flutter-prepare-publish.sh` rewrites it to the release
  tag by URL, and drops the root computation, in the publishing job's working copy, and the rewrite is never committed.
