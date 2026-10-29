---
paths: ["ios/**", "Package.swift"]
---

# iOS / Swift

`OAuthCore` and `OAuthClient` (product `VersolaOAuth`) are real since issue #46's B5; the
`Versola*` targets are still placeholders. Copy the Android module of the same name for behaviour
(`android-kotlin.md`), and the spec for what it must do (`spec/`). The two implementations are written against the same conformance
transcripts, not against each other's code. Security rules are in `security.md`.

## Package layout

- `Package.swift` stays at the repository root: SPM cannot resolve a manifest from a subdirectory
  (issue #1 section 3, proven by the `swift package resolve` step in `ios.yml`). Targets use
  `path: "ios/Sources/<Name>"` and test targets `path: "ios/Tests/<Name>Tests"`, so Xcode sees a
  normal `ios/` tree. A new target is added in the manifest, in `ios/Sources`, in `ios/Tests`, and
  in the products list only if integrators import it.
- Targets: `OAuthCore` (the protocol engine, Android's `:oauth-core`: Foundation, CryptoKit and
  Security only, no UI, no Keychain, no browser) and `OAuthClient` (the generic facade and the
  platform halves it wires: Keychain stores, `ASWebAuthenticationSession`, the authenticated
  `URLSession` wrapper, the Secure Enclave DPoP key; product `VersolaOAuth`). The placeholder
  `VersolaCore`, `VersolaDPoP`, `VersolaStorage`, `VersolaBrowser`, `VersolaURLSession` targets are
  for the Versola facade, which does not exist on iOS yet; when it does it depends on `OAuthCore`
  the way Android's `:core` does, and `OAuthCore` never on it.
- The package is source, not a binary XCFramework: the licence is Apache-2.0, there is nothing to
  hide, and a binary would force library-evolution mode and make every dependency's ABI part of the
  contract. Do not add a `.binaryTarget`. CocoaPods is dormant in `release.yml`.
- `Package.swift` is `swift-tools-version:6.0` with `.iOS("17.4")` (https callbacks in
  `ASWebAuthenticationSession`, architecture review F11, issue #46 decision 6) and `.macOS("14.4")`
  so `swift test` on a host compiles the same AuthenticationServices API. Do not change the floor,
  the tools version or the product list as a side effect; ask first. Adding an availability check
  that quietly narrows the floor is the same change.

## Swift 6 and concurrency

- Swift 6 language mode (`swiftLanguageMode(.v6)` per target, which makes strict concurrency
  part of the language), so a concurrency diagnostic is a compile error, not a warning to review.
- The public surface is `Sendable` value types: `struct` and `enum` with associated values.
  `SessionState` and the four-category error are `Sendable` enums (`spec/errors.md`).
- Shared mutable state lives in an `actor`. The session coordinator is the textbook case: a single
  refresh in flight, callers coalescing on its result, the rotation slot persisted. Remember actor
  reentrancy: every `await` inside the coordinator is a point where another caller can enter, so
  re-check the state after it, and persist before and after as the spec says
  (`spec/state-machine.md`).
- No `@unchecked Sendable`, no `nonisolated(unsafe)`, no global mutable `var`. If a type does not
  fit, change the design; if a framework type forces it, wrap it in an actor and say why in a
  comment. A synchronous read a `Clock` or a logger needs is `OSAllocatedUnfairLock`, not a lock
  behind `@unchecked`.
- `AsyncStream` is single-consumer, so two observers would starve one another. Expose
  `sessionStates()` as a function that creates a stream per call, backed by an actor-held set of
  continuations, with `onTermination` removing the continuation.
- Callbacks only as `@Sendable` closures, and only where a platform API demands one. Public async
  work is `async` / `throws`. Cancellation is honoured, and persistence of a token that already came
  back is not skipped because the caller was cancelled.
- Time and randomness are injected (a clock closure, `SystemRandomNumberGenerator` behind a
  protocol) so tests need no sleeps (`testing.md`).

## Browser

- `ASWebAuthenticationSession` only. `WKWebView` and `SFSafariViewController` are unreachable from
  any public API in `VersolaBrowser`.
- `prefersEphemeralWebBrowserSession` is `false` by default, with an opt-in that mirrors Android's
  ephemeral option, so the state machine stays one machine.
- `canceledLogin` is one error code for two causes. Pair it with app lifecycle state at the moment
  it arrives: while the app is foreground it is a user cancel (wipe the pending request); while
  backgrounded or inactive it is a system cancel (keep it, retry silently). This is required, not
  optional (`spec/state-machine.md`, "cancel").
- The presentation anchor comes from the app. Do not reach for `UIApplication.shared.keyWindow` or
  any API that finds a window by itself.

## Keychain and keys

- Refresh token and pending request: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` and
  `kSecAttrSynchronizable = false`. Anything else (`WhenUnlocked`, synchronizable, no `ThisDeviceOnly`)
  is a security change; ask first (`security.md`).
- Write the new token before removing the old: `SecItemUpdate`, not delete-then-add, so a crash
  between the two cannot lose the credential.
- `errSecInteractionNotAllowed` (-25308) means the device is locked: surface `UnlockRequired`
  (`Recoverable`), never sign the user out and never wipe the item.
- The DPoP key is a CryptoKit `SecureEnclave.P256.Signing.PrivateKey`; persist its
  `dataRepresentation` (an encrypted blob, not the key). `SecureEnclave.isAvailable` decides the
  software fallback and the `KeyAttestation` value, and the value is read back, not assumed. The key
  is not user-gated by default (issue #1 section 4). `signature(for:).rawRepresentation` is already
  `R || S`; do not port Android's DER conversion.
- Never log or `print` a token, key blob, `state` or proof; redact in `description` and
  `debugDescription`.

## Background and lifecycle

- No background scheduling in the SDK: no `BGTaskScheduler`, no timers that refresh on their own.
  The SDK refreshes when asked; the app owns `BGAppRefreshTask`. A refresh started from a
  background task must be cancellable, because iOS grants about 30 seconds.
- Do not add a background-mode or entitlement requirement to the integrator without asking.

## Commands (repository root)

```bash
swift package resolve                  # SPM resolution from a clean checkout
swift build
swift test                             # macOS host; what runs without a simulator
xcodebuild build -scheme Versola-Package -destination "platform=iOS Simulator,name=iPhone 17"
xcodebuild test  -scheme Versola-Package -destination "platform=iOS Simulator,name=iPhone 17"
```

- `.github/workflows/ios.yml` runs exactly the `resolve`, `xcodebuild build` and `xcodebuild test`
  lines. `generic/platform=iOS` fails there ("Supported platforms for the buildables in the current
  scheme is empty"), so a concrete simulator is used. The simulator name is whatever the runner's
  Xcode ships and drifts with Xcode upgrades ("iPhone 16" disappeared and became "iPhone 17");
  when it vanishes, bump the name in both steps of `ios.yml` and say so in the PR.
- The maintainer's Mac has Xcode 16.3. `swift test` on a host cannot exercise the Secure Enclave or
  a real Keychain access group; that is the device tier on a simulator or phone, and the PR says
  which tier ran.

## Tests

- XCTest. Name a test for the behaviour and its condition:
  `testRefreshWithReplayedTokenEndsInReauthenticate`, not `testRefresh2`.
- A security check gets a negative test beside the positive one; concurrency tests start two
  racing callers (`testing.md`).
