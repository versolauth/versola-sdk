# Security

This SDK holds the credentials of an identity provider's users on their phones: a mistake here is
a vulnerability in every app that embeds it, not a bug. Platform specifics are in
`android-kotlin.md`, `ios-swift.md` and `flutter.md`; what the tests must prove is in
`testing.md`. This file is the rest.

## Default stance

- Fail closed. When a check cannot be completed (a key cannot be unwrapped, discovery omits a
  member, the redirect carries no `iss`, a header is absent), the operation is refused with a
  typed error from `spec/errors.md`, never allowed with a log line.
- Do not loosen a security check to make a test, a demo, a conformance run or a provider work. If
  a legitimate case needs an exception, say what it is and ask; the answer belongs in
  `spec/providers.md` as a documented limit, not in a flag (see `spec-conformance.md`).
- Every security-relevant branch has a negative test next to the positive one (`testing.md`).
- If you notice a vulnerability while doing something else, tell the user in the conversation. Do
  not put exploit details in a public issue, commit message or PR description before it is fixed.
  Reporting is private, through the repository's Security tab (`SECURITY.md`).

## Key material and storage classes

- Keys are non-exportable and stay in hardware where the device has it. Android: DPoP keys are
  generated StrongBox first and fall through to the TEE at runtime (`KeystoreDpopKey`, catching
  `StrongBoxUnavailableException`), and the tier actually obtained is read back from the key's
  security level and surfaced as `KeyAttestation` (`StrongBox`, `TrustedEnvironment`, `Software`).
  `setIsStrongBoxBacked(true)` succeeding is not proof of where the key landed; do not report a
  tier you did not read back.
- Android credential storage is an AES-256-GCM key held in the Keystore that wraps the refresh
  token, ID token and pending request (`HardwareKeyProvider`). Files live under `noBackupFilesDir`
  so a device backup cannot replay them on another device. Do not reintroduce
  `EncryptedSharedPreferences` (deprecated, ruled out in `android/storage/build.gradle.kts`) and do
  not write a token to `SharedPreferences`, DataStore or a file in the clear.
- iOS credential storage is the Keychain with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
  and `kSecAttrSynchronizable = false`: usable after a background refresh, never restored onto
  another device, never in iCloud Keychain. The DPoP key is a Secure Enclave key whose
  `dataRepresentation` is persisted; it is not user-gated (issue #1 section 4).
- What is stored where is fixed by the persistence table in `spec/state-machine.md`. Putting an
  item in a more permissive place (the access token on disk, the nonce in the Keychain) is a spec
  change first.
- A software-tier key is a fact to report, not an error to hide. The app decides whether it
  accepts `Software`; the SDK does not silently downgrade a configuration that asked for more.

## Secrets never leave the store

- The refresh token and every private key never leave the platform store: not into logs,
  `toString()`, exception messages, error detail, metrics labels, analytics, crash reports,
  intents, `Bundle`s, `UserDefaults`, notifications or a pasteboard.
- Types that carry a secret override `toString()` / `description` to a redacted constant, as
  `TokenResponse`, `AuthorizationGrant`, `CodeVerifier` and `AccessToken` do
  (`"...(redacted)"`). A new such type does the same, and a `@Serializable` or `data class` that
  would print its fields gets a wrapper (see the comment in `TokenResponse.kt`).
- The refresh token is unwrapped for one token request and zeroed afterwards. Keep it that way;
  do not cache a decrypted copy.
- Nothing credential-shaped crosses the Flutter bridge. The one exception is the short-lived access
  token (issue #46 decision 7), and only through the call that returns it (`flutter.md`).
- The default log level emits no token, code, verifier, `state`, `nonce` or proof. Scenario 01
  asserts it; a new log line is reviewed against that assertion.

## The browser leg and redirect validation

- Authorization runs in the system browser only: Auth Tab or Custom Tabs on Android,
  `ASWebAuthenticationSession` on iOS. A `WebView` / `WKWebView` is unreachable from any public
  API. `BrowserAuthorizationSession` takes a URI, which is what keeps a web view
  unrepresentable; do not widen that contract.
- The redirect is validated in this order, before any network call: `state` (constant-time
  comparison), `iss` (RFC 9207), then `code`. The same sequence on every platform; scenarios 15
  and 16 hold it.
- `state`, `nonce`, PKCE `S256`, `iss` and ID-token validation (signature, `iss`, `aud` / `azp`,
  `exp`, `nonce`, `auth_time` under `max_age`) are never optional and have no off switch. The
  architecture review's F5 (ID token never validated) is the example of what a missing MUST costs.
  Never add a `validateX = false`, a debug bypass or a plain-HTTP allowance to the public API.
- Compare secrets and MACs in constant time (`MessageDigest.isEqual`, CryptoKit, a loop with no
  early exit); never `==` on a `state`, a code, a hash or a token.
- Randomness for `state`, `nonce`, PKCE verifiers and `jti` comes from the platform CSPRNG
  (`SecureRandom`, `SystemRandomNumberGenerator`), at least 128 bits. Never a seeded or
  `Random`-based source, and never a value derived from the clock.
- No client secret is representable. The configuration types have no `clientSecret` parameter
  (RFC 8252 section 8.5, issue #46 decision 4). A provider that demands one for a native app is a
  documented limit.
- Redirect handling uses explicit intents and verified App Links / Universal Links; a custom
  scheme is accepted with a loud warning (`android-kotlin.md`).

## Tests, docs and samples

- `example.com` and `example.org` hosts, throwaway client ids and generated keys only. No real
  issuer, client id, token, certificate or device identifier in tests, scenarios, docs, samples or
  fixtures. The conformance harness stages its own stack; it never points at a production tenant.
- A real secret does not go into the repository in any form: code, workflows, Gradle properties,
  `local.properties`, Xcode schemes, plist files. CI credentials are repository secrets
  (`VERSOLA_CHECKOUT_TOKEN`, publishing keys) referenced by name and never echoed.

## Dependencies and supply chain

- Adding a dependency needs approval. Check it is maintained, that its licence is compatible with
  Apache-2.0 (no GPL / AGPL / SSPL, no field-of-use restriction), that it pulls no transitive
  surprises, and prefer the platform's own crypto over a library (Keystore, CryptoKit, `java.security`).
  State licence and maintenance in the PR. Pins and versions live in the Gradle build files, the
  version catalogue and `Package.swift`.
- Workflow actions are pinned to a full commit SHA with the version in a comment. Do not replace a
  pin with a floating tag; `ci-release.md` has the rest.
- Scanners (secret scan, dependency review, CodeQL) say next to each job whether they gate or only
  report. Do not change that without being asked, and never suppress a finding silently: a
  suppression names the reason, an owner and a re-evaluation date.
- CodeQL and dependency review run only when the repository is public
  (`ci-release.md`); that is not a reason to skip the manual review they would have done.

## Review

Changes to token handling, key generation, storage, the browser leg, redirect validation, DPoP
proofs, the bridge, or any workflow need a code-owner review (`.github/CODEOWNERS`). For a change to
any of these, offer to run the `security-review` skill before the PR is opened, and say in the PR
which of the checks above the change touches.
