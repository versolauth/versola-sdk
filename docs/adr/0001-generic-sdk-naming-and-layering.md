# ADR 0001: naming and layering of the generic OAuth SDK

Status: proposed, 2026-10-29. Decides the two questions issue #46 left to this document: what the
generic SDK is called on every registry, and which code the two facades share.

## Context

The repository ships the `Versola` facade (Android complete through #40; iOS and Flutter
placeholders), built on `android/core`, which README.md and #4 describe as plain RFC behaviour
usable against any provider. In practice `core` also holds the edge back channel (`BackChannel`,
`EdgeNativeTokenClient`, `NativeAuthorizationStarter`, `NativeEndpoints*`, `MtlsEndpointAliases`'
edge usage) and 855 lines of public wiring (`core.api`). Issue #46 adds a second facade with its own
API, `spec/oauth-sdk-api.md`, for any conforming provider. Two facades that each carry nonce
handling, single-flight refresh and the retry budget would be the drift #1 section 3 rejects; a
generic core that cannot express a Versola choice would push Versola behaviour into "generic" code.

## Decision 1: names

| Where | Name | Why |
|---|---|---|
| Kotlin packages | `versola.oauth.*` (generic), `versola.sdk.*` (Versola facade; moved from `kz.versola.sdk.*` in B2, nothing is published) | the maintainer's decision of 2026-10-29: the import an integrator types starts with `versola` |
| Android library namespaces | `versola.oauth`, `versola.oauth.core`, `versola.sdk`, … | two segments, which is what AGP requires of a namespace |
| Maven Central | `io.versola:oauth-android`, `io.versola:versola-android` | Central verifies a groupId by DNS ownership or a code-host account (#4); a bare `versola` cannot be verified. The groupId is the one place reverse-DNS survives, and it follows the project's domain, `versola.io` (the project moved from `versola.kz` on 2026-10-30, before anything was published, so the group is `io.versola`). Alternative `io.github.versolauth` is possible but ties the artefact to a GitHub account rather than the domain |
| Swift | module and product `VersolaOAuth`; `Versola*` targets stay for the Versola facade | one `Package.swift`; SwiftPM has no namespace to verify |
| Dart | `package:versola_oauth`; the Versola plugin `package:versola` later | pub.dev package names are bare |
| Opt-in marker | `@VersolaInternalApi` in `versola.oauth` | one marker for both facades; the conformance drivers opt in, apps cannot without saying so |

## Decision 2: shared core, independent facades

```text
android/
  oauth-core/   kotlin("jvm"), package versola.oauth.core (no android.* import; hook-enforced)
  dpop/ storage/ browser/ okhttp/   unchanged in purpose, depend on oauth-core
  oauth/        com.android.library, package versola.oauth: the OAuthClient facade
  core/         package versola.sdk.core: what is Versola-specific
  sdk/          package versola.sdk: the Versola facade
```

- `oauth-core` is the protocol engine: discovery, PKCE, authorization request and response, the
  token client, ID-token validation, the session coordinator, the retry budget, the error
  taxonomy, the DPoP proof contract, the storage and browser contracts. It knows nothing about
  edge, tenants, security profiles or any Versola endpoint.
- Facades differ in API and defaults and are not held to each other. `Versola.configure()` keeps
  `edgeBaseUrl`, `BackChannel`, DPoP by default and the edge-native flow; `OAuthClient` has
  `spec/oauth-sdk-api.md`. Neither is "the real API" of the other.
- A Versola behaviour becomes a seam of `oauth-core` only when it is RFC-shaped or when the core
  already needs the extension point for another reason. Otherwise it lives in `core`. The seams
  below are the ones the current code already has; B2 adds none speculatively.

### Seams the facades use

| Seam (in `oauth-core`) | Generic facade | Versola facade |
|---|---|---|
| `TokenClient` (`exchange`, `refresh`, `revoke`) | `HttpTokenClient` against the discovered token endpoint | `HttpTokenClient` under `BackChannel.Auth`; `EdgeNativeTokenClient` (in `core`) under `BackChannel.Edge` |
| Authorization starter (builds the request the browser opens) | PKCE request, or PAR then `request_uri` | the same, or `/native/start` (in `core`) |
| `BrowserAuthorizationSession` (URI in, outcome out) | Auth Tab / Custom Tabs; `ASWebAuthenticationSession` | the same; the harness's `HttpLoginBrowser` opts in |
| `CredentialStore`, `CredentialKeyProvider`, `PendingAuthorizationStore` | `storage` module | the same |
| `DpopProofSource`, `DpopKeyBinding` | `dpop` module, opt-in | the same, default |
| Token-request decoration (extra headers and form fields) | none | `Idempotency-Key` on refresh |
| Error extension cases | none | `EdgeClientUnknown` and future edge-only details |
| Token binding default | `Bearer` | `Dpop` |

Error extension cases use one pattern: each sealed detail hierarchy in `oauth-core`
(`Configuration.Detail`, `Reauthenticate.Reason`, `Recoverable.Cause`) carries one abstract
subclass `Extension` that a facade module may extend. An exhaustive `when` in app code handles
`is Extension` as one branch; the generic facade never produces one, and the Versola facade
documents its cases. This keeps one `OAuthError` type on both facades (the Versola facade exposes it
under its own name as a type alias) without putting edge vocabulary in the core.

### Where each existing `core` type goes

| Type | Destination | Note |
|---|---|---|
| `AccessToken`, `AccessTokenSource`, `AuthorizationGrant`, `AuthorizationRequest`, `AuthorizationResponseValidator`, `BrowserAuthorizationSession`, `BrowserOutcome`, `CodeVerifier`, `Pkce`, `PendingAuthorizationRequest`, `PendingAuthorizationCodec`, `PendingAuthorizationStore`, `CredentialStore`, `CredentialKeyProvider`, `DiscoveryClient`, `DiscoveryService`, `HttpDiscoveryClient`, `ProviderMetadata`, `ProviderMetadataCache`, `FileProviderMetadataCache`, `RedirectUri`, `RedirectUriKind`, `RetryPolicy`, `SessionCoordinator`, `SessionState`, `TokenBinding`, `TokenClient`, `HttpTokenClient`, `TokenResponse`, `UnlockPolicy`, `DpopProofSource`, `DpopKeyBinding`, `VersolaLogger` | `oauth-core` | moved as-is, package renamed; most become `internal` or `@VersolaInternalApi` (architecture review F6) |
| `MtlsEndpointAliases` | `oauth-core` | RFC 8705 metadata, generic; only its consumer in the edge flow is Versola-specific |
| `VersolaConfiguration` | `oauth-core`, under its current name until B3 (issuer, client id, redirect URIs, validation) | both facades' configuration types wrap it; the rename to `ClientConfiguration` lands with the generic facade for the same reason as `VersolaError` |
| `VersolaError` | `oauth-core`, under its current name until B3 | `EdgeClientUnknown` moves to `core` as an `Extension`. The rename to `OAuthError` waits for the generic facade: a Kotlin type alias cannot name nested classes (`VersolaError.Configuration` through an alias does not compile), so the Versola facade's code will reference the renamed type directly, which is B3's change to make, not B2's |
| `AuthorizationFlow` | `oauth-core`, with the `AuthorizationStarter` seam (done in B2) | the edge branch moved to `core`'s `EdgeAuthorizationStarter`; the pending request carries an opaque `extension` map and an `issRequired` flag instead of edge fields |
| `BackChannel`, `EdgeNativeTokenClient`, `NativeAuthorizationStarter`, `HttpNativeAuthorizationStarter`, `NativeStart`, `NativeStartRequest`, `NativeEndpoints`, `NativeEndpointsStore`, `FileNativeEndpointsStore` | `core` | Versola-specific by definition |
| `Idempotency-Key` on refresh (inside `HttpTokenClient` today) | `oauth-core` seam, enabled by the Versola facade | an unknown header is harmless to other providers, but the generic facade sends only what a standard defines |

iOS mirrors the split with targets `OAuthCore` (plus `OAuthDPoP`, `OAuthStorage`, `OAuthBrowser`,
`OAuthURLSession`) and `OAuthClient` under the product `VersolaOAuth`; the `Versola*` targets
depend on them when the Versola iOS facade is built. Flutter has one plugin per facade.

## Consequences

- B2 is a mechanical move with the Versola facade's tests kept green and `apiDump` regenerated;
  the public API of `Versola` does not change in B2 except the package rename, the
  `@VersolaInternalApi` marker on the wiring the edge module reaches, and `EdgeClientUnknown`
  becoming a top-level class of `versola.sdk.core` (an `Extension` of the shared detail type).
- A Versola choice that cannot be a seam is not forced into the core; it stays in `core` and the
  ADR's seam table gains no row. If B2 finds that most of the coordinator must fork, this ADR is
  revisited rather than bent.
- The conformance catalogue gains a `facade` field so a scenario can say which facades it holds
  (`spec/conformance/README.md`).

## Alternatives considered

- **Independent generic modules, re-base the Versola facade later.** Rejected: duplicates the code
  the spec exists to keep single; the re-base never happens.
- **One facade with a `provider` switch.** Rejected: the defaults differ (DPoP, PAR, edge) and a
  mode switch is the boolean-fork shape `REVIEW.md` flags.
- **Bare `versola` Maven groupId.** Not possible: Central's namespace verification (#4).
