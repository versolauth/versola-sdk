# Versola Mobile SDKs

Native SDKs that let a mobile app authenticate against Versola and call APIs through edge,
without the integrator having to learn OAuth.

```kotlin
val versola = Versola.configure(
    context,
    issuer      = "https://id.versola.kz",
    clientId    = "mobile-app",
    redirectUri = "https://app.example.com/oauth",
    // Separate configuration: edge's address is not in the OAuth metadata.
    edgeBaseUrl = "https://versola.kz",
)

versola.login(scopes = setOf("openid", "profile"))
val response = versola.call(request)
versola.logout()
```

DPoP, nonce handling, refresh coordination and secure storage are the SDK's job, not the
integrator's. So is `offline_access`: `login()` asks for it whatever scopes it is given,
because a session with no refresh token is not one the SDK can keep.

A client on a FAPI 2.0 tenant — the server's default for a new tenant — cannot be a public
client of auth. Add `backChannel = BackChannel.Edge` and the SDK authorizes through edge's
native endpoints instead, with the same API and the same key-bound tokens:

```kotlin
val versola = Versola.configure(
    context,
    issuer      = "https://id.versola.kz",
    clientId    = "mobile-app",
    redirectUri = "https://app.example.com/oauth",   // an https App Link is required here
    edgeBaseUrl = "https://versola.kz",
    backChannel = BackChannel.Edge,
)
```

## The generic facade

The same core serves any conforming provider through `OAuthClient` (`android/oauth`,
`spec/oauth-sdk-api.md`): Bearer by default, DPoP when the app opts in and the provider
advertises it, PAR when advertised, the ID token validated against the provider's keys before
anything is stored, and a token attached only to the origins the app names.

```kotlin
val oauth = OAuthClient.create(
    context,
    OAuthConfiguration(
        issuer = "https://keycloak.example.com/realms/app",
        clientId = "mobile",
        redirectUri = "https://app.example.com/oauth",
        scopes = setOf("openid", "profile", "offline_access"),
        protectedOrigins = setOf("https://api.example.com"),
    ),
)
oauth.login()
val response = oauth.call(request)
oauth.logout()
```

## Status

Phase 1 — Android — is functionally complete on `main`: discovery and browser authorization
(#5), hardware DPoP (#6), secure storage (#7), token endpoint and single-flight refresh (#8),
the authenticated client and step-up (#9), logout (#10), and authorization through edge's
native endpoints for FAPI 2.0 tenants (#40). What is proven against stubs only is tracked
in issues #36, #37 and #39 and the conformance harness (#15). Issue #1 is the grounding
document every other issue assumes; read it before opening a pull request, and
[`spec/server-dependencies.md`](spec/server-dependencies.md) for what the server does today.

| Phase | Contents |
|---|---|
| 0 | `spec/` — state machine, error taxonomy, retry policy, conformance catalogue |
| 1 | Android |
| 2 | iOS |
| 3 | Conformance harness, Flutter, `mobile-demo` migration |

## Layout

```text
spec/            state machine, errors, retry policy, conformance scenarios,
                 the generic facade's API (oauth-sdk-api.md) and provider matrix (providers.md)
android/         Gradle multi-project: oauth-core (the protocol engine, plain JVM, package
                 versola.oauth.core), core (the edge back channel, versola.sdk.core), dpop,
                 storage, browser, okhttp, sdk (the Versola facade), oauth (the generic OAuthClient facade,
                 spec/oauth-sdk-api.md), conformance-android and conformance-oauth (the drivers)
ios/Sources/     Swift targets
Package.swift    at the repo root; SPM cannot resolve a manifest from a subdirectory
flutter/         plugin + Pigeon bridge
conformance/     harness driving every SDK against a staged auth + edge, and the provider
                 containers (providers/) the generic facade is proven against
```

## Portability

The core — PKCE, DPoP proofs, nonce handling, refresh coordination, secure storage, browser
flows — is plain RFC behaviour and must stay usable against any conforming OpenID provider.
Versola-specific pieces depend on the core, never the reverse. Behaviour the core exhibits
that a generic provider would reject is a bug.

## Working on this repository

`develop.md` has the toolchains and the commands for every tier. `AGENTS.md` is the shared
policy for contributors and coding agents (`CLAUDE.md` imports it; `.claude/rules/` holds the
rules scoped by path and `.claude/hooks/` the guards). Pull requests are reviewed against
`REVIEW.md`; security reports follow `SECURITY.md`. Issue #46 tracks the generic OAuth SDK that
shares this repository's protocol core.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
