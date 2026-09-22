# Versola Mobile SDKs

Native SDKs that let a mobile app authenticate against Versola and call APIs through edge,
without the integrator having to learn OAuth.

```kotlin
val versola = Versola.configure(
    context,
    issuer      = "https://id.versola.kz",
    clientId    = "mobile-app",
    redirectUri = "https://app.example.com/oauth",
)

versola.login(scopes = setOf("openid", "profile"))
val response = versola.httpClient().newCall(request).execute()
```

DPoP, nonce handling, refresh coordination and secure storage are the SDK's job, not the
integrator's.

## Status

Phase 0 — specification. No implementation exists yet. Issue #1 is the grounding document
every other issue assumes; read it before opening a pull request.

| Phase | Contents |
|---|---|
| 0 | `spec/` — state machine, error taxonomy, conformance catalogue |
| 1 | Android |
| 2 | iOS |
| 3 | Conformance harness, Flutter, `mobile-demo` migration |

## Layout

```
spec/            state machine, errors, conformance scenarios
android/         Gradle multi-project
ios/Sources/     Swift targets
Package.swift    at the repo root; SPM cannot resolve a manifest from a subdirectory
flutter/         plugin + Pigeon bridge
conformance/     harness driving every SDK against a staged auth + edge
```

## Portability

The core — PKCE, DPoP proofs, nonce handling, refresh coordination, secure storage, browser
flows — is plain RFC behaviour and must stay usable against any conforming OpenID provider.
Versola-specific pieces depend on the core, never the reverse. Behaviour the core exhibits
that a generic provider would reject is a bug.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
