# ADR 0002: the `Versola` facade signs in through edge only

Status: proposed, 2026-11-22. Decides what the `Versola` facade is once a deployment has cells and
an edge in front of its issuer, and what it leaves to the generic facade. Builds on ADR 0001, which
decided that the two facades share a protocol core and are free to differ in API.

## Context

The `Versola` facade on Android (`android/sdk`) was built for a deployment of one `auth` reached at
the issuer's address: it reads discovery there, and offers two back channels, `BackChannel.Auth`
(the app is a public client of `auth`) and `BackChannel.Edge` (edge's native endpoints, issue #40).
iOS and Flutter have no `Versola` facade.

The server moved (`versolauth/versola` pull request 1023, read at `0a2b72d34`):

- A deployment may have several `auth` cells. The issuer's address is then an edge's, which serves
  the browser pages of a sign-in (`/authorize`, `/challenge/**`, `/logout`) and nothing a client
  calls: no `/token`, `/par`, `/userinfo`, `/revoke`, discovery or JWKS (`IssuerFront.scala`).
- `fapi2` is the default profile of a tenant and refuses a public client.
- A native client fronted by edge is DPoP-bound, pushes every request and redirects to `https`
  only, in every tenant (`InvalidRegistrationConfiguration.scala`).
- `/native/start` answers the `authorization_endpoint` to open and the two endpoints later proofs
  are signed for, and forwards a fixed list of authorization parameters.

So on the deployment the facade exists for, discovery cannot be fetched, `BackChannel.Auth` has no
endpoint to call, and the bearer fallback has no client that could use it.

## Decision 1: one back channel

The `Versola` facade signs in, refreshes and revokes through edge's native endpoints and has no
other path. `BackChannel`, `tokenBinding`, discovery and the bearer mode leave its public API. An
app that talks to an `auth` directly, as a public client on a `standard` tenant, uses the generic
facade, which is what that is.

| | Kept two back channels | One (chosen) |
|---|---|---|
| Works with cells | only `Edge` | yes |
| Works on a `fapi2` tenant | only `Edge` | yes |
| Configuration an integrator can get wrong | back channel, binding, issuer, edge | edge, client, redirect |
| Bearer rotation with `Idempotency-Key` against Versola's `auth` | exercised by scenarios 09 and 13 | no facade exercises it; the core keeps the rule at the unit tier |
| Code and tests carried | two starters, two token clients, discovery | one of each |

The cost is the third row from the bottom: scenarios 07, 09, 10 and 13 lose the facade they ran
under. 07 and 10 describe what the generic facade also does; 09 and 13 rest on a header no
standard defines, which the generic facade does not send (ADR 0001). They stay in the catalogue as
the core's rules and are proven against stubs only.

## Decision 2: no discovery; the issuer is configuration

The facade is configured with `edgeUrl`, `clientId` and `redirectUri`. `issuer` defaults to
`edgeUrl` and is set when it differs (a partner edge; an issuer at another address). The browser
opens the `authorization_endpoint` that `/native/start` answered; the end-session page is the
issuer's `/logout`.

Alternative: require `issuer`. One more value in the common case, for a mistake that already fails
loudly: a redirect whose `iss` is not the configured one is `Configuration(IssuerMismatch)` before
any network call (RFC 9207), and edge checks it again.

Alternative: take the issuer from `/native/start`. Rejected: the value an `iss` check compares
against must not come from the response the check protects.

## Decision 3: ID-token claims are checked, the signature is not, until the key set is reachable

The facade validates `iss`, `aud` and `azp`, `exp`, `iat`, `nonce`, `auth_time` under `max_age`,
`at_hash`, and `sub` continuity, and cannot verify the signature: no endpoint a native app reaches
serves the key set. OpenID Connect Core 1.0 section 3.1.3.7 step 6 permits relying on TLS for a
token received from the token endpoint; here it arrives from edge, which is the client that
received it. `spec/versola-sdk-api.md` section 9 states the limit and what the claims are used for.

This is less than `security.md` asks of an ID-token check, and it is more than the facade does
today (nothing: architecture review F5). It is a limit of the deployment, recorded in
`server-dependencies.md`, with no parameter: when the server serves the key set at the issuer's
address the signature check is added and is not optional.

Alternative: wait for the server before validating anything. Rejected: `nonce`, `aud` and
`auth_time` are checkable now and are the checks a missing one is exploited through.

## Decision 4: typed options, no free-form parameters

`login()` takes the parameters `/native/start` forwards, as typed options, and no map. Edge drops
any other parameter without an error, so a map would let an app set something that does nothing.
Issue #128 asked for a map; it predates the allow-list. A parameter the server adds (phone-number
verification, versola#887) becomes an option in the release that follows.

Cost: a server parameter needs an SDK release. If edge answered `invalid_request` for a parameter
it does not forward, a map could be offered without the silent failure.

## Decision 5: one facade for first-party and partner apps

A partner app is the same facade with `edgeUrl` set to the partner's edge and `issuer` to the
operator's. No `kind` or `mode` parameter: what differs (consent in the browser, no account
surface, the partner edge's own resources) is the server's, and a flag that forks the SDK is the
shape `REVIEW.md` flags. The server does not let a partner register a native client yet, so the
partner case is specified and not built.

## Decision 6: names

| Where | Name |
|---|---|
| Kotlin | package `versola.sdk`, artefact `io.versola:versola-android` |
| Swift | product and module `VersolaSDK`, type `Versola` |
| Dart | plugin `versola` |

`VersolaSDK` and not `Versola` for the module, because a Swift module and a type of the same name
cannot be told apart in a qualified name. Adding the product changes the product list of
`Package.swift` and the scheme `ios.yml` builds, both of which need the maintainer's say-so.

## Consequences

- Android `:sdk` loses `BackChannel`, `tokenBinding`, `metadata()`, `accessToken()`, the public
  `dpop` property and discovery, and gains `LoginOptions`, the ID-token check, `claims`, the
  account check on a step-up and `LogoutOptions`. `:core` keeps the edge starter and token client.
  Nothing of `:sdk` is published, so no released API changes.
- The shared error type gains `Recoverable(AccountMismatch)`: a public addition on every platform
  and in the generic facade's types.
- `REVIEW.md`, `.claude/rules/android-kotlin.md` and `.claude/rules/spec-conformance.md` still name
  `BackChannel`; they change with the code, not before it.
- Conformance needs a staged stack with two cells for scenarios 39 and 40.
