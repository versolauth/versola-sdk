# Keycloak

Confidence: **tested in CI against a container**, `quay.io/keycloak/keycloak:26.4` in development
mode with the realm in
[`conformance/providers/keycloak/realm.json`](../../conformance/providers/keycloak/realm.json).
Not tested: a production-mode Keycloak, other 26.x lines, a hostname or proxy setup of your own, or
any customised login theme or authentication flow. Read [the index](README.md) first for the minimum
contract, the confidence markers and the redirect setup that is the same for every provider.

## 1. What to configure in Keycloak

### Realm and issuer

The discovery document is at `{base}/realms/{realm}/.well-known/openid-configuration` and the issuer
is `{base}/realms/{realm}` (documented, Keycloak's OIDC page). Open the discovery document in a
browser and copy its `issuer` member: that exact value is what you configure. In development mode
Keycloak derives the issuer, every endpoint and the login form's action from the `Host` of the
request (verified, B4), so what you see depends on how you reach it; a production deployment fixes
the hostname in its own configuration, which these guides did not test.

### The client

Create an OpenID Connect client for the app. The fields below are what the conformance realm sets;
the names in backticks are the realm-import attributes it uses.

| Setting | Value | Why |
|---|---|---|
| Client authentication | Off (`publicClient: true`) | A native app cannot keep a secret; the SDK has no secret to send. |
| Standard flow | On (`standardFlowEnabled`) | The authorization code flow is the only flow the SDK uses. |
| Implicit flow, direct access grants, service accounts | Off | Not used; the conformance realm leaves them off. |
| Valid redirect URIs | The exact `redirectUri` string, one entry per platform if they differ | Keycloak matches exactly and case-sensitively; a wildcard is allowed only at the end of a pattern (documented, Keycloak server admin guide). |
| Valid post logout redirect URIs | The exact `postLogoutRedirectUri` (`attributes."post.logout.redirect.uris"`) | Without a registered URI Keycloak does not redirect back after sign-out. |
| PKCE code challenge method | `S256` (`attributes."pkce.code.challenge.method"`) | Makes Keycloak refuse a request without S256. The SDK always sends it. The console label for this option was not read for this guide. |
| Web origins | Empty | A native app makes no cross-origin browser requests. |

Redirect URIs for Android App Links, iOS Universal Links and custom schemes are all registered as
plain entries in that list. The conformance realm registers an `https` URL only
(`https://conformance.example.com/oauth`). A custom-scheme redirect and loopback port handling
were not exercised, and the Keycloak documentation pages read for the matrix do not state their
rules (`spec/providers.md`, "Not verified"). Prefer the `https` form, as everywhere
([index](README.md#redirect-setup-shared-by-every-provider)).

### Scopes and refresh tokens

Keycloak issues a refresh token for the authorization code flow by default, without any special
scope: the conformance client asks for `openid profile` only and receives one (verified, B4). The
conformance realm also lists `offline_access` as an optional client scope.

`offline_access` is a different thing on Keycloak: it asks for an **offline token**. Per the
Keycloak documentation an offline token is not bound by the SSO session timeouts, stays valid after
the user signs out, must be used at least every 30 days (or within the realm's Offline Session Idle
setting), and requires the user to hold the realm role `offline_access` (documented, Keycloak
server admin guide, "offline" topic). Do not add it unless you want that behaviour. The SDK never
adds it, and at `create()` it logs one warning if `scopes_supported` lists `offline_access` and your
scopes do not; for Keycloak the warning says a refresh token *may* not be issued, and Keycloak
issues one regardless.

### Refresh token rotation

Rotation is a realm setting: **Revoke Refresh Token** under Realm settings, Tokens (documented,
Keycloak server admin guide, "timeouts" topic). The conformance realm sets
`revokeRefreshToken: true` and `refreshTokenMaxReuse: 0`. With it on, reusing a rotated refresh
token is `400 invalid_grant` ("Maximum allowed refresh token reuse exceeded") and revokes the
session (verified, B4). The SDK stores each rotated token before it forgets the old one, treats
`invalid_grant` as `Reauthenticate(GrantRejected)` and never retries it. What a realm that does not
set the option does by default was not established; set it deliberately.

An important consequence of the generic facade sending no `Idempotency-Key`: if the app is killed
after Keycloak rotated the token but before the new one was stored, the next refresh is a replay and
ends in `GrantRejected`. Keycloak's "Refresh Token Max Reuse" is the option that softens this; its
name and effect were not confirmed in the pages read here, so check it on your version before
relying on it.

### Sign-out

Keycloak's end-session endpoint is `.../protocol/openid-connect/logout` and discovery advertises it.
With `id_token_hint`, a registered `post_logout_redirect_uri` and `state` it answers a direct `302`
to the post-logout URI carrying `state`, with no confirmation page (verified, B4). Without an
`id_token_hint` Keycloak shows a confirmation page; that variant was not driven.

The revocation endpoint is `.../protocol/openid-connect/revoke`. A public client sends `client_id`
together with `token` and `token_type_hint`, and nothing else (verified, B4).

## 2. SDK configuration

The `issuer` below is `{base}/realms/{realm}` with the realm name `example`. No trailing slash:
Keycloak announces none.

### Kotlin

```kotlin
import versola.oauth.OAuthClient
import versola.oauth.OAuthConfiguration

val client = OAuthClient.create(
    context,
    OAuthConfiguration(
        issuer = "https://id.example.com/realms/example",
        clientId = "example-app",
        redirectUri = "https://app.example.com/oauth",
        postLogoutRedirectUri = "https://app.example.com/signed-out",
        scopes = setOf("openid", "profile"),
    ),
)
```

### Swift

```swift
import OAuthClient

let configuration = try OAuthConfiguration(
    issuer: "https://id.example.com/realms/example",
    clientId: "example-app",
    redirectUri: "https://app.example.com/oauth",
    postLogoutRedirectUri: "https://app.example.com/signed-out",
    scopes: ["openid", "profile"]
)
let client = try await OAuthClient.create(
    configuration: configuration,
    presentationAnchor: appKeyWindow  // from the index page
)
```

The Swift package product is `VersolaOAuth`; the module you import is `OAuthClient`.

### Dart

```dart
import 'package:versola_oauth/versola_oauth.dart';

final client = await OAuthClient.create(const OAuthConfiguration(
  issuer: 'https://id.example.com/realms/example',
  clientId: 'example-app',
  redirectUri: 'https://app.example.com/oauth',
  postLogoutRedirectUri: 'https://app.example.com/signed-out',
  scopes: {'openid', 'profile'},
));
```

### Notes on the values

- **`scopes`**: `openid` is always added. Add `profile`, `email` and so on as the client's scopes
  allow. Not `offline_access`, unless you want an offline token (section 1).
- **`postLogoutRedirectUri`**: set it. `sessionEnded` in the logout result is `true` only when the
  browser returns to this URI carrying the `state` the SDK sent (derived from the SDK source,
  `AuthorizationFlow.endSession`); without it the provider may end the session and the result still
  says `false`. On Android under Auth Tab an `https` value must be a verified App Link too.
- **`endSessionEndpoint`**: not needed. Keycloak advertises it.
- **`pushedAuthorization`**: leave the default. Keycloak advertises PAR, so `WhenAdvertised` pushes
  the request, and the conformance suite ran that way (section 3).
- **`tokenBinding`**: leave the default `Bearer`. See section 3 for DPoP.

## 3. What to expect

| Capability | Keycloak 26.4 as observed | What the SDK does |
|---|---|---|
| Refresh token | Issued without `offline_access` (verified, B4) | `Authenticated` with a refresh token; rotation as the realm is set. |
| Revocation | Present, public client sends `client_id` only (verified, B4) | `logout()` revokes; `tokenRevoked = true`. |
| End-session | Present; direct `302` with `state` when `id_token_hint` and a registered URI are sent (verified, B4) | `sessionEnded = true` when the redirect returns with the matching `state`. |
| UserInfo | Present (verified, B4) | `userInfo()` works; `sub` is checked against the ID token. |
| PAR | `pushed_authorization_request_endpoint` advertised, `require_pushed_authorization_requests: false`, public client accepted (verified, B4) | Default `WhenAdvertised` pushes the request and opens the browser with `client_id` and `request_uri` only. A rejection (for example an unregistered redirect URI) is `Configuration(AuthorizationRejected)` before any browser opens: Keycloak answers `400 invalid_request` "Invalid parameter: redirect_uri". |
| RFC 9207 `iss` on the redirect | Advertised and sent (verified, B4) | Checked on every redirect. |
| DPoP | `dpop_signing_alg_values_supported` advertised with ES, RS and PS 256 to 512 and EdDSA (verified, B4); the DPoP flow itself was not driven | Default is `Bearer`. `Dpop(required = false)` would use DPoP because `ES256` is advertised. Not tested against Keycloak; do not enable the per-client "Require DPoP bound tokens" option together with it on the strength of this guide. |
| ID-token algorithm | `RS256` by default; the discovery list also names HS256/384/512 and EdDSA (verified, B4) | The SDK's closed set refuses HMAC whatever discovery lists, and accepts `RS256`. |
| `Date` header on the token response | Absent (verified, B4) | The server-time skew correction does not engage; `iat` and `exp` are checked against the device clock within `clockSkewTolerance`. |
| Step-up (RFC 9470) | Not found in Keycloak's documentation | No `StepUp` is raised by Keycloak itself. `acrValues` in `LoginOptions` reach Keycloak's LoA mapping (documented), which was not tested. |

## 4. Known limits

- Single account per client configuration; the same for every provider.
- A refresh replay after a crash ends in `Reauthenticate(GrantRejected)` (section 1).
- Offline tokens (`offline_access`) were not tested at all.
- Custom-scheme and loopback redirect rules, "Exclude Issuer From Authentication Response", the
  default of "Revoke Refresh Token", RFC 9470 and rate limiting at the token endpoint are open
  items in [`spec/providers.md`](../../spec/providers.md), section 5.
- The login conversation was driven for a user without required actions or consent
  (`emailVerified: true`, non-temporary password, first-party client). A realm that forces a
  required action, an MFA step or a consent screen shows those pages in the browser; the SDK is
  not involved, but the suite did not cover them.

## 5. How this was verified

The Android driver `android/conformance-oauth` ran scenarios 24 to 32 against
`quay.io/keycloak/keycloak:26.4` staged from
[`conformance/providers/keycloak/`](../../conformance/providers/keycloak/), all green, in the
`providers` job of `.github/workflows/conformance.yml`
([`spec/providers.md`](../../spec/providers.md), section 4). The iOS driver and the Flutter-bridge
drivers are the same design and run locally against the same container
([`conformance/README.md`](../../conformance/README.md)). What the scenarios asserted:

- **24** sign-in, an authenticated call to a protected origin, UserInfo, and sign-out: the token
  request carried no `client_secret`, the ID token was validated before `Authenticated`, and
  nothing went to a non-protected origin with an `Authorization` header.
- **25 to 27** a re-signed ID token with a wrong `nonce`, a bad signature or algorithm, and wrong
  `iss`, `aud`, `exp`, `iat` or `auth_time` was refused with the matching reason.
- **28** the whole flow from explicit endpoints, with no request to any `/.well-known/` path.
- **29** PAR used when advertised, a rejected PAR surfacing as `AuthorizationRejected` before the
  browser, and `ProviderUnsupported` for the `Never` and `Required` mismatches.
- **30** sign-out with discovery's `end_session_endpoint` removed, with revocation failing, and with
  the browser dismissed.
- **31** a client registered with refresh tokens off and ten-second access tokens
  (`conformance-app-norefresh`) ended in `Reauthenticate(SessionExpired)` with no token request.
- **32** the token attached to the configured origin and nowhere else.

The session was staged as a throwaway: development mode, `sslRequired: none`, test user
`alice`. No scenario drove Custom Tabs, Auth Tab, a real device, a production
Keycloak or the DPoP flow, and scenario 31's clock step is real time against ten-second tokens
rather than a moved device clock.

## Sources

Read on 2026-10-30 unless noted. Findings marked "verified, B4" come from the conformance run, not
from these pages.

The pages were read through a fetch tool that summarises long pages (Microsoft Learn pages came back
as full text). Where a guide says "documented" for one of these pages it means the summary stated it;
recheck exact setting names on the page or in the dashboard before relying on them.

- Keycloak, securing applications, OIDC endpoints:
  <https://www.keycloak.org/securing-apps/oidc-layers>
- Keycloak server admin guide, client basic settings (client authentication, standard flow, valid
  redirect URIs):
  <https://raw.githubusercontent.com/keycloak/keycloak/main/docs/documentation/server_admin/topics/clients/oidc/con-basic-settings.adoc>
- Keycloak server admin guide, offline tokens:
  <https://raw.githubusercontent.com/keycloak/keycloak/main/docs/documentation/server_admin/topics/sessions/offline.adoc>
- Keycloak server admin guide, session timeouts and "Revoke Refresh Token":
  <https://raw.githubusercontent.com/keycloak/keycloak/main/docs/documentation/server_admin/topics/sessions/timeouts.adoc>
- Keycloak server admin guide, client advanced settings (checked for the PKCE, PAR and DPoP option
  labels: not present on this page):
  <https://raw.githubusercontent.com/keycloak/keycloak/main/docs/documentation/server_admin/topics/clients/oidc/con-advanced-settings.adoc>
- This repository: [`spec/providers.md`](../../spec/providers.md) (matrix and section 4),
  [`spec/oauth-sdk-api.md`](../../spec/oauth-sdk-api.md),
  [`conformance/providers/keycloak/`](../../conformance/providers/keycloak/),
  [`conformance/README.md`](../../conformance/README.md).
