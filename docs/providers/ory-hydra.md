# Ory Hydra

Confidence: **tested in CI against a container**, `oryd/hydra:v26.2.0` with Ory's reference
login-consent app `oryd/hydra-login-consent-node:v26.2.0`, configured as in
[`conformance/providers/hydra/`](../../conformance/providers/hydra/). Not tested: Ory Network, the
Enterprise build, a persistent database, your own login, consent and logout UI, or any Hydra other
than that image. Read [the index](README.md) first for the minimum contract, the confidence markers
and the redirect setup that is the same for every provider.

Hydra is an OAuth 2.0 and OpenID Connect server without a user interface. Sign-in, consent and
sign-out screens are an application you write or deploy and point Hydra at. Everything the user
sees during `login()` and `logout()` comes from that application, not from the SDK or Hydra.

## 1. What to configure in Hydra

### Server configuration

These keys come from the conformance
[`hydra.yml`](../../conformance/providers/hydra/hydra.yml). Values are placeholders.

```yaml
urls:
  self:
    issuer: https://auth.example.com/
    public: https://auth.example.com/
  login: https://login.example.com/login
  consent: https://login.example.com/consent
  logout: https://login.example.com/logout

secrets:
  system:
    - replace-with-your-own-generated-secret

oauth2:
  pkce:
    enforced_for_public_clients: true
```

- **`urls.self.issuer` is announced verbatim**, trailing slash included, in discovery and in every
  ID token's `iss`. Hydra builds its issuer and every URL it hands the browser from
  `urls.self.issuer` and `urls.self.public`, never from the request (verified, B4). Decide the
  value once and give the SDK the same string.
- **`login`, `consent` and `logout`** are the URLs of your user-facing application.
- **`oauth2.pkce.enforced_for_public_clients: true`** makes Hydra refuse a public client's request
  without a code challenge. The SDK always sends `S256`, so it does not depend on this; enable it so
  other clients cannot skip PKCE. The default of this option was not established (the Ory page read
  says PKCE can be used without enforcement by default, and can be required for all clients or only
  for public ones).

### The client

Register the app as a public client. The conformance suite imports an array of clients with
`hydra import oauth2-client clients.json --endpoint http://hydra:4445`; a single object is refused,
the file is a JSON **array** (verified, B4).

```json
[
  {
    "client_id": "example-app",
    "token_endpoint_auth_method": "none",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "scope": "openid offline_access profile email",
    "redirect_uris": ["https://app.example.com/oauth"],
    "post_logout_redirect_uris": ["https://app.example.com/signed-out"],
    "skip_consent": false
  }
]
```

- **`token_endpoint_auth_method: none`** is what makes the client public. Hydra's CLI default is
  `client_secret_basic`, so set `none` explicitly (documented per `spec/providers.md`; the Ory page
read for this guide says public clients are registered with `none`).
- **`redirect_uris`** are matched exactly; wildcards are not allowed; custom schemes such as
  `com.example.app:/callback` are allowed; `javascript:`, `data:` and `vbscript:` are rejected
  (documented, Ory OAuth2 clients page). Register the exact `redirectUri` string of each platform.
  This covers Android App Links, iOS Universal Links and custom schemes alike. Loopback port rules
  are not on the page read and were not tested.
- **`post_logout_redirect_uris`** must contain the exact `postLogoutRedirectUri`. Only registered
  URIs can be used (documented, Ory OIDC logout page).
- **`scope`** lists every scope the client may request, including `offline_access`. A client whose
  scope lacks it never receives a refresh token (verified, B4).

### Scopes and refresh tokens

A refresh token is issued when `offline_access` is requested **and** granted: the client must be
allowed to request it, and your consent application must accept it for the user (documented, Ory
authorization code flow page; verified, B4: a token was issued for `openid profile offline_access`
and not for `openid profile`). Discovery lists `scopes_supported: [offline_access, offline, openid]`.
The conformance consent app grants every scope the request asks for; yours must not drop
`offline_access`.

### Refresh token rotation

Hydra's refresh tokens are always single-use, and reuse revokes the tokens linked to the same
consent (documented per [`spec/providers.md`](../../spec/providers.md); the Ory page read for this
guide says only that a reused token "triggers reuse detection"). Reuse detection was not driven in
the conformance run. The optional grace period is
`oauth2.grant.refresh_token.rotation_grace_period`; it is off unless set, and at most 5 minutes
without a reuse count (documented, Ory graceful refresh page). It softens a retry after a crash. The
Ory page calls it a workaround that weakens reuse detection, and the generic SDK's rule does not
change with it: `invalid_grant` is `Reauthenticate(GrantRejected)`, never retried.

### Sign-out

Hydra's end-session endpoint is `{public}/oauth2/sessions/logout`. With an `id_token_hint`, a
registered `post_logout_redirect_uri` and `state` it redirects the browser to your logout UI
(`urls.logout`, with a `logout_challenge`), which must accept or reject the request; then Hydra
redirects to the post-logout URI carrying `state` (verified, B4). The conformance app confirms the
logout unless the user declines. If your logout UI never accepts the request, the browser never
returns and `logout()` reports `sessionEnded = false`.

The revocation endpoint is `/oauth2/revoke`. A public client sends `client_id` with `token` and no
other client authentication; the revoked refresh token is then `400 invalid_grant` at the token
endpoint (verified, B4).

## 2. SDK configuration

`issuer` is exactly what `urls.self.issuer` is, trailing slash included. The SDK accepts either form
at the discovery comparison (one trailing slash is ignored there), but the ID token's `iss` is held
to the discovered value byte for byte, so write what Hydra announces.

### Kotlin

```kotlin
import versola.oauth.OAuthClient
import versola.oauth.OAuthConfiguration

val client = OAuthClient.create(
    context,
    OAuthConfiguration(
        issuer = "https://auth.example.com/",
        clientId = "example-app",
        redirectUri = "https://app.example.com/oauth",
        postLogoutRedirectUri = "https://app.example.com/signed-out",
        scopes = setOf("openid", "profile", "offline_access"),
    ),
)
```

### Swift

```swift
import OAuthClient

let configuration = try OAuthConfiguration(
    issuer: "https://auth.example.com/",
    clientId: "example-app",
    redirectUri: "https://app.example.com/oauth",
    postLogoutRedirectUri: "https://app.example.com/signed-out",
    scopes: ["openid", "profile", "offline_access"]
)
let client = try await OAuthClient.create(
    configuration: configuration,
    presentationAnchor: appKeyWindow  // from the index page
)
```

### Dart

```dart
import 'package:versola_oauth/versola_oauth.dart';

final client = await OAuthClient.create(const OAuthConfiguration(
  issuer: 'https://auth.example.com/',
  clientId: 'example-app',
  redirectUri: 'https://app.example.com/oauth',
  postLogoutRedirectUri: 'https://app.example.com/signed-out',
  scopes: {'openid', 'profile', 'offline_access'},
));
```

### Notes on the values

- **`scopes`**: include `offline_access` or the session has no refresh token and ends when the
  access token expires. The SDK never adds it; discovery lists it, so a configuration without it
  gets one warning at `create()`.
- **`postLogoutRedirectUri`**: set it, and register it. `sessionEnded` is `true` only when the
  browser returns to it with the `state` the SDK sent (derived from the SDK source).
- **`endSessionEndpoint`**: not needed; discovery advertises it.
- **`pushedAuthorization`**: leave the default. Hydra advertises no PAR, so `WhenAdvertised` sends
  the plain request, and `Required` would be `ProviderUnsupported("par")`.
- **`tokenBinding`**: leave `Bearer`. Hydra advertises no DPoP, so `Dpop(required = true)` is
  `ProviderUnsupported("dpop")` and `Dpop(required = false)` falls back to bearer with a warning.

## 3. What to expect

| Capability | Hydra v26.2.0 as observed | What the SDK does |
|---|---|---|
| Discovery | `issuer` verbatim from `urls.self.issuer`; `jwks_uri` under `/.well-known/jwks.json` (verified, B4) | Fetches `{issuer}/.well-known/openid-configuration` and compares issuers. |
| Refresh token | Only with `offline_access` requested and granted (verified, B4) | With it: `Authenticated` with a refresh token. Without: the session ends at access-token expiry with `Reauthenticate(SessionExpired)`, no token request. |
| Revocation | Present, public client sends `client_id` only (verified, B4) | `tokenRevoked = true` on success. |
| End-session | Present, through your logout UI (verified, B4) | `sessionEnded = true` when the browser returns with `state`. |
| UserInfo | Present; opaque access tokens are accepted (verified, B4) | `userInfo()` works. |
| PAR | Not advertised (verified, B4) | Plain authorization request. |
| RFC 9207 `iss` on the redirect | Not advertised and not sent (verified, B4) | Not required because not advertised; checked when present. |
| DPoP | Not advertised (verified, B4) | Bearer. |
| ID-token algorithm | `RS256` only (verified, B4) | Accepted. |
| `Date` header on the token response | Absent (verified, B4) | No server-time skew correction; the device clock is checked within `clockSkewTolerance`. |

## 4. Known limits

- You need a login, consent and logout application. The SDK cannot supply one, and the sign-in
  pages in the conformance run are Ory's reference app, a fixed test user with no real
  authentication.
- No `iss` on the redirect means the SDK cannot use RFC 9207 mix-up protection against Hydra; the
  `state` check and the ID token's `iss` still apply.
- Vendor documentation and observation disagree on PKCE methods: the Ory authorization code flow
  page says the `plain` method is not supported, while the live discovery document listed
  `code_challenge_methods_supported: [plain, S256]` (verified, B4). The SDK sends `S256` whatever is
  listed, so nothing depends on it, but do not read that list as "plain is refused".
- A refresh replay after a crash ends in `Reauthenticate(GrantRejected)`; the grace period softens
  it and was not tested.
- Open items in [`spec/providers.md`](../../spec/providers.md), section 5: whether the Enterprise
  build adds RFC 9207, PAR or DPoP, the default of `oauth2.pkce.enforced`, logout with an expired
  `id_token_hint`, loopback redirect port behaviour, `acr_values` handling, Ory Network custom
  domains and rate limits.
- Ory Network (the hosted service) was not run. Its limits (429 with `x-ratelimit-reset`) are
  documented, not tested, and the SDK retries a 429 only as a generic transient failure within the
  operation's budget.

## 5. How this was verified

The Android driver `android/conformance-oauth` ran against `oryd/hydra:v26.2.0` staged from
[`conformance/providers/hydra/`](../../conformance/providers/hydra/): 25 of 27 tests green, and the
two PAR tests of scenario 29 skipped by assumption because Hydra advertises no PAR. The two
`ProviderUnsupported` tests of scenario 29 ran. The job is the `providers` job of
`.github/workflows/conformance.yml`. The iOS driver and the Flutter-bridge drivers run locally
([`conformance/README.md`](../../conformance/README.md)). What ran:

- **24** sign-in with `openid profile offline_access`, an authenticated call, UserInfo, revocation
  and sign-out through the logout UI, with no `client_secret` anywhere.
- **25 to 27** a tampered ID token refused with the matching reason.
- **28** the whole flow from explicit endpoints, with no discovery request.
- **29** the `Never`-with-required-PAR and `Required`-without-endpoint cases, as
  `ProviderUnsupported("par")`. The PAR push and its rejection did not run.
- **30** sign-out with `end_session_endpoint` removed, with revocation failing, and dismissed.
- **31** `conformance-app-norefresh` (grant type `authorization_code` only, scope without
  `offline_access`, access-token lifespan 10 s) ended in `Reauthenticate(SessionExpired)`.
- **32** the token attached to the configured origin only.

The stack was `DSN=memory` with `serve all --dev` (plain HTTP, non-secure cookies), the SDK reached
it through the driver's proxy on a fixed port because Hydra takes its URLs from configuration, and
the login conversation was about ten HTTP hops through Ory's reference app. Custom Tabs, Auth Tab,
Universal Links and a real device were not part of it.

## Sources

Read on 2026-10-30 unless noted; "verified, B4" findings come from the conformance run.

The pages were read through a fetch tool that summarises long pages (Microsoft Learn pages came back
as full text). Where a guide says "documented" for one of these pages it means the summary stated it;
recheck exact setting names on the page or in the dashboard before relying on them.

- Ory, OAuth2 clients (public client, redirect URIs, post-logout URIs, grant types):
  <https://www.ory.com/docs/hydra/guides/oauth2-clients>
- Ory, OIDC logout (`id_token_hint`, `post_logout_redirect_uri`, `state`, registered URIs):
  <https://www.ory.com/docs/oauth2-oidc/oidc-logout>
- Ory, authorization code flow (PKCE enforcement, `offline_access`, consent, S256):
  <https://www.ory.com/docs/oauth2-oidc/authorization-code-flow>
- Ory, graceful token refresh (rotation grace period):
  <https://www.ory.com/docs/hydra/guides/graceful-token-refresh>
- This repository: [`spec/providers.md`](../../spec/providers.md) (matrix and section 4),
  [`spec/oauth-sdk-api.md`](../../spec/oauth-sdk-api.md),
  [`conformance/providers/hydra/`](../../conformance/providers/hydra/),
  [`conformance/README.md`](../../conformance/README.md).
