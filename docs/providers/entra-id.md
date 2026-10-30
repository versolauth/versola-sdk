# Microsoft Entra ID

Confidence: **documented, not tested against a real tenant.** This guide is written from Microsoft's
official documentation and from the public v2.0 OpenID configuration documents, all read on
2026-10-30, and checked against [`spec/providers.md`](../../spec/providers.md). Nothing in it was run
against an Entra tenant: the generic facade has never talked to one. Entra is the provider with the
most open questions, so this guide leads with the two that can stop an integration, then gives the
setup. Read [the index](README.md) first for the minimum contract, the confidence markers and the
redirect setup that is the same for every provider.

## Read this first

1. **Configure the issuer with the tenant's GUID, not its domain name.** Reading the public v2.0
   OpenID configuration document of a tenant addressed by its `.onmicrosoft.com` name, its `issuer`
   member was the GUID form `https://login.microsoftonline.com/{tenant-id}/v2.0`, not the domain
   form that was asked for (reported: read from the live document through a fetch summary). The SDK
   requires the configured issuer to equal the discovered one, so a domain-form issuer is expected to
   fail with `Configuration(DiscoveryIssuerMismatch)`. `spec/providers.md` section 3 says "tenant GUID
   or domain"; that is the first disagreement of section 5.
2. **A refresh may fail if Entra's ID token on the refresh response is unsigned.** Microsoft's
   authorization code flow page describes the `id_token` of a refresh response as "an unsigned JSON
   Web Token". Its sample tokens, in both the code redemption response and the refresh response, carry
   the header `{"typ":"JWT","alg":"none"}`, although the description of the redemption response says
   only "a JSON Web Token", and the separate ID tokens page shows a sample signed with RS256. The SDK validates an
   ID token on a refresh response with the login rules and refuses `none`. If Entra really returns
   such a token on refresh, `accessToken()` after the access token expires would fail with
   `Configuration(IdTokenRejected(Algorithm))`, the grant would stay, and the session would be
   unusable until the user signs in again. This is documented, not observed, and the samples may be
   simplified. It needs a test against a tenant before anyone ships on Entra (section 5).

## 1. What to configure in Entra

### The app registration

In the Microsoft Entra admin center, App registrations, create a registration and open
Authentication.

| Setting | Value | Source and confidence |
|---|---|---|
| Supported account types | Single tenant, or the audience your tenant-specific authority serves | The SDK needs a concrete tenant issuer (above). `common` and `organizations` publish a templated issuer and are unsupported. |
| Platform | **Mobile and desktop applications** | Documented: Microsoft's redirect URI page lists this platform for iOS apps using AppAuth or Flutter or implementing OAuth directly, and the how-to page says to select it for "mobile apps not using MSAL or a broker". The Android and iOS/macOS platform tiles generate redirect URIs from a package name and signature hash or a bundle identifier, which suit MSAL; this SDK is not MSAL. |
| Redirect URI | The exact `redirectUri`, as a custom redirect URI | Documented that custom redirect URIs can be entered for this platform; whether Entra accepts an `https` App Link or Universal Link or a private-use scheme there was not tested (see "Redirect URIs"). |
| Client secret or certificate | None | Documented: public clients must not use secrets or certificates when redeeming an authorization code. The SDK has none. |
| Allow public client flows | See the note below | Microsoft's pages disagree. |
| ID tokens (implicit and hybrid) | Not needed | The SDK uses `response_type=code`; the ID token comes from the token endpoint. |

Allow public client flows: Microsoft's redirect URI page says an application that has redirect URIs
"needs to enable a public client flow configuration", while its public and confidential client page
says the setting should stay disabled unless you use device code, the resource owner password flow,
Windows Integrated Authentication or Native Authentication. The SDK uses none of those. If the code
exchange answers `invalid_client` (documented as "Client authentication failed"), this setting is the
first thing to try. It was not tested either way.

### Redirect URIs

Microsoft's redirect URI page (documented) says a redirect URI must begin with `https`, with
exceptions for some localhost URIs; it is case-sensitive; it may not contain `! $ ' ( ) , ;` or an
internationalised domain name; it is at most 256 characters; and an app registration that signs in
personal Microsoft accounts may not use query parameters. A URI with no path is returned with a
trailing slash, so give a path (`https://app.example.com/oauth`).

- **`https` (App Link or Universal Link).** Allowed by the page for every HTTP-based redirect URI.
  This is the form to try first, and the one the SDK prefers, with the Android and iOS setup of the
  [index](README.md#redirect-setup-shared-by-every-provider). Not tested.
- **Private-use scheme.** The same page says redirect URIs begin with `https`; the how-to page offers
  custom redirect URIs for the mobile and desktop platform. The two do not settle whether a plain
  custom scheme such as `com.example.app:/oauth` is accepted. Unverified; register it, try it, and
  expect the SDK's warning on every `create()`.
- **Loopback.** Microsoft recommends `http://localhost` for apps that use a system browser, with the
  port ignored when matching and `[::1]` unsupported. This SDK cannot use it on iOS: it refuses a
  cleartext redirect because `ASWebAuthenticationSession` cannot receive one. It was not evaluated on
  Android.

### Scopes and refresh tokens

A refresh token is issued only if `offline_access` was requested; the v2.0 endpoint requires the scope
explicitly even though granting a delegated permission implies it (documented, scopes page and
authorization code flow page). Put `offline_access` in `scopes` together with `openid` and the
permissions you need.

- A scope without a resource identifier is a Microsoft Graph scope (`User.Read` means
  `https://graph.microsoft.com/User.Read`). For your own API use its application ID URI, for example
  `api://example-api/access_as_user`.
- A single token response is for one resource. The authorize request may span several; the token
  request's scopes must be from one (documented). Ask for one API's scopes plus the OpenID Connect
  scopes.
- `address` and `phone` are not supported scopes (documented).
- Admin-restricted permissions need administrator consent (documented).

Refresh tokens last 90 days by default for apps like this one (24 hours for single-page apps)
(documented, refresh tokens page). Each use returns a new refresh token; Entra does **not** revoke the
old one, and Microsoft says to discard it (documented). No reuse detection is documented.
Consequence, not tested: the generic SDK stores the new token and forgets the old one, and a replay of
the old token after a crash may simply work.

### Sign-out

Entra's `end_session_endpoint` is in the discovery document (`.../oauth2/v2.0/logout`, reported: live
document). Its documented parameters are `post_logout_redirect_uri` (recommended; **it must match one
of the redirect URIs registered for the application**) and `logout_hint`. `id_token_hint` and `state`
are not in the documented table. The SDK sends `id_token_hint`, `post_logout_redirect_uri` and
`state`, so three consequences:

- Register the `postLogoutRedirectUri` as a redirect URI too. There is no separate sign-out list.
- Extra parameters are presumably ignored; that is untested.
- `sessionEnded` is `true` only when the browser returns with the `state` the SDK sent. If Entra does
  not echo `state` on the post-logout redirect, `logout()` returns `sessionEnded = false` even though
  the session ended. Unverified; the local wipe happens regardless.

There is no revocation endpoint (below). A user or administrator can revoke all of a user's refresh
tokens (documented, refresh tokens page).

### PKCE, DPoP and PAR

Entra accepts `S256` and `plain` (documented); the SDK sends `S256`. The v2.0 document read does not
list `code_challenge_methods_supported`; the SDK treats an absent member as unknown and sends `S256`
anyway. Access tokens are `Bearer` only (documented: "The only type that Microsoft Entra ID supports is
`Bearer`"). No PAR endpoint and no DPoP algorithms are advertised (reported: live document).

## 2. SDK configuration

The `issuer` is `https://login.microsoftonline.com/{tenant-id}/v2.0`, using the tenant's directory
(tenant) ID. The IDs below are placeholders.

### Kotlin

```kotlin
import versola.oauth.OAuthClient
import versola.oauth.OAuthConfiguration

val client = OAuthClient.create(
    context,
    OAuthConfiguration(
        issuer = "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
        clientId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        redirectUri = "https://app.example.com/oauth",
        postLogoutRedirectUri = "https://app.example.com/signed-out",
        scopes = setOf("openid", "profile", "offline_access", "api://example-api/access_as_user"),
    ),
)
```

### Swift

```swift
import OAuthClient

let configuration = try OAuthConfiguration(
    issuer: "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
    clientId: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    redirectUri: "https://app.example.com/oauth",
    postLogoutRedirectUri: "https://app.example.com/signed-out",
    scopes: ["openid", "profile", "offline_access", "api://example-api/access_as_user"]
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
  issuer: 'https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0',
  clientId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
  redirectUri: 'https://app.example.com/oauth',
  postLogoutRedirectUri: 'https://app.example.com/signed-out',
  scopes: {'openid', 'profile', 'offline_access', 'api://example-api/access_as_user'},
));
```

### Notes on the values

- **`issuer`**: the GUID form, never `common`, `organizations` or a domain name (see "Read this
  first").
- **`scopes`**: `offline_access` for a refresh token; one API's scopes at most.
- **`postLogoutRedirectUri`**: also registered as a redirect URI. On Android under Auth Tab an `https`
  value must be a verified App Link.
- **`endSessionEndpoint`**: leave unset; discovery has one. If you ever set it, the SDK still sends
  the RP-Initiated Logout parameters (`id_token_hint`, `post_logout_redirect_uri`, `state`), not
  Microsoft's `logout_hint`.
- **`LoginOptions.prompt`**: Microsoft documents `login`, `none`, `consent` and `select_account`;
  `Create` is not among them, so do not use it. `login_hint` cannot be combined with `select_account`
  (documented).
- **`pushedAuthorization`, `tokenBinding`**: leave the defaults; neither capability is advertised.

## 3. What to expect

| Capability | Entra v2.0 per the documentation and the live documents | What the SDK does |
|---|---|---|
| Refresh token | Only with `offline_access` (documented) | With it, a refresh token. Without it, `Authenticated` until the access token expires, then `Reauthenticate(SessionExpired)`, no token request, one warning. |
| Rotation | New token on every use, old not revoked, no reuse detection documented (documented) | New token stored before the old is forgotten. `invalid_grant` is `Reauthenticate(GrantRejected)`, never retried. |
| Revocation | No RFC 7009 endpoint in the live document (reported); none documented | `logout()` skips revocation: `tokenRevoked = false` always. The refresh token stays valid server-side until it expires or is revoked per user. |
| End-session | Present; `post_logout_redirect_uri` must be a registered redirect URI; `state` not documented (documented; reported) | `sessionEnded = true` only if the browser returns with `state`. |
| UserInfo | `https://graph.microsoft.com/oidc/userinfo`; needs a token for Graph (documented) | `userInfo()` sends the session's access token. If that token is for your own API it is not a Graph token: use `claims` from the ID token instead. Untested. |
| PAR | Not advertised (reported) | Plain request. |
| DPoP | Not advertised; tokens are `Bearer` (reported; documented) | Bearer. `Dpop(required = true)` is `ProviderUnsupported("dpop")`. |
| RFC 9207 `iss` on the redirect | Not advertised (reported) | Not required. |
| ID-token algorithm | `id_token_signing_alg_values_supported` is `["RS256"]` (reported) | Accepted. The refresh-response caveat is above. |
| `code_challenge_methods_supported` | Absent from the documents read (reported) | Treated as unknown; `S256` sent. |
| Step-up | A claims challenge (`insufficient_claims`), not RFC 9470 (`spec/providers.md`) | Not a `StepUp`; the app decodes the challenge itself. |
| Rate limiting | Limits unpublished; 429 with `Retry-After` reported (`spec/providers.md`) | A generic transient failure within the retry budget. |

## 4. Known limits

- A multi-tenant app that must accept any tenant (`common`, `organizations`) is out of scope:
  their issuer is a template, and the SDK compares issuers literally.
- No revocation: sign-out leaves the refresh token valid on the server.
- `sessionEnded` may read `false` after a successful sign-out (above).
- Microsoft's own pages advise that native and single-page apps "rarely benefit" from validating ID
  tokens, because anyone with access to the device can bypass the check. The SDK validates every ID
  token and has no off switch (`.claude/rules/security.md`); that includes the one on a refresh
  response.
- Access tokens for Microsoft services can be in a format that does not validate as a JWT, and
  Microsoft tells clients not to read tokens for APIs they do not own. The SDK treats the access
  token as opaque and only validates the ID token.
- Entra's claims challenge, Continuous Access Evaluation, broker-based flows and MSAL's token cache
  are not supported or involved.

## 5. Where the documentation and `spec/providers.md` differ, and what could not be checked

| Point | `spec/providers.md` | What the sources read on 2026-10-30 say | What this guide does |
|---|---|---|---|
| Issuer form for a tenant | "`https://login.microsoftonline.com/{tenant GUID or domain}/v2.0`" | A live document for a domain-addressed tenant announced the GUID form (reported) | Says GUID only. A domain-form issuer is expected to be refused. Not run. |
| ID token on the refresh response | Not mentioned; API 8 says it is validated like login's minus `nonce` | The refresh response's `id_token` is described as unsigned; sample headers in both responses are `alg: none`; the ID tokens page's sample is RS256 (documented) | Flags a possible `IdTokenRejected(Algorithm)` on refresh. Unresolved; needs a tenant. |
| Plain custom scheme as a redirect URI | Unverified | The redirect URI page says `https` with localhost exceptions; the how-to page offers custom redirect URIs for the mobile and desktop platform | Unresolved; says so. |
| "Allow public client flows" | Not mentioned | Two Microsoft pages contradict each other | Says so; no recommendation beyond "check it on `invalid_client`". |
| `id_token_hint` at sign-out | "Not in the documented table" | Confirmed: only `post_logout_redirect_uri` and `logout_hint` are documented; the SDK sends `id_token_hint` and `state` anyway | Says what the SDK sends and what follows. |
| `post_logout_redirect_uri` registration | Not mentioned | Must match a registered redirect URI | New in this guide: register it as a redirect URI. |
| RS256-only and `code_challenge_methods_supported` | Unverified, from Q&A threads | Read from the live common, organizations and tenant-addressed documents: `["RS256"]`; the member absent (reported) | Upgraded to reported. Rechecking against the documents themselves is still owed. |
| No RFC 7009 endpoint | From Q&A threads | Absent from the live document (reported); not documented | Treats revocation as absent. |

Not checked at all: that Entra accepts an `https` App Link or Universal Link as a redirect URI under
the mobile and desktop platform; that the Auth Tab leg and the Universal Link `webcredentials`
requirement work against Entra; anything about throttling (`Retry-After` specifics are search digests
in `spec/providers.md`); the `consumers` authority; sovereign clouds; and everything under "What to
expect".

## 6. How this was verified

It was not run. No Entra tenant was used and the conformance suite has no Entra profile (its providers
are Keycloak and Ory Hydra). The three discovery documents named above are public documents: they were
fetched and read, which says what Microsoft publishes, not that this SDK works with it. The facts taken
from them carry the marker "reported" because they came through a fetch summary. The Microsoft Learn
pages came back as full text. A run against a tenant is the "hosted providers on demand" item of
`conformance/README.md` and has not happened. Nothing is "verified, B4" for Entra.

## Sources

All read on 2026-10-30.

- OAuth 2.0 authorization code flow (parameters, refresh, unsigned refresh `id_token`, `Bearer` only):
  <https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow>
- Redirect URI (reply URL) best practices and limitations:
  <https://learn.microsoft.com/en-us/entra/identity-platform/reply-url>
- How to add a redirect URI to your application:
  <https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-redirect-uri>
- Refresh tokens in the Microsoft identity platform:
  <https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens>
- OpenID Connect on the Microsoft identity platform (configuration document, sign-out):
  <https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc>
- Scopes and permissions (`offline_access`):
  <https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc>
- Public and confidential client apps:
  <https://learn.microsoft.com/en-us/entra/identity-platform/msal-client-applications>
- ID tokens in the Microsoft identity platform:
  <https://learn.microsoft.com/en-us/entra/identity-platform/id-tokens>
- The v2.0 OpenID configuration documents of the `common` and `organizations` authorities and of one
  tenant addressed by its domain name (public documents, read for their shape only):
  <https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration> and
  <https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration>
- This repository: [`spec/providers.md`](../../spec/providers.md) (matrix, sections 3 and 5),
  [`spec/oauth-sdk-api.md`](../../spec/oauth-sdk-api.md), [`spec/errors.md`](../../spec/errors.md).
