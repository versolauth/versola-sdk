# Auth0

Confidence: **documented, not tested against a real tenant.** This guide is written from Auth0's
official documentation, read on 2026-10-30, checked against
[`spec/providers.md`](../../spec/providers.md). Nothing in it was run against an Auth0 tenant: the
generic facade has never talked to one. Where the documentation and `spec/providers.md` differ, or
where a claim could not be checked, the text says so and the list is collected in section 5. Read
[the index](README.md) first for the minimum contract, the confidence markers and the redirect setup
that is the same for every provider.

## 1. What to configure in Auth0

### The application

Create an application of type **Native** (documented: Auth0's Android and iOS quickstarts, application
settings page). A native app is a public client: the authorization code flow with PKCE replaces the
client secret, and the PKCE token request carries `client_id`, `code_verifier`, `code` and
`redirect_uri` and no secret (documented, Auth0's PKCE how-to). Do not copy a client secret from the
dashboard into the app: the SDK has no parameter for one.

| Setting | Value | Source and confidence |
|---|---|---|
| Application type | Native | Documented. |
| Allowed Callback URLs | The exact `redirectUri`, one per platform if they differ (comma separated) | Documented. Wildcards are supported but not recommended for production. |
| Allowed Logout URLs | The exact `postLogoutRedirectUri` | Documented; see "Sign-out" below. |
| OIDC Conformant | On | Documented as a toggle under Advanced Settings, OAuth; refresh token rotation is supported only for OIDC-conformant applications. |
| Signing algorithm (ID token) | RS256 | Documented: Advanced Settings, OAuth, HS256 or RS256, RS256 recommended. The SDK refuses HMAC: an application on HS256 fails with `IdTokenRejected(Algorithm)`. |
| Grant types | Authorization Code and Refresh Token | Documented for the refresh token (Auth0's "call your API" page). |
| Token endpoint authentication method | `none` | Documented on the revocation reference: a public client may omit the secret there only when the application's `tokenEndpointAuthMethod` is `none`; set in the dashboard or the Management API. Whether a new Native application defaults to it: not found. |

### Redirect URIs for Android and iOS

Auth0's quickstarts register these shapes, and the SDK accepts any of them as `redirectUri`:

| Platform | Form | Registered as |
|---|---|---|
| Android, App Links | `https://{domain}/android/PACKAGE_NAME/callback` | Callback and logout URL (documented, Android quickstart). The `https` scheme requires App Links setup. |
| Android, custom scheme | `myapp://{domain}/android/PACKAGE_NAME/callback` | Both fields (documented). Auth0's page calls custom schemes less secure than App Links and advises App Links. |
| iOS, Universal Link | `https://{domain}/ios/BUNDLE_ID/callback` | Both fields (documented, iOS quickstart). Needs the Apple Team ID and bundle identifier under Advanced Settings, Device Settings, the Associated Domains capability with `webcredentials:{domain}`, iOS 17.4 or newer. |
| iOS, custom scheme | `BUNDLE_ID://{domain}/ios/BUNDLE_ID/callback` | Both fields (documented). |

`{domain}` is the tenant domain, or the custom domain if you use one. These are the shapes Auth0's
own SDKs use; the generic SDK does not require them. Any `https` URL on a host you control that
serves Digital Asset Links (Android) and an `apple-app-site-association` file (iOS) works the same
way, as long as the exact string is in Allowed Callback URLs. A private-use scheme works and logs a
warning on every `create()`; the Auth0 PKCE page "strongly discourages" custom schemes.

### Audience and refresh tokens

- **`audience`.** To get an access token for your own API, the `/authorize` request carries
  `audience` set to the API's Identifier. Auth0's PKCE reference lists it as required for that flow;
  the PKCE how-to page does not mention it. It is not an SDK option: pass it per login through
  `LoginOptions.extraParameters` (`audience` is not a reserved parameter), or use `resources`
  (RFC 8707 `resource`) if the tenant's Resource Parameter Compatibility Profile is set for it
  (documented on the reference; how the setting interacts with `audience` is not explained there).
  Without an audience, what kind of access token you receive was not stated on the pages read.
- **Refresh token.** Put `offline_access` in `scopes`, and enable **Allow Offline Access** (documented:
  the "call your API" page says on the API, the PKCE how-to says in Application Settings, the
  application settings page lists no such setting; see section 5). The application's grant types
  include Refresh Token. The response then carries a `refresh_token` only if `offline_access` was
  requested and allowed.
- **PKCE.** `code_challenge_method` accepts only `S256` (documented, Authorization Code Flow with PKCE
  reference). The SDK always sends it.

### Refresh token rotation

Rotation is per application: Applications, the application, Settings, **Refresh Token Rotation**,
turn on **Allow Refresh Token Rotation**, set a **Rotation Overlap Period** in seconds, save
(documented, "Configure Refresh Token Rotation"). Each use returns a new token and invalidates the
old one. Presenting an already-used token is treated as reuse and invalidates the whole family: every
token descended from the original, including the newest, until the user signs in again (documented,
"Refresh Token Rotation"). The overlap period is a grace window for network delays: the immediately
previous token may be reused inside it without tripping detection. Its default and maximum are not
stated on the pages read.

With rotation on, an expiration must be set: **Set Maximum Refresh Token Lifetime** (absolute, up to
one year) and **Set Idle Refresh Token Lifetime** (default 30 days, resets on each exchange)
(documented, "Configure Refresh Token Expiration"). A token's lifetime does not extend when it
rotates.

### Sign-out

Auth0 has two sign-out endpoints and they take different parameters.

- **OIDC logout (RP-Initiated Logout 1.0).** Takes `id_token_hint` (recommended), `logout_hint`,
  `post_logout_redirect_uri`, `client_id`, `state`, `federated` and `ui_locales` (documented, "Log
  Users Out of Auth0"). The `post_logout_redirect_uri` must be in **Allowed Logout URLs**: in the
  application's settings when `id_token_hint` is used, and query strings must match exactly. Discovery
  advertises `end_session_endpoint` only when the tenant setting **RP-Initiated Logout End Session
  Endpoint Discovery** is on (Settings, Advanced, Login and Logout; Management API field
  `oidc_logout.rp_logout_end_session_endpoint_discovery`), which is on by default for tenants created
  on or after 14 November 2023 (documented). For an older tenant, turn it on or give the SDK the URL
  yourself. The pages read do not state the endpoint's path; `spec/providers.md` names `/oidc/logout`
  from memory (unverified), so take the path from Auth0's Authentication API reference for OIDC
  Logout.
- **Legacy `/v2/logout`.** Takes `returnTo`, optional `client_id` and `federated`, against Allowed
  Logout URLs (documented, "Redirect Users After Logout"). The parameters are not RP-Initiated
  Logout's, and the SDK's `endSessionEndpoint` override replaces only the URL, never the parameters.
  If you must use it, do the browser step in app code after `logout()` has wiped locally.

### Revocation

`POST /oauth/revoke` with `client_id` and `token`, and no secret for a public client whose
`tokenEndpointAuthMethod` is `none` (documented). Whether discovery lists a `revocation_endpoint` was
not established. Without one, `logout()` skips revocation and reports `tokenRevoked = false`; pass
`endpoints` instead of `issuer` only if you need to supply it, which also turns discovery off.

### PAR and DPoP

PAR needs an Enterprise plan with the Highly Regulated Identity add-on and a tenant toggle that is
off by default (documented, "Configure PAR"); the page does not say whether public applications
may use it, and `spec/providers.md` records that as reported unsupported. DPoP support is documented
for Auth0 (see `spec/providers.md`); neither was tested. Leave the defaults and see section 3.

## 2. SDK configuration

The `issuer` is `https://{domain}/` **with the trailing slash**. Auth0's documentation shows access
tokens whose `iss` is `https://{domain}/` (documented, access token profiles page: sample tokens), and
for a custom domain shows `iss` as the custom domain with a trailing slash (documented, custom
domains SDK configuration page). The discovery document's `issuer` member itself could not be
checked, because the pages read do not show one. The SDK ignores a single trailing slash when it
compares the configured issuer with discovery's, and holds the ID token's `iss` to discovery's value
byte for byte, so writing the slash is the safe choice.

Use one domain per client configuration. A configuration whose `iss` follows a different domain than
discovery's would be refused by the ID-token check.

### Kotlin

```kotlin
import versola.oauth.LoginOptions
import versola.oauth.OAuthClient
import versola.oauth.OAuthConfiguration

val client = OAuthClient.create(
    context,
    OAuthConfiguration(
        issuer = "https://login.example.com/",
        clientId = "example-app",
        redirectUri = "https://login.example.com/android/com.example.app/callback",
        postLogoutRedirectUri = "https://login.example.com/android/com.example.app/callback",
        scopes = setOf("openid", "profile", "offline_access"),
    ),
)

client.login(
    LoginOptions(extraParameters = mapOf("audience" to "https://api.example.com")),
)
```

### Swift

```swift
import OAuthClient

let configuration = try OAuthConfiguration(
    issuer: "https://login.example.com/",
    clientId: "example-app",
    redirectUri: "https://login.example.com/ios/com.example.app/callback",
    postLogoutRedirectUri: "https://login.example.com/ios/com.example.app/callback",
    scopes: ["openid", "profile", "offline_access"]
)
let client = try await OAuthClient.create(
    configuration: configuration,
    presentationAnchor: appKeyWindow  // from the index page
)

try await client.login(
    try LoginOptions(extraParameters: ["audience": "https://api.example.com"])
)
```

### Dart

```dart
import 'package:versola_oauth/versola_oauth.dart';

final client = await OAuthClient.create(const OAuthConfiguration(
  issuer: 'https://login.example.com/',
  clientId: 'example-app',
  redirectUri: 'https://login.example.com/android/com.example.app/callback',
  postLogoutRedirectUri:
      'https://login.example.com/android/com.example.app/callback',
  scopes: {'openid', 'profile', 'offline_access'},
));

await client.login(
  const LoginOptions(extraParameters: {'audience': 'https://api.example.com'}),
);
```

The redirect URIs above are Auth0's quickstart shapes, per platform: in a Flutter app the Android
build and the iOS build need their own value, so choose it per platform. Auth0's quickstarts register
the same URL in both Allowed Callback URLs and Allowed Logout URLs; the snippets follow that.

### Notes on the values

- **`scopes`**: `offline_access` is needed for a refresh token (section 1). Without it the session
  ends at access-token expiry with `Reauthenticate(SessionExpired)` and no token request.
- **`postLogoutRedirectUri`**: set it, and register it under Allowed Logout URLs. On Android under
  Auth Tab an `https` value must be a verified App Link too.
- **`endSessionEndpoint`**: leave unset when discovery advertises `end_session_endpoint`. Set it
  when the tenant's discovery does not, to the OIDC logout URL from Auth0's reference. Do not point
  it at `/v2/logout`.
- **`pushedAuthorization`**: default `WhenAdvertised`. If the tenant advertises PAR and rejects the
  public client, set `Never` (unless the metadata says PAR is required). Not tested.
- **`tokenBinding`**: default `Bearer`. Leave it.

## 3. What to expect

Everything in this table is what the documentation says or what the SDK does when a capability is
present or absent. None of it was observed.

| Capability | Auth0, per the documentation | What the SDK does |
|---|---|---|
| Refresh token | With `offline_access` requested and allowed (documented) | With it, a refresh token. Without it, no refresh token: `Authenticated` until the access token expires, then `Reauthenticate(SessionExpired)`, one warning. |
| Rotation and reuse | Opt-in per application; reuse invalidates the family (documented) | A rotated token is stored before the old one is forgotten. `invalid_grant` is `Reauthenticate(GrantRejected)`, never retried. |
| Revocation | `POST /oauth/revoke`, public client with `client_id` and `token` (documented) | If discovery advertises it, `logout()` revokes; otherwise `tokenRevoked = false`. |
| End-session | Advertised on tenants with the discovery setting on (documented) | `sessionEnded = true` only when the browser returns to `postLogoutRedirectUri` with the `state` the SDK sent. |
| UserInfo | `GET /userinfo` (documented in `spec/providers.md`, source [65]; not re-read here) | `userInfo()` works if advertised. |
| PAR | Enterprise plus add-on; tenant toggle off by default (documented) | Plain request unless advertised. |
| DPoP | Documented per `spec/providers.md`; advertisement not found | Bearer by default. `Dpop(required = true)` is `ProviderUnsupported("dpop")` unless `ES256` is advertised. |
| RFC 9207 `iss` on the redirect | Tenant setting "Include Issuer in Authorization Responses", default not found (`spec/providers.md`) | Checked when present; required only when discovery advertises it. |
| Step-up (RFC 9470) | Not found | No `StepUp` from Auth0 itself. |
| Rate limiting | 429 with `X-RateLimit-*` (`spec/providers.md`) | A generic transient failure within the retry budget. |

## 4. Known limits

- The legacy `/v2/logout` endpoint cannot be driven by `endSessionEndpoint` because its parameters are
  not RP-Initiated Logout's.
- An application on HS256 cannot work with this SDK. Switch it to RS256.
- PAR for public clients, DPoP, the `iss` setting, and the contents of the discovery document are
  not established. See section 5.
- Single-use refresh tokens with no overlap: a crash after Auth0 rotated the token and before the
  SDK stored the new one ends in `Reauthenticate(GrantRejected)`. A rotation overlap period softens
  this; it does not change the SDK's rule.
- A custom domain changes the issuer the ID token carries. Keep one domain per configuration.
- The SDK's `userInfo()`, revocation and sign-out against Auth0 were not run.

## 5. Where the documentation and `spec/providers.md` differ, and what could not be checked

| Point | `spec/providers.md` | The vendor pages read on 2026-10-30 | What this guide does |
|---|---|---|---|
| Where "Allow Offline Access" lives | On the application and the API | "Call your API" page: on the API, plus Refresh Token among the application's grant types. PKCE how-to: in Application Settings. Application settings page: no such setting | Says both, and tells you to check your dashboard. Not resolved. |
| Rotation overlap default | 0 (reported) | The "Configure Refresh Token Rotation" page gives units (seconds) but no default or maximum | Says the default is not stated. |
| Discovery `issuer` trailing slash | Slash (documented for tokens, reported for discovery) | Token samples and custom-domain page show a slash; no page shows the discovery document's `issuer` | Tells you to configure the slash; unchecked for discovery. |
| `end_session_endpoint` from 2023-11-14 | Reported | Documented: the discovery setting is on by default for tenants created on or after that date | Upgraded to documented. |
| OIDC logout path `/oidc/logout` | Unverified, from memory | Not stated on the pages read | Does not state the path. |
| Discovery contents (`code_challenge_methods_supported` listing `plain`, algorithm lists, DPoP member) | From a search digest, conflicts with the `/authorize` reference | The `/authorize` reference says `S256` only and "Auth0 only supports this method"; the discovery page shows no sample | Follows the reference. Discovery was not read. |
| PAR for public clients | Reported unsupported | The PAR page does not say | Says not stated; `Never` as the fallback. |
| `tokenEndpointAuthMethod` for a public client | Whether a secret is allowed: not found | Revocation reference: must be `none` for a public client to omit the secret | Recommends `none`. |

Not checked at all: that a Native application accepts the Auth0-style callbacks with this SDK; that
Auth0's App Links verification works with the Auth Tab leg; that Universal Link callbacks need only the
`webcredentials` association; any behaviour of `/userinfo`, `/oauth/revoke` or the logout endpoint
against the SDK; and everything under "What to expect".

## 6. How this was verified

It was not run. No Auth0 tenant was used, and the conformance suite has no Auth0 profile (its
providers are Keycloak and Ory Hydra). Every provider-side step above was checked against the
vendor pages below and the results are in the tables; "documented" there means Auth0's page says it,
not that the SDK worked against it. A run against a real tenant is the "hosted providers on demand"
item of `conformance/README.md` and has not happened. The confidence markers are
[`spec/providers.md`](../../spec/providers.md)'s, not B4's: nothing is "verified, B4" for Auth0.

## Sources

All read on 2026-10-30.

The pages were read through a fetch tool that summarises long pages (Microsoft Learn pages came back
as full text). Where a guide says "documented" for one of these pages it means the summary stated it;
recheck exact setting names on the page or in the dashboard before relying on them.

- Authorization Code Flow with PKCE (concept):
  <https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-pkce>
- Add Login Using the Authorization Code Flow with PKCE (parameters):
  <https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-pkce/add-login-using-the-authorization-code-flow-with-pkce>
- Authorize Application with PKCE (API reference):
  <https://auth0.com/docs/api/authentication/authorization-code-flow-with-pkce/authorize-with-pkce>
- Call Your API Using the Authorization Code Flow (refresh tokens, audience):
  <https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow/call-your-api-using-the-authorization-code-flow>
- Refresh Token Rotation:
  <https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation>
- Configure Refresh Token Rotation:
  <https://auth0.com/docs/secure/tokens/refresh-tokens/configure-refresh-token-rotation>
- Configure Refresh Token Expiration:
  <https://auth0.com/docs/secure/tokens/refresh-tokens/configure-refresh-token-expiration>
- Application Settings:
  <https://auth0.com/docs/get-started/applications/application-settings>
- Configure Applications with OIDC Discovery:
  <https://auth0.com/docs/get-started/applications/configure-applications-with-oidc-discovery>
- Access token profiles (issuer samples):
  <https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles>
- Multiple custom domains, SDK configuration (issuer with a custom domain):
  <https://auth0.com/docs/customize/custom-domains/multiple-custom-domains/sdk-configuration>
- Log Users Out of Auth0 (OIDC logout):
  <https://auth0.com/docs/authenticate/login/logout/log-users-out-of-auth0>
- Redirect Users After Logout (`/v2/logout`):
  <https://auth0.com/docs/authenticate/login/logout/redirect-users-after-logout>
- Revoke Refresh Token (API reference):
  <https://auth0.com/docs/api/authentication/revoke-refresh-token/revoke-refresh-token>
- Configure PAR:
  <https://auth0.com/docs/get-started/applications/configure-par>
- Android quickstart (callback URL forms): <https://auth0.com/docs/quickstart/native/android/interactive>
- iOS quickstart (callback URL forms, Universal Links):
  <https://auth0.com/docs/quickstart/native/ios-swift/interactive>
- This repository: [`spec/providers.md`](../../spec/providers.md) (matrix, sections 3 and 5),
  [`spec/oauth-sdk-api.md`](../../spec/oauth-sdk-api.md).
