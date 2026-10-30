# Providers

How the generic facade of [`oauth-sdk-api.md`](oauth-sdk-api.md) meets real OpenID Providers: what it
assumes of one, how it adapts through discovered metadata, and where the documented limits are.
Section numbers below ("API 7") refer to `oauth-sdk-api.md`. Error names are those of
[`errors.md`](errors.md); the retry rules are [`retry-policy.md`](retry-policy.md).

The rule (API design rule 8): a provider-specific behaviour is a **capability row in this
document**, driven by the discovered metadata or by a configuration value, and is never a branch on
an issuer string or a product name in code. Where a provider needs something the metadata cannot
say, this document tells the integrator what to configure or what to do in app code.

Every cell of the matrix carries a confidence marker in parentheses:

- **documented**: stated by the vendor's official documentation; the link is in the Sources list.
- **reported**: taken from a search digest or a fetch summary of official documentation, to be
  rechecked against the page itself.
- **unverified**: from memory, or from a non-official source such as a forum thread.
- **not found**: looked for in the official documentation and absent. This does not mean the
  feature is absent.

Every cell is overturned by what the conformance run observes against the real provider: scenario
24 and the rest of those tagged `facade: [oauth]` (see the Facades section of
[`conformance/README.md`](conformance/README.md)). B4 of issue #46 replaces the markers with
"tested on <date>".

The research behind the matrix was done on 2026-10-29. The Versola column is taken from
[`server-dependencies.md`](server-dependencies.md) (checked against `versolauth/versola` at
`d6203f93`, 2026-10-11) and the README of this repository, not from the vendor-doc research.

## 1. The minimum contract

A provider works with the generic facade when it offers all of the following:

- A discovery document at the well-known path of its issuer (OpenID Connect Discovery 1.0, RFC
  8414), or explicit endpoints given through `ProviderEndpoints` (API 3). Discovery's `issuer` must
  equal the configured one, a single trailing slash ignored.
- The authorization code flow with PKCE `S256` (RFC 7636, RFC 8252) for a **public client**:
  `token_endpoint_auth_method` `none`, `client_id` in the token request body, no secret anywhere.
- `response_type=code` with the `state` parameter echoed on the redirect (RFC 6749 section 4.1.2).
- An ID token signed with an asymmetric algorithm from the closed set of API 11 (`RS256`,
  `PS256`, `ES256`, `ES384`, `ES512`, `RS384`, `RS512`, `PS384`, `PS512`), with keys at
  `jwks_uri`. `none` and HMAC algorithms are refused.
- An `iss` claim in the ID token equal to the discovered issuer, byte for byte (OIDC Core 3.1.3.7).

Everything else is optional and discovered. The SDK's behaviour when it is absent:

| Optional capability | Standard | When absent |
|---|---|---|
| Refresh token | RFC 6749 section 5.1 | Session lives as long as the access token, then `Reauthenticate(SessionExpired)`, no token request (API 8, `state-machine.md`, scenario 31) |
| Revocation endpoint | RFC 7009 | Sign-out skips revocation, `tokenRevoked = false` (API 12) |
| `end_session_endpoint` | RP-Initiated Logout 1.0 | Sign-out revokes and wipes locally, `sessionEnded = false`; the `endSessionEndpoint` override can supply one (API 3, 12, scenario 30) |
| UserInfo endpoint | OIDC Core 5.3 | `userInfo()` is `Configuration(ProviderUnsupported)` (API 5) |
| Pushed authorization requests | RFC 9126 | Plain request under `WhenAdvertised`; `ProviderUnsupported("par")` under `Required` (API 7, scenario 29) |
| DPoP with `ES256` | RFC 9449 | Bearer with one warning under `Dpop(required = false)`; `ProviderUnsupported("dpop")` when required (API 9, scenario 07) |
| `iss` in the authorization response | RFC 9207 | Not required; checked when the provider sends it (API 2) |
| Step-up challenge on a resource server | RFC 9470 | No `StepUp` is ever raised by that provider's resources (API 10) |

A provider is **unsupported** by the generic facade when it:

- requires a client secret (or any client authentication) from a native app, so no public client
  can be registered;
- accepts only `plain` PKCE, or does not support PKCE at all;
- signs ID tokens only with HMAC (HS256), which a public client cannot verify;
- announces an issuer that does not match its discovery document, without a documented exception.
  The single documented exception is the one trailing slash (Auth0). A templated issuer is not an
  exception (Microsoft Entra's `common` endpoint, section 3).

## 2. Capability matrix

`[n]` points to the Sources list at the end. In the Versola column the source is
`server-dependencies.md` unless stated; Versola is a plain OIDC provider on a `standard`-profile
tenant here, and "documented" there means documented in that file.

| Capability | Keycloak 26.x | Ory Hydra (self-hosted and Ory Network) | Auth0 | Microsoft Entra ID | Okta | Amazon Cognito | Versola |
|---|---|---|---|---|---|---|---|
| Discovery URL shape | `{base}/realms/{realm}/.well-known/openid-configuration`; issuer `{base}/realms/{realm}` (documented [1]) | `{issuer}/.well-known/openid-configuration`; Ory Network `{slug}.projects.oryapis.com`; custom-domain shape not found (documented [23]) | `https://{domain}/.well-known/openid-configuration`; issuer `https://{domain}/` with trailing slash (documented [46]; slash reported [47]) | `https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration` (documented [73]) | Org AS `https://{org}/.well-known/openid-configuration`; custom AS under `/oauth2/{asId}/` (documented [93]) | `{issuer}/.well-known/openid-configuration`; OAuth endpoints on the separate user-pool domain (documented [112]) | `{issuer}/.well-known/openid-configuration` (documented, issue #1 section 2.1); issuer `https://id.versola.io` in the README example |
| Public client + PKCE | Yes, client authentication off (documented [2, 3]) | Yes, `token_endpoint_auth_method` `none` (documented [24, 25]) | Yes, application type Native (documented [49, 50]) | Yes, mobile and desktop platform (documented [75, 76, 77]) | Yes, Native app, client auth None requires PKCE (reported [95]) | Yes, app client without secret (documented [113]) | Standard tenant only; `fapi2` tenant refuses public clients at `/token`, `/revoke`, `/par`, `/introspect` (documented) |
| S256 enforced | Per-client method setting and `pkce-enforcer` executor; option list from 21.0.2 (documented [2, 4]; list reported [5]) | `S256` only; enforcement is server-wide config, default not found (documented [24, 27]) | `S256` only, challenge required (reported [52]); a discovery sample also lists `plain` (reported [53], conflicts) | `plain` and `S256` both accepted, not enforced for native (documented [75]) | "Always S256" (reported [95]); `plain` rejected: not found | `S256` only, PKCE itself optional (documented [114, 115]) | Mandatory, `S256`: `AuthorizeRequestParser` refuses a request without a code challenge (documented, issue #1 section 2) |
| Client secret for native apps | Not required (documented [3]) | Not required; CLI default is `client_secret_basic`, set `none` explicitly (documented [26]) | Not needed for Native; whether one is allowed: not found (documented [50]) | Must not be used by public clients (documented [75]); `none` absent from discovery's auth methods | Auth None is the default; whether a secret is allowed: not found (reported [95]) | Client must have no secret; fixed at creation (documented [113]) | None for a public client on a `standard` tenant; `fapi2` takes confidential clients only (documented) |
| RFC 9207 `iss` | Supported since 23.0; per-client opt-out reported; `authorization_response_iss_parameter_supported: true` and `iss` on the redirect (verified, B4) | Not advertised by v26.2.0 OSS: no `authorization_response_iss_parameter_supported`, no `iss` on the redirect (verified, B4) | Tenant setting "Include Issuer in Authorization Responses"; default not found (documented [54]) | Not found | Not found | Not found | Always on the redirect, success and error; discovery advertises `authorization_response_iss_parameter_supported: true` (documented) |
| PAR | Supported, feature `par:v1` on by default; `…/protocol/openid-connect/ext/par/request` advertised, public client accepted (verified, B4) | Not advertised by v26.2.0 OSS (verified, B4) | `/oauth/par`; tenant toggle off by default, Enterprise plan plus add-on; public apps reportedly unsupported (documented [56, 57]; limitation reported) | Not found | `/par` exists and discovery lists it; use by public clients not found (reported [98]) | Not found | `/par` exists and is advertised; required for `fapi2`; per-client `requirePushedAuthorizationRequests`; discovery says `request_uri_parameter_supported: false` (documented) |
| DPoP | Supported since 26.4, per-client "Require DPoP bound tokens"; `dpop_signing_alg_values_supported` advertised (ES/RS/PS 256–512, EdDSA) (verified, B4; the DPoP flow is driven end to end by scenario 33) | Not advertised by v26.2.0 OSS (verified, B4) | Supported for public clients, server nonce required; algorithms beyond ES256 examples not found; plan not confirmed (documented [58]) | Not found at the v2.0 token endpoint; only `Bearer` (documented [75]); MSAL PoP needs a broker (reported [80]) | Per-app setting, nonce flow; ES256 in the reported algorithm list; native clients not found (reported [99, 100]) | Not found | `ES256` and `PS256` advertised; client needs `dpopBoundAccessTokens = true` (and `accessTokenTtl >= 3600s`); nonce when the tenant sets `requireDpopNonce` (default false) (documented) |
| Refresh token for public clients, and scope | Returned by default from most flows; `offline_access` yields an offline token (documented [3, 15]) | `offline_access` (or `offline`) and the consent app must grant it; issued for `openid profile offline_access`, not for `openid profile` (verified, B4; documented [24, 32]) | `offline_access` plus "Allow Offline Access" on the application and the API (documented [55]) | `offline_access` required (documented [82]) | `offline_access` on `/authorize`; mobile apps default to persistent tokens (reported [101]) | Always issued for the code grant; `offline_access` has no effect (documented [114, 116]) | Scope needed: not found. Expiry fixed at the code exchange, default 180 days, never extended (documented) |
| Refresh rotation and reuse detection | Realm "Revoke Refresh Token" (`revokeRefreshToken`, `refreshTokenMaxReuse`); default not stated; with it on, reuse is 400 `invalid_grant` and revokes the session (verified, B4) | Always single-use; reuse revokes the consent chain; grace period default 0 s, at most 5 min (documented [24, 31, 32]) | Opt-in per app; reuse invalidates the family; overlap window default 0 (reported [60, 62]) | New token each use, old one not revoked; no reuse detection documented (documented [83]) | `ROTATE` or `STATIC`, grace 30 s (0 to 60); reuse invalidates the latest token (reported [101]) | Optional per app client, grace up to 60 s; reuse detection after grace not found (documented [114, 116]) | DPoP: renewed in place, same token echoed, no rotation. Bearer: rotation, replay revokes the family; `Idempotency-Key` honoured (documented; scenarios 09, 10, 11) |
| Revocation endpoint (RFC 7009) | `/revoke`; a public client sends `client_id` only (verified, B4) | `/oauth2/revoke`; a public client sends `client_id` only, 200, and the revoked refresh token is then 400 `invalid_grant` (verified, B4) | `/oauth/revoke` with `client_id` and `token` (documented [51]) | No RFC 7009 endpoint documented (documented [83]; Q&A unverified [85]) | `/revoke`, public clients send `client_id` only (reported [103]) | `/oauth2/revoke`, `client_id` required for public clients, refresh tokens only (documented [118]) | `/revoke` exists and reads no proof; public-client call on a `standard` tenant not found (documented) |
| RP-initiated logout and its parameters | `.../openid-connect/logout`; with `id_token_hint` and a registered `post_logout_redirect_uri` a direct 302 carrying `state`, no confirmation page (verified, B4) | `{public}/oauth2/sessions/logout`; with `id_token_hint`, a registered `post_logout_redirect_uri` and `state`: redirect to the logout UI app, which confirms, then 302 to the post-logout URI with `state` (verified, B4; documented [33, 34]) | `end_session_endpoint` advertised for tenants created from 2023-11-14; legacy `/v2/logout` with `returnTo`; `/oidc/logout` path unverified (reported [63, 64]) | `/{tenant}/oauth2/v2.0/logout`; `post_logout_redirect_uri`, `logout_hint`; `id_token_hint` not in the documented table (documented [73]) | `/oauth2/v1/logout`; `id_token_hint` required; discovery member not found (reported [100, 102]) | Own `/logout` with `client_id` and `logout_uri`; no `id_token_hint`; discovery member not found (documented [117]) | `/logout` renders a signed-out page with `post_logout_redirect_uri` and `state`; tenant-level URI list; expired `id_token_hint` silently ignored; discovery member not found (documented) |
| UserInfo | Present, bearer (documented [1, 12]) | Advertised `/userinfo` (documented [28]) | `GET /userinfo`, accepts DPoP (documented [65]) | `https://graph.microsoft.com/oidc/userinfo`; token may not be a JWT (documented [86]) | `/oauth2/v1/userinfo` or per custom AS (reported [100]) | `/oauth2/userInfo`, token must come from the token endpoint (documented [120]) | `/userinfo` exists; answers 401 with `WWW-Authenticate: DPoP error="use_dpop_nonce"` (documented) |
| ID-token algorithms | RS256 by default; discovery lists RS/PS/ES 256–512, EdDSA and HS256/384/512 (verified, B4) | `RS256` only in `id_token_signing_alg_values_supported` (verified, B4) | App setting HS256 or RS256 (documented [50]); sample lists HS256, RS256, PS256 (reported [53]) | Asymmetric, "such as RS256" (documented [74]); RS256-only list from a Q&A thread (unverified) | RS256 in token headers; discovery list not found (reported [100]) | RS256 only (documented [121]) | Not found |
| Redirect URI rules | Exact match, wildcard only at the end; loopback IP literal advised; custom scheme and loopback port not found (documented [1, 2, 19]) | Exact, pre-registered; no wildcards; custom schemes allowed; loopback port rules reported (documented [25]; loopback reported [35]) | Allowed Callback URLs, `*` subdomain wildcard discouraged; custom scheme and https forms in the iOS guide (documented [50, 67]) | `https` except loopback (port ignored, `[::1]` unsupported); plain custom scheme: conflicting docs (documented [76, 77]) | Exact match; reverse-domain custom scheme in the mobile guide (reported [96]) | `https` except `http://localhost`; app schemes supported; wildcards not found (documented [115]) | `fapi2` edge-fronted client: `https` only, no private-use scheme, no loopback (documented); `standard` tenant rules: not found |
| RFC 9470 step-up and `acr_values` | `acr_values` and `claims` with LoA mapping; RFC 9470 not found (documented [10, 17, 20]) | Not found | `acr_values` with the multi-factor URI; RFC 9470 not found (documented [68]) | Claims challenge with `insufficient_claims`, not RFC 9470; `acr_values` not found (documented [90]) | `acr_values` `urn:okta:loa:*`; RFC 9470 not found (documented [106]) | `acr_values` and `max_age` in managed login on Essentials or Plus; RFC 9470 not found (documented [122]) | Edge answers 401 `insufficient_user_authentication`; unknown `acr_values` dropped, not refused (documented, `errors.md`) |
| Rate limiting at the token endpoint | Brute-force detection only (password, OTP), off by default; no 429 documented (documented [21]) | Self-hosted: none in config. Ory Network: 429 with `x-ratelimit-reset`, no `Retry-After` mentioned (documented [27, 39]) | 429 with `X-RateLimit-*`; `Retry-After` only in custom policies (documented [71]; reported [72]) | Limits unpublished; 429 with `Retry-After` (reported [91, 92]) | 429 with `X-Rate-Limit-*`; `Retry-After` not mentioned (documented [105]) | Per-account quotas; 429 and `Retry-After` not found (documented [123]) | Nothing emits 429 or `Retry-After` as of 2026-10-11; versola#310 open (documented) |
| Issuer quirks | `{base}/realms/{realm}`; none documented (documented [1]) | Must match exactly, trailing slashes included: `urls.self.issuer` is announced verbatim (`http://host:port/` in the CI config) and the ID token repeats it; the SDK tolerates the one trailing slash at discovery and holds the ID token to the discovered value (verified, B4; documented [23]) | Trailing slash; with a custom domain `iss` follows the domain used (reported [47, 48]) | `common` and `organizations` return a `{tenantid}` template (documented [73]) | Org AS and custom AS have different issuers (documented [93]) | Two issuer forms, `cognito-idp` and `issuer-cognito-idp` (documented [112]) | No trailing slash in the README example; PAR works while `request_uri_parameter_supported` is false (documented) |

## 3. What the SDK does with each difference

| Difference | Providers | SDK behaviour | Integrator action |
|---|---|---|---|
| Issuer with a trailing slash; discovery issuer equality | Auth0 (`https://{domain}/`); Hydra requires an exact match | The discovery `issuer` must equal the configured one, a single trailing slash ignored for that comparison only; `DiscoveryIssuerMismatch` otherwise, with no per-provider exception. The ID token's `iss` and the authorization response's `iss` (RFC 9207 section 2.4) are then compared to the discovered value byte for byte (API 3, 11) | Configure the issuer as the provider's metadata announces it. Auth0 with a custom domain: `iss` follows the domain used (reported), so keep one domain per configuration |
| Templated issuer in metadata | Entra `common` and `organizations`, whose metadata carries `{tenantid}` | Unsupported for issuer equality: `DiscoveryIssuerMismatch` (API 3) | Use a tenant-specific authority, `https://login.microsoftonline.com/{tenant GUID or domain}/v2.0`. A multi-tenant app that must accept any tenant is out of scope |
| Scope needed for a refresh token | `offline_access`: Auth0, Entra, Okta, Hydra. Keycloak: refresh token by default (verified, B4), and `offline_access` there asks for an offline token (realm role needed, different lifetime). Cognito: always issued, `offline_access` has no effect | The SDK never adds `offline_access`; it warns once, at the first login, when the scopes lack it and `scopes_supported` lists it, that a refresh token *may* not be issued (Keycloak issues one regardless) (API 8, 15) | Put `offline_access` in `scopes` for Auth0 (also enable Allow Offline Access on the app and the API), Entra, Okta, Hydra (the consent app must also grant it). Do not add it for Keycloak unless an offline token is wanted; harmless for Cognito |
| No refresh token issued | Any provider configured without one (for example Entra or Auth0 without the scope above) | `Authenticated` until the access token expires, then `Reauthenticate(SessionExpired)`; no token request, nothing retried, one warning (API 8, `errors.md`, `state-machine.md`, scenario 31) | Fix the provider side, or accept that the user signs in again when the access token expires |
| No `end_session_endpoint`, or a non-standard logout URL | Cognito: own `/logout` with `client_id` and `logout_uri`, no discovery member found. Auth0: legacy `/v2/logout`, with `end_session_endpoint` advertised by default only for tenants from 2023-11-14 (reported). Okta and Entra: path documented; Okta's discovery member not found, Entra's `id_token_hint` not in the documented parameters | A provider that advertises none gets revocation and the local wipe, `sessionEnded = false` (API 12, scenario 30). The `endSessionEndpoint` override replaces only the URL; the parameters stay those of RP-Initiated Logout 1.0 (API 3, 12) | Where the provider's logout URL takes the standard parameters, set `endSessionEndpoint`. Where its parameters are non-standard (Cognito's `logout_uri`), handle sign-out in app code after `logout()` has wiped locally; the SDK does not special-case it |
| No revocation endpoint | Entra (no RFC 7009 endpoint documented) | The revocation step is skipped, `tokenRevoked = false`; the end-session and wipe steps still run (API 12) | None available in the SDK. The refresh token stays valid server-side until it expires or the user's tokens are revoked by an admin or the user (documented per-user revocation) |
| Single-use refresh tokens | Hydra always; Auth0, Okta, Cognito when rotation is enabled; Keycloak when "Revoke Refresh Token" is on; Entra issues a new token on each use but does not revoke the old one | A rotated token is stored before the old one is forgotten; `invalid_grant` wipes the grant and is `Reauthenticate(GrantRejected)`, never retried, because a retry is a replay that some providers answer by revoking the whole family (API 8, `retry-policy.md`). The generic facade sends no `Idempotency-Key`, so a process killed after the provider rotated ends in `GrantRejected` (API 8) | Enable the provider's rotation grace window where one exists (Hydra up to 5 min, Okta 30 s default, Cognito up to 60 s, Auth0 overlap period); it softens a retry after a killed process, it does not change the SDK's rule |
| DPoP advertised or not | Keycloak 26.4+ (per-client requirement; advertisement member not found) and Versola (`ES256` and `PS256` advertised). Auth0 and Okta support DPoP per the docs, with no advertisement found; Hydra, Entra, Cognito: not found | Default is Bearer. `Dpop(required = false)` uses DPoP only when `ES256` is advertised, otherwise bearer with one warning; `Dpop(required = true)` is `ProviderUnsupported("dpop")` when it is not (API 9, scenario 07) | Opt in only when the resource servers verify DPoP. A provider that supports DPoP but does not advertise it stays on bearer; do not set the per-app "require DPoP" option there (not tested) |
| PAR advertised, `require_pushed_authorization_requests` | PAR: Keycloak, Okta, Versola (and `fapi2` tenants require it), Auth0 (tenant toggle, add-on). Not found: Hydra, Entra, Cognito | `WhenAdvertised` (default) pushes when advertised; `require_pushed_authorization_requests: true` is honoured even under `Never`; a rejection is `AuthorizationRejected` before the browser opens (API 7, scenario 29) | Auth0 and Okta public clients: PAR for public clients is reported unsupported (Auth0) or not found (Okta). If PAR is advertised and a public client is rejected, set `Never` unless the metadata requires it. Not tested |
| Redirect scheme rules | Entra: `https` except loopback on the web platform; the mobile platform offers custom URIs, and whether a plain custom scheme is accepted is unverified. Okta: reverse-domain custom scheme. Cognito: `https` except `http://localhost`, app schemes supported. Keycloak: exact match, `127.0.0.1` advised over `localhost`. Hydra: custom schemes allowed | The redirect URI is validated before any network call: `https`, loopback, or a private-use scheme with a warning on every `create()`; cleartext non-loopback `http` refused (API 3). Registration is the provider's | Prefer a verified `https` link where the provider allows it. Register the exact string (Keycloak, Hydra, Okta). Entra: register under the mobile and desktop platform and test the scheme before relying on it |
| Step-up challenges | RFC 9470: not found for any hosted provider or Keycloak or Hydra; Versola's edge emits it. Entra uses a claims challenge (`insufficient_claims`) | The authenticated client turns a 401 `insufficient_user_authentication` from a protected origin into `StepUp(acrValues, maxAge)`; other 401s are not step-ups (API 10, `errors.md`) | `acrValues` in `login()` works where the provider honours `acr_values` (Keycloak, Auth0, Okta, Cognito on Essentials or Plus, where lower plans silently ignore it); read `claims.acr` and check it yourself. Entra's claims challenge is not RFC 9470 and is out of scope: the app decodes it and may pass it as `extraParameters["claims"]` (API 6), which is not tested |
| Rate limits and `Retry-After` | 429 documented for Auth0 (`X-RateLimit-*`), Okta (`X-Rate-Limit-*`), Ory Network (`x-ratelimit-reset`), Entra (`Retry-After`, reported); not found for Keycloak and Cognito; none emitted by Versola | 429 and 503 with `Retry-After` (seconds or HTTP-date) are honoured in preference to the SDK's backoff and never shortened to fit the budget; a value that does not fit stops the operation and is surfaced as `Recoverable(Server)` with `retryAfter`, and no request goes to that origin until it has passed (`retry-policy.md`, scenarios 35 and 36). Without the header a 429 is retried under the budget like a 5xx. Providers that send only their own headers (`X-RateLimit-*`, `x-ratelimit-reset`) get the ordinary backoff | Nothing to configure. Do not raise the retry maxima to ride out a limit; they are hard bounds |
| Clock skew | All | No vendor documents a server tolerance for client-side JWT validation. `clockSkewTolerance` defaults to 60 s, maximum 5 minutes; this is the SDK's own choice (API 3, 11) | Raise it only for a device clock known to drift; guide figures of 2 to 5 minutes (Okta, reported) are examples, not a server contract |
| ID-token algorithm | Auth0 lets the app pick HS256 or RS256; Cognito RS256 only; others RS256 or unspecified | Verification uses the closed asymmetric set and `id_token_signing_alg_values_supported` when advertised; HS256 is refused as `IdTokenRejected(Algorithm)` (API 11) | Set the Auth0 application to RS256 |
| `code_challenge_methods_supported` missing | Entra (regional documents reportedly missing it, Q&A, unverified) | The SDK always sends `S256`. `ProviderUnsupported("S256")` is raised only when the member is present and lacks `S256`; an absent member is treated as unknown, not as "no PKCE", because providers that omit it accept `S256` in practice (API 6, `errors.md`) | None; B4 tests it against Entra |
| OAuth endpoints on another host than the issuer | Cognito (user-pool domain); Entra's UserInfo is on Microsoft Graph | Follows discovered metadata; issuer equality concerns only the issuer (API 3). Whether Cognito's discovery document lists the domain-host endpoints was not read | Verify at B4 |

## 4. Running each provider in CI

Issue #46 decision 8 puts Keycloak and Ory Hydra in the CI matrix; the hosted providers need a
tenant and credentials and run on demand. All of it feeds scenario 24 and the rest tagged
`facade: [oauth]`.

### Keycloak

Verified in B4 against `quay.io/keycloak/keycloak:26.4` from
`conformance/providers/keycloak/` (scenarios 24 to 33 green, `android/conformance-oauth`):

- Image pinned to `26.4`; `start-dev --import-realm` with `realm.json` mounted at
  `/opt/keycloak/data/import`, `KC_BOOTSTRAP_ADMIN_USERNAME` / `_PASSWORD` for the first admin,
  `KC_HEALTH_ENABLED=true` for `/health/ready` on port 9000 (the compose health check). Import
  runs at start and leaves an existing realm alone (`down` before re-importing).
- Realm-import fields that work: `publicClient: true`, `standardFlowEnabled`, `redirectUris`,
  `attributes."pkce.code.challenge.method": "S256"`, `attributes."post.logout.redirect.uris"`,
  `attributes."use.refresh.tokens": "false"`, `attributes."access.token.lifespan"` and
  `attributes."dpop.bound.access.tokens": "true"` ("Require DPoP bound tokens", per client),
  realm `revokeRefreshToken: true` with `refreshTokenMaxReuse: 0`, `sslRequired: "none"`. There
  is no `openid` client scope to list (it is implicit; listing it logs a warning and is ignored).
- Live discovery: `authorization_response_iss_parameter_supported: true`,
  `pushed_authorization_request_endpoint` at `…/protocol/openid-connect/ext/par/request`,
  `require_pushed_authorization_requests: false`, `code_challenge_methods_supported: [plain, S256]`,
  `dpop_signing_alg_values_supported` with ES/RS/PS 256–512 and EdDSA,
  `id_token_signing_alg_values_supported` including HS256/384/512 (the SDK's closed set still
  refuses HS), `end_session_endpoint`, `revocation_endpoint`, `userinfo_endpoint`. The JWKS carries
  an RSA-OAEP `use: enc` key next to the RS256 signing key; ID tokens are RS256 by default.
- Development mode derives the issuer, every endpoint and the login form's action from the
  request's `Host`, which is what lets the driver's proxy stand in front of it unannounced.
- Browser leg: the authorization request answers 200 with the login page (302 to it under PAR);
  the page's `kc-form-login` form posts `username`, `password` and an empty `credentialId`; a
  correct password answers 302 to the redirect URI with `code`, `state`, `iss` and
  `session_state`. Session cookies are set `Secure` even over plain HTTP (a browser sends them to
  loopback; the driver's jar does too). No consent page for a first-party client; no required
  action for a user imported with `emailVerified: true` and a non-temporary password.
- A public client calls `/revoke` with `token`, `token_type_hint` and `client_id` only; an
  invalid token is 200 with an `invalid_token` body (RFC 7009). Refresh reuse after rotation is
  400 `invalid_grant` "Maximum allowed refresh token reuse exceeded" and revokes the session.
- RP-initiated logout with `id_token_hint`, a registered `post_logout_redirect_uri` and `state`
  answers 302 to the post-logout URI with `state`, no confirmation page. Without `id_token_hint`
  a confirmation page is shown (not driven).
- A refresh token is issued without `offline_access` (the realm's default); the SDK's
  "advertises offline_access and the scopes omit it" warning therefore says *may* not be issued.
- PAR with an unregistered `redirect_uri` is 400 `invalid_request` "Invalid parameter:
  redirect_uri", before any browser.
- The token response carries no `Date` header, so the SDK's server-time skew path does not
  engage against Keycloak; the ID token's `iat`/`exp` are checked against the device clock.
- DPoP (scenario 33, client `conformance-app-dpop` with `dpop.bound.access.tokens`): the token
  request needs a proof, and without one (a Bearer-configured SDK) is 400 with no token. A proof
  from the right key gives `token_type: DPoP` and a JWT access token (RS256, `iss` the request's
  origin, `exp`) whose `cnf.jkt` is the proof key's RFC 7638 thumbprint; `dpop_jkt` on the PAR
  request is accepted. The refresh token is bound to the key too: a refresh grant with no proof,
  or with a proof from another key, is 400, and neither spends the token (the SDK's refresh with
  the right key still works afterwards). Observed on the success path (PAR, token, JWKS): Keycloak
  26.4 sent no `DPoP-Nonce` header, and a proof carrying a nonce it never issued (the harness
  answers the first token request with `use_dpop_nonce` and the retry goes to Keycloak) is accepted,
  so Keycloak neither demands nor checks one; the SDK's retry is proven against the harness's
  challenge and the resource server's (`DpopResourceServer`), not against a provider that issues
  nonces. The authorization request's `dpop_jkt` is enforced: a token request whose proof is from
  another key is 400 `invalid_request` "DPoP Proof public key thumbprint does not match dpop_jkt".
  UserInfo needs a proof for a bound token (no proof, Bearer, or another key's proof is 401; the
  SDK's key is 200). Revocation (`/revoke`) is taken without a proof for a DPoP-bound refresh
  token (200), and the token is refused with `invalid_grant` afterwards; the SDK sends none, as
  documented. Keycloak's non-browser logout with a refresh token, which the documentation says
  needs a proof, is not what the SDK calls (it uses `/revoke` and the browser's end-session).

### Ory Hydra

Verified in B4 against `oryd/hydra:v26.2.0` with `oryd/hydra-login-consent-node:v26.2.0` from
`conformance/providers/hydra/` (scenarios 24 to 33, `android/conformance-oauth`: 25 of 27 tests
green for 24 to 32, the two PAR tests skipped because no PAR endpoint is advertised; the fourteen tests
of scenario 33 are skipped because no `dpop_signing_alg_values_supported` is advertised):

- Stack as the quickstart's: `hydra serve all --dev` (plain HTTP, non-secure cookies) with
  `DSN=memory` (no migration step, nothing survives a restart), the admin API on 4445 for the
  client import only, and the consent app on 3000 with `HYDRA_ADMIN_URL=http://hydra:4445`.
- Hydra builds its issuer and every URL it hands the browser from `urls.self.issuer` and
  `urls.self.public`, never from the request. The driver's proxy therefore listens on a fixed
  port (14444) that `hydra.yml` names, and the login and consent redirects go through it.
- Pre-provisioning: `hydra import oauth2-client clients.json --endpoint http://hydra:4445`, the
  file being a JSON **array** of clients (one object is refused). Fields that work:
  `client_id`, `token_endpoint_auth_method: none`, `grant_types`, `response_types`, `scope`,
  `redirect_uris`, `post_logout_redirect_uris`, `skip_consent`, and
  `authorization_code_grant_access_token_lifespan: "10s"` per client (scenario 31).
  `oauth2.pkce.enforced_for_public_clients: true` is set; the SDK always sends `S256`.
- Live discovery: `issuer` verbatim from the config with its trailing slash,
  `code_challenge_methods_supported: [plain, S256]`, `id_token_signing_alg_values_supported:
  [RS256]`, `scopes_supported: [offline_access, offline, openid]` (the clients' `profile` and
  `email` are not listed), `end_session_endpoint`, `revocation_endpoint`, `userinfo_endpoint`,
  `jwks_uri` under `/.well-known/jwks.json`; no `pushed_authorization_request_endpoint`, no
  `authorization_response_iss_parameter_supported`, no `dpop_signing_alg_values_supported`.
- Browser leg: `/oauth2/auth` 302s to the consent app's `/login?login_challenge=…`, a form
  with `_csrf` (paired with the app's `_csrf` cookie), `challenge`, `email`, `password`,
  `submit`; the app accepts `foo@bar.com` / `foobar` only, then 302s to hydra, which 302s to
  `/consent?consent_challenge=…`, a form with `_csrf`, `challenge`, one `grant_scope` checkbox
  per requested scope and `submit=Allow access`; then hydra 302s to the client with `code`,
  `state` and `scope`, no `iss`. About ten hops in all.
- A refresh token is issued when `offline_access` is requested and granted; a client whose
  scope lacks it gets none. Access tokens are opaque by default and UserInfo accepts them.
- Revocation by a public client with `client_id` only is accepted; the revoked refresh token
  then answers 400 `invalid_grant` at `/oauth2/token`.
- RP-initiated logout with `id_token_hint`, a registered `post_logout_redirect_uri` and
  `state` 302s to the logout UI app (`/logout?logout_challenge=…`, a form with `_csrf` and
  `challenge`; anything but `submit=No` confirms), then back through hydra to the post-logout
  URI with `state`.
- The token response carries no `Date` header either, so the SDK's server-time skew path is
  exercised only through the proxy's header.

### Auth0, Microsoft Entra ID, Okta, Amazon Cognito

A tenant (or user pool) and credentials are needed; the run is on demand and never part of the
default matrix. What a maintainer registers, one line each:

- **Auth0**: an application of type Native, Allowed Callback URLs and Allowed Logout URLs for the
  harness redirect, "Allow Offline Access" on the application and on the API, RS256 as the ID-token
  algorithm, and an API whose identifier is sent as the `audience` extra parameter.
- **Microsoft Entra ID**: an app registration with the "Mobile and desktop applications" platform
  and the harness redirect URI, `offline_access` in the scopes, and a tenant-specific authority as
  the issuer (never `common`).
- **Okta**: an OIDC application of type Native with the Authorization Code and Refresh Token grants,
  the harness URI as Sign-in redirect and Sign-out redirect, client authentication None, and a
  custom authorization server if `acr_values` or longer lifetimes are wanted.
- **Amazon Cognito**: a user pool with a domain, an app client without a secret, only the
  authorization-code grant enabled, the harness URI as callback and sign-out URL, and the `openid`
  scope. Managed login is needed for `acr_values`, with the Essentials or Plus plan.

### Versola

The staged stack already used by `conformance.yml`: `auth` and `edge` on a `standard`-profile
tenant, the public client of scenarios 01 to 20, driven by the harness's `HttpLoginBrowser`. The
generic facade runs against it in `Bearer` mode (scenario 24).

## 5. Not verified

This list is what B4 must close. Each item is one line.

### Keycloak

What B4 closed is in section 4. Still open:

- "Exclude Issuer From Authentication Response": from search summaries of a Red Hat 26.4 guide.
- Default of "Revoke Refresh Token" on a realm that does not set it (the CI realm sets it).
- Custom-scheme and loopback port rules for redirect URIs; RFC 9470; clock skew tolerance; token
  endpoint rate limiting and 429; token endpoint idempotency.
- `kc_action` semantics not read.
- The site's `server_admin` page was read in lossy chunks and the raw `.adoc` files are from branch
  `main`, so an absence there is weaker than usual.
- 24.0.0 "PKCE enabled by default" and the 23.0.2, 24.0.3, 21.1.2 redirect-URI changes: release-note
  headings only.

### Ory Hydra and Ory Network

What B4 closed is in section 4 (OSS `oryd/hydra:v26.2.0`). Still open:

- Whether the Enterprise build adds RFC 9207, PAR or DPoP (absence is verified for OSS only).
- The default of `oauth2.pkce.enforced` (the CI config sets `enforced_for_public_clients`); that a
  request without PKCE is refused was not driven.
- Logout with an expired `id_token_hint`; refresh-token reuse detection and its grace period.
- Loopback dynamic-port behaviour in current OSS builds (issue 1732 closed in 2020; the v26.3.17 note
  is from the Enterprise changelog; the `localhost` versus IP-literal limit is a search summary).
- `acr_values` and `acr` handling (issues 1032 and 3637 seen only in search results).
- Clock-skew behaviour (a search summary only; the 5-minute `iat` tolerance of the jwt-bearer grant
  was a search summary of a page not read).
- Ory Network custom-domain discovery URL; per-bucket 429 limits for `/oauth2/token`; whether
  Ory Network sends `Retry-After` (the docs do not mention it).
- The Kratos option for a real identity flow: not researched.
- Enterprise-changelog items apply to that build, not necessarily to `oryd/hydra`.

### Auth0

- The literal `/oidc/logout` path: not on the pages read (memory).
- Discovery contents (`plain` in `code_challenge_methods_supported`, HS256, RS256, PS256, no DPoP
  member): from a search digest of a sample whose page returned 404; conflicts with the `/authorize`
  reference (`S256` only).
- PAR "public applications not currently supported": from a search digest; the Configure PAR page
  has no limitations list.
- DPoP: the full algorithm list and the plan requirement; `dpop_signing_alg_values_supported` in
  discovery.
- Default of "Include Issuer in Authorization Responses", and whether
  `authorization_response_iss_parameter_supported` appears in discovery.
- Quotes marked "per fetch summary" (Auth0 and Okta pages): wording may not be verbatim.

### Microsoft Entra ID

- No RFC 7009 endpoint and the Graph `revokeSignInSessions` workaround: from Q&A threads, not an
  official reference. Same for `id_token_signing_alg_values_supported` equal to RS256 and the
  regional `code_challenge_methods_supported` inconsistency.
- Whether a plain custom scheme (not `msauth://...`) is accepted as a v2.0 redirect URI: the
  reply-url page says `https` (loopback excepted), the mobile and desktop platform offers custom
  URIs. Needs a live test.
- Standard RFC 9449 DPoP at the v2.0 token endpoint, PAR, RFC 9207 `iss` and token endpoint
  idempotency: not found. MSAL PoP wording ("aims to support") is from a search digest.
- Throttling specifics (`Retry-After: 60`, 5 s first retry, MSAL one-minute hold): search digests;
  the token endpoint's real limits are unpublished.

### Okta

- The pages for `/par`, `/revoke`, `/authorize`, `/logout` and discovery metadata are JavaScript
  rendered and came back empty; PAR, revocation, logout, the DPoP algorithm list and
  `dpop_signing_alg_values_supported` come from search digests.
- Refresh-token default lifetime has two statements (default Unlimited but expiring after seven days
  unused, versus 90 days hard-coded on the org AS); the reuse-detection scope ("family") is not
  described; DPoP for native clients and at `/userinfo`, PAR for public clients, and the discovery
  members `end_session_endpoint` and `id_token_signing_alg_values_supported` were not found.
- Clock-skew figures (5 min, 2 min) are from a search digest of a blog and an older .NET guide.

### Amazon Cognito

- HTTP 429 and `Retry-After` on the OAuth endpoints; reuse detection and family revocation of a
  rotated refresh token; `end_session_endpoint` in discovery; wildcard callback URLs; DPoP, PAR and
  RFC 9207: not found.
- Step-up (`acr_values`) is documented as "rolling out gradually", so a pool may not have it.

### All providers

- Clock-skew tolerance: no vendor documents a server-side tolerance for client-side JWT validation;
  the figures in the research are SDK defaults or guide examples.

## Sources

1. <https://www.keycloak.org/securing-apps/oidc-layers>
2. <https://raw.githubusercontent.com/keycloak/keycloak/main/docs/documentation/server_admin/topics/clients/oidc/con-basic-settings.adoc>
3. <https://raw.githubusercontent.com/keycloak/keycloak/main/docs/documentation/server_admin/topics/sso-protocols/con-oidc-auth-flows.adoc>
4. <https://raw.githubusercontent.com/keycloak/keycloak/main/docs/documentation/server_admin/topics/clients/client-policies.adoc>
5. <https://www.keycloak.org/docs/21.0.2/server_admin/index.html>
6. <https://www.keycloak.org/docs/latest/upgrading/index.html>
7. <https://www.keycloak.org/securing-apps/specifications>
8. <https://www.keycloak.org/2023/11/keycloak-2300-released>
9. <https://docs.redhat.com/en/documentation/red_hat_build_of_keycloak/26.4/html/migration_guide/migrating-applications>
10. <https://www.keycloak.org/server/features>
11. <https://www.keycloak.org/docs-api/latest/javadocs/constant-values.html>
12. <https://www.keycloak.org/securing-apps/dpop>
13. <https://www.keycloak.org/docs/latest/release_notes/index.html>
14. <https://www.keycloak.org/2025/10/dpop-support-26-4>
15. <https://raw.githubusercontent.com/keycloak/keycloak/main/docs/documentation/server_admin/topics/sessions/offline.adoc>
16. <https://raw.githubusercontent.com/keycloak/keycloak/main/docs/documentation/server_admin/topics/sessions/timeouts.adoc>
17. <https://www.keycloak.org/docs/latest/server_admin/index.html>
18. <https://www.keycloak.org/2026/01/keycloak-2650-released>
19. <https://raw.githubusercontent.com/keycloak/keycloak/main/docs/documentation/server_admin/topics/threat/redirect.adoc>
20. <https://raw.githubusercontent.com/keycloak/keycloak/main/docs/documentation/server_admin/topics/clients/oidc/con-advanced-settings.adoc>
21. <https://raw.githubusercontent.com/keycloak/keycloak/main/docs/documentation/server_admin/topics/threat/brute-force.adoc>
22. <https://www.keycloak.org/server/containers>
23. <https://www.ory.com/docs/oauth2-oidc/wellknown-endpoint-discovery>
24. <https://www.ory.com/docs/oauth2-oidc/authorization-code-flow>
25. <https://www.ory.com/docs/hydra/guides/oauth2-clients>
26. <https://www.ory.com/docs/hydra/cli/hydra-create-oauth2-client>
27. <https://raw.githubusercontent.com/ory/hydra/master/spec/config.json>
28. <https://raw.githubusercontent.com/ory/hydra/master/spec/api.json>
29. <https://www.ory.com/docs/self-hosted/oel/oauth2/changelog>
30. <https://github.com/ory/hydra/discussions/3071>
31. <https://www.ory.com/docs/hydra/guides/graceful-token-refresh>
32. <https://www.ory.com/docs/hydra/debug>
33. <https://www.ory.com/docs/oauth2-oidc/oidc-logout>
34. <https://www.ory.com/docs/hydra/guides/logout>
35. <https://github.com/ory/hydra/issues/1732>
36. <https://www.ory.com/docs/hydra/concepts/login>
37. <https://github.com/ory/hydra/issues/3637>
38. <https://github.com/ory/fosite/issues/651>
39. <https://www.ory.com/docs/guides/rate-limits>
40. <https://www.ory.com/docs/hydra/guides/custom-ui-oauth2>
41. <https://api.github.com/repos/ory/hydra/releases>
42. <https://hub.docker.com/r/oryd/hydra>
43. <https://raw.githubusercontent.com/ory/hydra/master/quickstart.yml>
44. <https://raw.githubusercontent.com/ory/hydra/master/contrib/quickstart/5-min/hydra.yml>
45. <https://www.ory.com/docs/hydra/self-hosted/quickstart>
46. <https://auth0.com/docs/get-started/applications/configure-applications-with-oidc-discovery>
47. <https://auth0.com/docs/secure/tokens/access-tokens/access-token-profiles>
48. <https://auth0.com/docs/customize/custom-domains/multiple-custom-domains/sdk-configuration>
49. <https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-pkce>
50. <https://auth0.com/docs/get-started/applications/application-settings>
51. <https://auth0.com/docs/api/authentication/revoke-refresh-token/revoke-refresh-token>
52. <https://auth0.com/docs/api/authentication/authorization-code-flow-with-pkce/authorize-with-pkce>
53. <https://dev.auth0.com/docs/get-started/applications/configure-applications-with-oidc-discovery>
54. <https://auth0.com/ai/docs/mcp/guides/resource-param-compatibility-profile>
55. <https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow/call-your-api-using-the-authorization-code-flow>
56. <https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow/authorization-code-flow-with-par>
57. <https://auth0.com/docs/get-started/applications/configure-par>
58. <https://auth0.com/docs/secure/sender-constraining/demonstrating-proof-of-possession-dpop>
59. <https://auth0.com/docs/secure/sender-constraining/configure-sender-constraining>
60. <https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation>
61. <https://auth0.com/docs/secure/tokens/refresh-tokens/configure-refresh-token-expiration>
62. <https://auth0.com/docs/secure/tokens/refresh-tokens/configure-refresh-token-rotation>
63. <https://auth0.com/docs/authenticate/login/logout/log-users-out-of-auth0>
64. <https://auth0.com/docs/authenticate/login/logout/redirect-users-after-logout>
65. <https://auth0.com/docs/api/authentication/user-profile/get-user-info>
66. <https://auth0.com/docs/get-started/tenant-settings/signing-keys/rotate-signing-keys>
67. <https://auth0.com/docs/quickstart/native/ios-swift/interactive>
68. <https://auth0.com/docs/secure/multi-factor-authentication/step-up-authentication/configure-step-up-authentication-for-web-apps>
69. <https://auth0.com/docs/libraries/lock-swift/lock-swift-configuration-options>
70. <https://auth0.com/docs/authenticate/protocols/openid-connect-protocol>
71. <https://auth0.com/docs/troubleshoot/customer-support/operational-policies/rate-limit-policy>
72. <https://auth0.com/docs/troubleshoot/customer-support/operational-policies/rate-limit-policy/custom-rate-limit-policies>
73. <https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc>
74. <https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens>
75. <https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow>
76. <https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-redirect-uri>
77. <https://learn.microsoft.com/en-us/entra/identity-platform/reply-url>
78. <https://learn.microsoft.com/en-us/entra/identity-platform/msal-client-applications>
79. <https://learn.microsoft.com/en-us/answers/questions/5576031/oidc-discovery-metadata-inconsistent-across-region>
80. <https://learn.microsoft.com/en-us/entra/msal/dotnet/advanced/proof-of-possession-tokens>
81. <https://learn.microsoft.com/en-us/security/zero-trust/develop/user-authentication>
82. <https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc>
83. <https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens>
84. <https://learn.microsoft.com/en-us/entra/identity-platform/configurable-token-lifetimes>
85. <https://learn.microsoft.com/en-us/answers/questions/1426223/entraid-azuread-oidc-implementation-missing-revoca>
86. <https://learn.microsoft.com/en-us/entra/identity-platform/userinfo>
87. <https://learn.microsoft.com/en-us/entra/identity-platform/signing-key-rollover>
88. <https://learn.microsoft.com/en-us/entra/identity-platform/id-tokens>
89. <https://learn.microsoft.com/en-us/entra/msal/android/single-sign-on>
90. <https://learn.microsoft.com/en-us/entra/identity-platform/claims-challenge>
91. <https://learn.microsoft.com/en-us/entra/msal/dotnet/advanced/client-and-server-throttling>
92. <https://learn.microsoft.com/en-us/entra/architecture/resilience-client-app>
93. <https://developer.okta.com/docs/concepts/auth-servers/>
94. <https://developer.okta.com/docs/api/openapi/okta-oauth/guides/overview/>
95. <https://developer.okta.com/docs/guides/implement-grant-type/authcodepkce/main/>
96. <https://developer.okta.com/docs/guides/sign-into-mobile-app-redirect/main/>
97. <https://developer.okta.com/docs/api/openapi/okta-oauth/oauth/customas/authorizecustomas>
98. <https://developer.okta.com/docs/api/openapi/okta-oauth/oauth/customas/paroptionscustomas>
99. <https://developer.okta.com/docs/guides/dpop/oktaresourceserver/main/>
100. <https://developer.okta.com/docs/reference/api/oidc/index.html>
101. <https://developer.okta.com/docs/guides/refresh-tokens/main/>
102. <https://developer.okta.com/docs/api/openapi/okta-oauth/oauth/customas/logoutcustomas>
103. <https://developer.okta.com/docs/guides/revoke-tokens/main/>
104. <https://developer.okta.com/docs/guides/device-authorization-grant/main/>
105. <https://developer.okta.com/docs/reference/rate-limits/>
106. <https://developer.okta.com/docs/guides/step-up-authentication/main/>
107. <https://developer.okta.com/docs/guides/validate-id-tokens/main/>
108. <https://developer.okta.com/code/dotnet/jwt-validation/>
109. <https://developer.okta.com/docs/reference/rl2-monitor/>
110. <https://developer.okta.com/docs/guides/oie-upgrade-sign-in-widget/main/>
111. <https://developer.okta.com/docs/guides/session-cookie/main/>
112. <https://docs.aws.amazon.com/cognito/latest/developerguide/federation-endpoints.html>
113. <https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-client-apps.html>
114. <https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html>
115. <https://docs.aws.amazon.com/cognito/latest/developerguide/authorization-endpoint.html>
116. <https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-the-refresh-token.html>
117. <https://docs.aws.amazon.com/cognito/latest/developerguide/logout-endpoint.html>
118. <https://docs.aws.amazon.com/cognito/latest/developerguide/revocation-endpoint.html>
119. <https://docs.aws.amazon.com/cognito/latest/developerguide/token-revocation.html>
120. <https://docs.aws.amazon.com/cognito/latest/developerguide/userinfo-endpoint.html>
121. <https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html>
122. <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-step-up-authentication.html>
123. <https://docs.aws.amazon.com/cognito/latest/developerguide/quotas.html>
124. <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-define-resource-servers.html>
125. [`server-dependencies.md`](server-dependencies.md) and the README of this repository: the Versola column (no external URL)
