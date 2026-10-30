# Provider guides

How to point the generic `OAuthClient` of this SDK (Kotlin, Swift, Dart) at an OpenID Provider other
than Versola: what to create on the provider side, what to put in `OAuthConfiguration`, what to
expect back, and what was and was not verified. This is the integrator's view of
[`spec/providers.md`](../../spec/providers.md), which stays the source of truth: where a guide and
that file differ, the file wins and the guide is the bug.

The guides cover the generic facade (`OAuthClient`, issue
<https://github.com/versolauth/versola-sdk/issues/46>). The `Versola` facade, which is built for the
Versola server, is not described here.

Snippets in these guides use the real parameter names of the three public APIs and were checked
against the declarations by reading the source. They were not compiled as part of writing these
pages. Hosts are `example.com`, client ids are placeholders, and nothing here contains a secret:
the SDK has no client secret to configure.

## The guides

| Provider | Guide | Confidence |
|---|---|---|
| Keycloak 26.4 | [keycloak.md](keycloak.md) | Tested in CI against a container |
| Ory Hydra v26.2.0 (self-hosted, open source image) | [ory-hydra.md](ory-hydra.md) | Tested in CI against a container |
| Auth0 | [auth0.md](auth0.md) | Documented, not tested against a real tenant |
| Microsoft Entra ID | [entra-id.md](entra-id.md) | Documented, not tested against a real tenant |

"Tested in CI" means the Android driver `android/conformance-oauth` runs scenarios 24 to 32 of
[`spec/conformance/`](../../spec/conformance/) against the provider's container from
[`conformance/providers/`](../../conformance/providers/) in the `providers` job of
`.github/workflows/conformance.yml`. The iOS driver and the Flutter-bridge drivers run the same
scenarios against the same containers on a developer machine only; they have no CI job
([`conformance/README.md`](../../conformance/README.md), section "Providers"). A container run does
not exercise Custom Tabs or Auth Tab, App Link or Universal Link delivery, or a real Keystore or
Keychain: the browser leg is the provider's login conversation driven over HTTP. Those belong to
the device tier.

"Documented, not tested" means a maintainer read the vendor's official documentation and wrote the
setup from it, and nothing has run against a real tenant. Each of those guides names the points
where the vendor's pages and `spec/providers.md` say different things.

## How the confidence markers work

`spec/providers.md` marks every cell of its capability matrix with one of these words. The guides
reuse them.

| Marker | Meaning |
|---|---|
| documented | Stated by the vendor's official documentation; the page is in the guide's Sources. |
| reported | Taken from a search digest or a fetch summary of official documentation, to be rechecked against the page itself. |
| unverified | From memory, or from a non-official source such as a forum thread. |
| not found | Looked for in the official documentation and absent. It does not mean the feature is absent. |
| verified, B4 | Observed against the real container by the conformance suite (milestone B4 of issue 46). Overrides every other marker. |

The guides add two phrases of their own. "Read from the live document" means a public discovery
document was fetched and read on the date given; it says what the provider announces, not that the
SDK ran against it, and because the fetch tool returns a summary it carries the marker reported.
"Derived from the SDK source" means the behaviour follows from reading the code
or the spec in this repository and has no conformance scenario of its own.

## The minimum contract

This is section 1 of [`spec/providers.md`](../../spec/providers.md) in plain words. A provider works
with the generic facade when it offers all of the following.

- **Discovery, or explicit endpoints.** A document at `{issuer}/.well-known/openid-configuration`
  whose `issuer` member equals the issuer you configured. One trailing slash on either side is
  ignored for that comparison. Without discovery you give `ProviderEndpoints` instead, and then you
  cannot also give `issuer`.
- **Authorization code flow with PKCE `S256` for a public client.** The client has no secret and
  the token request carries only `client_id`. The SDK always sends `S256`.
- **`response_type=code`** with `state` echoed on the redirect.
- **An asymmetrically signed ID token** (`RS256`, `PS256`, `ES256`, `ES384`, `ES512`, `RS384`,
  `RS512`, `PS384` or `PS512`) with its keys at `jwks_uri`. `none` and HMAC algorithms are refused.
- **An `iss` claim in the ID token equal to the discovered issuer**, byte for byte.

Everything else is optional and the SDK adapts to what discovery says. A provider that issues no
refresh token gives a session that ends with `Reauthenticate(SessionExpired)` when the access token
expires. One without a revocation endpoint gets sign-out that skips revocation and reports
`tokenRevoked = false`. One without an `end_session_endpoint` gets sign-out that wipes locally and
reports `sessionEnded = false`, unless you supply the URL with `endSessionEndpoint`. No UserInfo
endpoint makes `userInfo()` fail with `Configuration(ProviderUnsupported)`. No PAR means the plain
authorization request. No DPoP means bearer tokens.

A provider is unsupported when it requires a client secret from a native app, accepts only `plain`
PKCE or none, signs ID tokens only with HMAC, or announces an issuer that does not match its
discovery document. A templated issuer (Microsoft Entra's `common` endpoint) is such a mismatch.

## Redirect setup shared by every provider

What you register with the provider is provider-specific and is in each guide. What the app does
with the redirect is the same everywhere.

The SDK accepts three kinds of `redirectUri`: an `https` URL (a verified App Link or Universal Link,
preferred), a loopback URL, or a private-use scheme such as `com.example.app:/oauth`. A private-use
scheme works but the SDK logs a warning on every `create()`, because any app on the device can
register the same scheme. Cleartext `http` to a non-loopback host is refused. On iOS a cleartext
loopback URL is refused too, because `ASWebAuthenticationSession` cannot receive it.

### Android: App Links

Register the redirect URI with the provider exactly as it appears in `OAuthConfiguration.redirectUri`.
Then re-declare the SDK's redirect activity in the app manifest with an intent filter for it. The
SDK's own manifest declares the activity without a filter; the manifest merger unions the two. This
is the snippet from the KDoc of `VersolaRedirectActivity`, with the sign-out path added.

```xml
<activity
    android:name="versola.sdk.browser.VersolaRedirectActivity"
    android:exported="true"
    tools:node="merge">
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="https" android:host="app.example.com" android:path="/oauth" />
        <data android:scheme="https" android:host="app.example.com" android:path="/signed-out" />
    </intent-filter>
</activity>
```

The host must be one you control, and it must serve Digital Asset Links
(`https://app.example.com/.well-known/assetlinks.json`) for the app's package name and signing
certificate. The SDK opens an Auth Tab where the device's browser supports it and a Custom Tab
otherwise. Under an Auth Tab the browser checks that the redirect host belongs to your app; if it
cannot, `login()` fails with `Configuration(InvalidConfiguration)` and the cause is the
`assetlinks.json`, not the provider. The same applies to `postLogoutRedirectUri` when it is an
`https` URL: without a verified host the tab closes unverified and `logout()` reports
`sessionEnded = false`.

For a private-use scheme the intent filter carries `android:scheme="com.example.app"` instead.

The module is `kz.versola:oauth-android`. Nothing is published yet, so the build setup is in
`develop.md`, not here. `minSdk` is 26.

### iOS: Universal Links

The SDK starts an `ASWebAuthenticationSession` with an `https(host:path:)` callback for an `https`
redirect URI, which needs iOS 17.4 (the package's platform floor). The SDK source does not state
what the app's entitlements must contain for that callback. AppAuth-iOS, which uses the same system
API, documents that an HTTPS redirect needs an Associated Domains entitlement for the redirect host
and an `apple-app-site-association` file on that host listing the app under `webcredentials`, and
that an `applinks` association alone is not enough (README of AppAuth-iOS, read 2026-10-30; see
[../migrating-from-appauth.md](../migrating-from-appauth.md)). Auth0's iOS quickstart says the same
about `webcredentials:` for its Universal Link callbacks. Treat that as the requirement and check
it on a device: the device tier has not covered it for this SDK.

The window the sheet is presented from is yours to supply, once, when the client is created. A
minimal anchor for a single-window app, illustrative:

```swift
import AuthenticationServices
import UIKit

@MainActor
func appKeyWindow() -> ASPresentationAnchor {
    UIApplication.shared.connectedScenes
        .compactMap { $0 as? UIWindowScene }
        .flatMap(\.windows)
        .first(where: \.isKeyWindow) ?? ASPresentationAnchor()
}
```

A Universal Link that reaches the app while it is cold goes to
`client.handleRedirect(url)`, which returns `true` when the URL was the redirect the SDK was
waiting for. In SwiftUI:

```swift
.onOpenURL { url in
    Task { _ = await client.handleRedirect(url) }
}
```

### Flutter

The plugin is a binding over the native SDKs and has no redirect handling of its own: do the
Android manifest work above in the app's `android/` project, and the iOS entitlement work in the
Runner target. On iOS the plugin presents the sheet from the key window of the foreground scene;
an app with its own window handling sets `VersolaOAuthPlugin.presentationAnchor` before the first
`create`. Dart has no authenticated HTTP client: `accessToken()` is the one call that hands you a
credential.

## Reading a failure

Errors are four categories (`spec/errors.md`) and the category tells the app what to do:
`Recoverable` (offer a retry), `Reauthenticate` (send the user to `login()`), `StepUp` (call
`stepUp`) and `Configuration` (a deployment mistake; fix it, do not catch it in production). Most
first-run provider problems arrive as `Configuration`:

| You see | Usually means |
|---|---|
| `DiscoveryIssuerMismatch` | The configured `issuer` is not what the provider's discovery document announces. Copy the `issuer` member exactly. |
| `InvalidConfiguration` after the browser closes (Android) | The redirect host is not a verified App Link of this app. |
| `IdTokenRejected(reason)` | The ID token failed validation: algorithm, `iss`, `aud`, `exp`, `nonce` or signature. Never fixed by retrying. |
| `ProviderUnsupported(capability)` | The configuration asks for something the provider does not advertise (`dpop`, `par`, `S256`) or `userInfo()` has no endpoint. |
| `AuthorizationRejected` | The provider refused a pushed authorization request (PAR), for example an unregistered redirect URI. |

An unregistered redirect URI on a plain (non-PAR) request shows an error page in the browser that
the SDK cannot see: it looks the same as the user closing the tab (`spec/errors.md`, authorization
endpoint). Check the registered string first.
