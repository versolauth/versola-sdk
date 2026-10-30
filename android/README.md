# Android

The Android SDKs of this repository: the generic `OAuthClient` (module `:oauth`, package
`versola.oauth`) and the `Versola` facade (module `:sdk`, package `versola.sdk`), over a shared
protocol core. Documentation: the SDK documentation will be hosted at <https://docs.versola.kz>;
until then this README, [`spec/oauth-sdk-api.md`](../spec/oauth-sdk-api.md) and the KDoc are the
source.

## Status and installation

Nothing is published: no Maven Central artefact and no release tag. The intended coordinates, from
version 0.1.0, are `kz.versola:oauth-android` for the generic facade and
`kz.versola:versola-android` for the Versola facade
([ADR 0001](../docs/adr/0001-generic-sdk-naming-and-layering.md)). Publishing is configured and
the release workflows are dormant: eight artefacts will be published under `kz.versola` (the table
below), and [`docs/releasing.md`](../docs/releasing.md) is the maintainer's runbook. The repository
is private.

To use it today, include this repository's `android/` build in yours as a composite build and
substitute the artefact with the project. This is the block the Flutter example uses
(`flutter/versola_oauth/example/android/settings.gradle.kts`); adjust the path to where the
checkout lives:

```kotlin
// settings.gradle.kts of the app
includeBuild("../versola-sdk/android") {
    dependencySubstitution {
        substitute(module("kz.versola:oauth-android")).using(project(":oauth"))
    }
}
```

```kotlin
// build.gradle.kts of the app module
dependencies {
    implementation("kz.versola:oauth-android:0.1.0")
}
```

An included build cannot load a second version of the Android Gradle Plugin or the Kotlin plugin,
so the app must use the versions that `android/build.gradle.kts` declares. Drop the `includeBuild`
block once the artefact is on Maven Central.

## Modules

| Module | Package | Role | Artefact (from 0.1.0) |
|---|---|---|---|
| `:oauth` | `versola.oauth` | The generic `OAuthClient` facade | `kz.versola:oauth-android` |
| `:sdk` | `versola.sdk` | The `Versola` facade for the Versola server | `kz.versola:versola-android` |
| `:oauth-core` | `versola.oauth.core` | The protocol engine: discovery, PKCE, token client, ID-token validation, session coordinator, errors. Plain JVM, no `android.*` import | `kz.versola:oauth-core` (JAR), pulled in by the facades |
| `:core` | `versola.sdk.core` | What is Versola-specific: the edge back channel | `kz.versola:versola-core-android`, pulled in by `:sdk` |
| `:dpop` | `versola.sdk.dpop` | Hardware-backed DPoP key and proofs | `kz.versola:dpop-android`, pulled in by the facades |
| `:storage` | `versola.sdk.storage` | Keystore-wrapped credential and pending-request stores | `kz.versola:storage-android`, pulled in by the facades |
| `:browser` | `versola.sdk.browser` | Auth Tab, Custom Tabs and the redirect activity | `kz.versola:browser-android`, pulled in by the facades; `:oauth` exposes it (see below) |
| `:okhttp` | `versola.sdk.okhttp` | The authenticated OkHttp interceptor | `kz.versola:okhttp-android`, pulled in by the facades |
| `:conformance-android`, `:conformance-oauth` | | Test drivers against a staged server or a provider container | Nothing is published |
| `:samples:oauth` | | A minified sample app over the generic facade | Nothing is published |

The dependency modules are separate artefacts because a facade's POM names them: a Gradle project
dependency becomes a Maven dependency, so an app that adds `kz.versola:oauth-android` receives the
rest transitively. `:oauth` declares `:oauth-core`, `:okhttp`, `:browser` and `:dpop` as `api` dependencies because their types
are on its public surface (the state, the errors, the interceptor, `VersolaRedirectActivity` and
`KeyAttestation`), so an app that depends on `:oauth` sees them.

## Using the generic facade

Floors: `minSdk` 26, `compileSdk` 36. The libraries declare no `targetSdk`; that is the app's
decision.

```kotlin
import okhttp3.OkHttpClient
import okhttp3.Request
import versola.oauth.LoginOptions
import versola.oauth.OAuthClient
import versola.oauth.OAuthConfiguration
import versola.oauth.core.SessionState
import versola.oauth.core.VersolaError

val oauth = OAuthClient.create(
    applicationContext,
    OAuthConfiguration(
        issuer = "https://id.example.com",
        clientId = "example-app",
        redirectUri = "https://app.example.com/oauth",
        postLogoutRedirectUri = "https://app.example.com/signed-out",
        scopes = setOf("openid", "profile", "offline_access"),
        protectedOrigins = setOf("https://api.example.com"),
    ),
)
```

`create` does no network I/O and no key generation. A second call with the same issuer and client
id returns the same instance; a different configuration for the same pair is refused with
`Configuration(InvalidConfiguration)`. `OAuthConfiguration` has no `clientSecret` parameter, on
purpose.

Observe the session, sign in, call an API and sign out:

```kotlin
lifecycleScope.launch {
    oauth.sessionState.collect { state ->      // the first emission is the restored state
        if (state == SessionState.Authenticated) showSignedIn()
    }
}

suspend fun signInAndCall() {
    try {
        oauth.login(LoginOptions(scopes = setOf("openid", "profile", "offline_access")))
        val request = Request.Builder().url("https://api.example.com/me").build()
        oauth.call(request).use { response -> handle(response.code) }
    } catch (e: VersolaError.StepUp) {
        oauth.stepUp(e)                         // then repeat the call
    }
}

suspend fun signOut() {
    val outcome = oauth.logout()               // never throws for a server-side failure
    // outcome.sessionEnded, outcome.tokenRevoked say which server-side steps worked
}
```

`login()` returns nothing; the session is observable through `sessionState`, and `claims` holds the
validated ID token's claims. The error type is `VersolaError` and its four categories are
`Recoverable`, `Reauthenticate`, `StepUp` and `Configuration`
([`spec/errors.md`](../spec/errors.md)). The rename to `OAuthError` is deferred.

### Redirect and browser

The browser leg is an Auth Tab where the device's Custom Tabs provider supports it, and a Custom
Tab otherwise (any browser as the last resort). An Auth Tab returns the redirect to the app that
opened it as an activity result and reports a dismissal as a result code. A web view cannot be
used: the browser contract takes a URI and nothing else.

The app declares its redirect URI by re-declaring `VersolaRedirectActivity` in its own manifest;
the manifest merger unions it with the library's declaration. For a verified App Link (from the KDoc
of `VersolaRedirectActivity`):

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
    </intent-filter>
</activity>
```

The host and path must match `redirectUri` and be the app's own verified App Link: serve
`/.well-known/assetlinks.json` for the app's package and signing certificate on that host. Under an
Auth Tab an `https` redirect URI that is not a verified App Link of the app makes the tab answer
with a verification failure, which surfaces as `Configuration(InvalidConfiguration)`. A private-use
scheme is accepted, with a logged warning on every `create()`, since any app can register the same
scheme. The same applies to `postLogoutRedirectUri` under an Auth Tab.

`LoginOptions(ephemeralBrowser = true)` asks for a session that shares nothing with the user's
browser. It is off by default because it breaks passkeys and single sign-on, and it is best effort:
where the provider's browser lacks support it is logged once and the session opens shared.

### Authenticated calls

`protectedOrigins` is the only set of origins that ever receives a token (`https` or `http` on a
loopback host, `scheme://host[:port]`, no path). `oauth.call(request)` and
`oauth.authenticatedClient()` use it, or pass a set per call. To install the session on an
`OkHttpClient` of your own:

```kotlin
val client = OkHttpClient.Builder()
    .addInterceptor(oauth.interceptor(setOf("https://api.example.com")))
    .build()
```

The interceptor is an application interceptor. It attaches the token only to the listed origins,
lets every other request through untouched, refreshes once and replays once on a 401, retries once
on a DPoP nonce challenge, and turns an RFC 9470 challenge into `StepUp`. Because an interceptor
may only raise an `IOException`, errors arrive from your own client as `VersolaHttpException`; its
`error` property is the `VersolaError`. `oauth.call` unwraps it. `authenticatedClient()` also
switches redirects off, so a `Location` from a protected origin cannot repeat the request, token
included, at another origin; if you use `interceptor` on your own client, do the same.

`oauth.accessToken().value` is the escape hatch for HTTP stacks that are not OkHttp. A token handed
to app code is one the app can log.

DPoP is opt-in with `tokenBinding = TokenBinding.Dpop()` (from `versola.oauth.core`), and applies
when the provider advertises `ES256`; `keyAttestation()` reports the Keystore tier the key reached
(`StrongBox`, `TrustedEnvironment` or `Software`). Under `Dpop(requireHardware = true)` a device
that cannot honour it gets a `Configuration` error instead of a downgrade.

### R8 and ProGuard

The SDK needs no consumer keep rules. `android/samples/oauth` builds a release variant with R8
(`isMinifyEnabled = true`, the stock `proguard-android-optimize.txt`) and an intentionally empty
`proguard-rules.pro`; serialization is reflection-free. A missing-class warning from R8 is a bug
in the SDK, not a reason to add rules in your app.

## The Versola facade

`:sdk` is `Versola.configure(...)`, with the edge back channel and DPoP by default. Its example is
in the [root README](../README.md#the-versola-facade); its sources and KDoc are in `android/sdk`.
It shares `:oauth-core` with the generic facade and is not held to the generic API.

## Building

Gradle 9.8.2 through the wrapper (never a system Gradle). Build with JDK 21: Robolectric's
android-all image for API 36 needs it, and a different default JDK breaks the build in ways that
look like plugin errors. The bytecode is Java 17 for consumers, set per module. Set `JAVA_HOME` and
`ANDROID_HOME` explicitly, and install the platform once (`platforms;android-36`,
`build-tools;36.0.0`); [`develop.md`](../develop.md) has the commands.

```bash
cd android
./gradlew assemble test lint apiCheck
```

That is what the `android.yml` workflow runs. `apiCheck` compares every module's public signatures
with the committed dumps in `android/<module>/api/`; after an intended public change, run
`./gradlew apiDump` and commit the result, and never edit a `.api` file by hand. Every module uses
`explicitApi()`.

## The sample app

`android/samples/oauth` is a minimal app over `OAuthClient` that signs in, calls a protected
resource and signs out. How to build the minified release, point it at a provider and run its smoke
test on an emulator is in [`samples/oauth/README.md`](samples/oauth/README.md).

## Tests

| Tier | Command or place | Proves |
|---|---|---|
| Unit | `./gradlew test` (JUnit, Robolectric, MockWebServer) | A rule, against stubs |
| Device | `./gradlew :storage:connectedDebugAndroidTest :dpop:connectedDebugAndroidTest`, needs an emulator | The real Keystore, key tiers, GCM wrapping |
| Conformance | `:conformance-oauth` against Keycloak or Hydra in Docker; `:conformance-android` against a staged Versola stack | The wiring against a real provider; the browser leg is an HTTP conversation, not an Auth Tab |

The exact emulator, `adb reverse` and provider-container commands are in
[`develop.md`](../develop.md), and what the conformance tier does not prove is in
[`conformance/README.md`](../conformance/README.md).
