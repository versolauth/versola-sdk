pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "versola-android"

// Order matches the dependency direction: core has no internal dependents,
// dpop/storage/browser depend only on core, okhttp depends on core and dpop,
// and sdk sits on top of all of them.
// See #1 §4 for why DPoP and storage are separate modules from the transport.
// The protocol core: discovery, PKCE, the token client, the session coordinator, the error
// taxonomy. Plain JVM, no Versola vocabulary (ADR 0001). Every other module depends on it.
include(":oauth-core")
// What is Versola-specific: the edge back channel and its native endpoints.
include(":core")
include(":dpop")
include(":storage")
include(":browser")
include(":okhttp")
// The facade module. Added in #5 rather than #4 because the entry point in #1 §1 has to see
// the browser and the store at once, and neither may depend on the other. It is also the
// module the single published artifact (io.versola:versola-android) maps to.
include(":sdk")
// The generic facade (issue #46, spec/oauth-sdk-api.md): OAuthClient over the same protocol
// core, for any conforming provider. Published as io.versola:oauth-android.
include(":oauth")
// The conformance driver (#15): instrumented tests only, driving the SDK against a staged
// auth + central + edge from an emulator. Nothing is published from it.
include(":conformance-android")
// A minimal app over the generic facade, minifyEnabled: R8 over the SDK is the proof that it
// needs no consumer keep rules (architecture review F9). Nothing is published from it.
include(":samples:oauth")
// The generic facade's conformance driver (#46, B4): Robolectric unit tests that drive OAuthClient
// against a real OpenID Provider in Docker (conformance/providers/) through a rewriting proxy, for
// the scenarios tagged `facade: [oauth]`. Skipped unless OAUTH_CONFORMANCE_ISSUER is set, so the
// build job's `test` stays a unit run. Nothing is published from it.
include(":conformance-oauth")
// The browser-leg device tier (develop.md): a debug-only host app over the generic facade, and the
// instrumentation package that drives it and Chrome with UI Automator against a Keycloak
// container. Separate packages so a test can kill the app's process (scenario 12) and keep
// running. Skipped without the provider environment; nothing is published from either.
include(":conformance-browser-app")
include(":conformance-browser")
