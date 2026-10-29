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
// module the single published artifact (kz.versola:versola-android) maps to.
include(":sdk")
// The generic facade (issue #46, spec/oauth-sdk-api.md): OAuthClient over the same protocol
// core, for any conforming provider. Published as kz.versola:oauth-android.
include(":oauth")
// The conformance driver (#15): instrumented tests only, driving the SDK against a staged
// auth + central + edge from an emulator. Nothing is published from it.
include(":conformance-android")
