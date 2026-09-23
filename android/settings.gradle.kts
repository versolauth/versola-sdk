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
// dpop/storage/browser depend only on core, okhttp depends on core and dpop.
// See #1 §4 for why DPoP and storage are separate modules from the transport.
include(":core")
include(":dpop")
include(":storage")
include(":browser")
include(":okhttp")
