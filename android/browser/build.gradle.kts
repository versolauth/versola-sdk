// System browser launch: Auth Tab where the browser supports it, Chrome Custom Tabs with a
// fallback chain to the default browser otherwise. Embedded WebView is deliberately
// unreachable from this module's public API — see #1 §4 and #5's scope note on why.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlinx.binary-compatibility-validator")
}

android {
    namespace = "versola.sdk.browser"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
        // No targetSdk on a library module: AGP requires libraries with a
        // targetSdk value to match consumers' compileSdk, which only tightens
        // things pointlessly here. Target 36 (#1 SS4) is the app's decision.
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.isIncludeAndroidResources = true
    }
}

kotlin {
    explicitApi()
}

dependencies {
    api(project(":oauth-core"))
    implementation("androidx.browser:browser:1.10.0")
    // Auth Tab (androidx.browser 1.9+) answers through the activity-result API, so the SDK's
    // trampoline activity must be a ComponentActivity. androidx.activity is already on the
    // runtime classpath as browser's own dependency, at this same version; declaring it is
    // what puts it on the compile classpath. Apache-2.0, AndroidX.
    implementation("androidx.activity:activity:1.9.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    // Custom Tabs launch, the redirect activity and the foreground-return detector are all
    // framework interactions; Robolectric runs them in a plain JVM test rather than needing
    // an emulator, which CI does not have.
    testImplementation("org.robolectric:robolectric:4.17")
    testImplementation("androidx.test:core:1.7.0")
}

apiValidation {
    // Wiring behind the opt-in marker is not public API: keep it out of the dump so that
    // apiCheck holds this module to the surface an app can actually use (architecture
    // review F6).
    nonPublicMarkers.add("versola.oauth.core.VersolaInternalApi")
}
