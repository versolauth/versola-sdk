// System browser launch: Chrome Custom Tabs with a fallback chain to the default
// browser. Embedded WebView is deliberately unreachable from this module's public API
// — see #1 §4 and #5's scope note on why.
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

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    // Custom Tabs launch, the redirect activity and the foreground-return detector are all
    // framework interactions; Robolectric runs them in a plain JVM test rather than needing
    // an emulator, which CI does not have.
    testImplementation("org.robolectric:robolectric:4.17")
    testImplementation("androidx.test:core:1.7.0")
}
