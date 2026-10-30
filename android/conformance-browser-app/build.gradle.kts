// The host app of the browser-leg device tier (develop.md, "The browser leg on an emulator"): a
// debug-only app over the generic facade whose screen is a log of what the SDK did, so that
// :conformance-browser, a separate instrumentation package, can drive it and Chrome with UI
// Automator and read the outcome back off the screen. A separate package because the tests
// kill this app's process (scenario 12), which would take an in-process instrumentation with it.
// Nothing is published from it.
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "versola.conformance.browser.app"
    compileSdk = 37

    defaultConfig {
        applicationId = "versola.conformance.browser.app"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "0.1"

        buildConfigField("String", "CLIENT_ID", "\"conformance-device\"")
        // A private-use scheme, since a verified App Link needs a host this machine does not
        // control. Registered with the provider in conformance/providers/keycloak/realm.json.
        buildConfigField("String", "REDIRECT_URI", "\"com.example.versola.devicetier://app/oauth\"")
        buildConfigField("String", "POST_LOGOUT_REDIRECT_URI", "\"com.example.versola.devicetier://app/signed-out\"")
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        // The test wiring that forces the Custom Tabs leg (the SDK picks Auth Tab on its own).
        optIn.add("versola.oauth.core.VersolaInternalApi")
    }
}

dependencies {
    implementation(project(":oauth"))
    implementation(project(":browser"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
}
