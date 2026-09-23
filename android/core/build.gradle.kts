// Protocol core: state machine, error taxonomy, discovery, token/authorization requests.
// No Versola-specific URLs or routing — see #4's licence decision on why this must stay
// generic enough to work against any OIDC provider.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
    id("org.jetbrains.kotlinx.binary-compatibility-validator")
}

android {
    namespace = "kz.versola.sdk.core"
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
}

kotlin {
    explicitApi()
}

dependencies {
    // api, not implementation: SessionState is exposed as a Flow (spec/state-machine.md,
    // "Observability"), so the coroutines types are part of this module's ABI.
    api("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")

    // Discovery needs an HTTP client and a JSON parser (#5).
    //
    // OkHttp rather than HttpURLConnection: the :okhttp module already pins it, and one
    // HTTP stack across the SDK means one place where timeouts, TLS and proxy behaviour
    // are decided. Same 5.4.0 pin and the same reason for it as :okhttp.
    //
    // kotlinx-serialization rather than the framework's org.json: org.json is stubbed in
    // plain JVM unit tests and throws "not mocked", which would force Robolectric onto
    // every discovery test. Reflection-free, so it also survives R8 without keep rules.
    // api, not implementation: HttpDiscoveryClient takes an OkHttpClient, so the type is on
    // this module's ABI and a consumer configuring their own client needs to see it.
    api("com.squareup.okhttp3:okhttp:5.4.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testImplementation("com.squareup.okhttp3:mockwebserver3:5.4.0")
}
