// The conformance driver (#15): an instrumented test suite that drives the SDK, assembled
// through Versola.configure(), against a real staged auth + central + edge, and asserts the
// scenarios under spec/conformance/. Nothing here ships: the module has no main sources worth
// publishing and is excluded from the release artefact.
//
// The stack is reached at the loopback addresses auth was configured with (`gen-env.scala`'s
// `local` target): `adb reverse tcp:9001 tcp:9001` (and 9003, 9005) makes the emulator's
// localhost the host's, so the issuer the SDK validates is the issuer auth announces.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
}

android {
    namespace = "versola.sdk.conformance"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    androidTestImplementation(project(":sdk"))
    androidTestImplementation("com.squareup.okhttp3:okhttp:5.4.0")
    // The upstream a registered edge resource proxies to runs on the device and is reached
    // from the host through `adb forward`; MockWebServer is that upstream.
    androidTestImplementation("com.squareup.okhttp3:mockwebserver3:5.4.0")
    androidTestImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.12.0")
    androidTestImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
}

kotlin {
    compilerOptions {
        // Java 17 bytecode for consumers, whatever JDK runs the build (develop.md: 21).
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}
