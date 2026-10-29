// DPoP proof generation: hardware-backed EC P-256 keys (Secure Enclave/StrongBox
// equivalent), proof signing, nonce handling. See #1 §4 — the possession-factor key,
// never gated on user presence by default.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlinx.binary-compatibility-validator")
}

android {
    namespace = "kz.versola.sdk.dpop"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
        // The instrumented tests under src/androidTest run against a real Android Keystore
        // on an emulator (#30, #37): the tier negotiation, the authentication window and the
        // exception mapping have no JVM equivalent, and Robolectric emulates none of them.
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
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
    api(project(":core"))

    // Claims are built as a JsonObject rather than concatenated, so escaping is the library's
    // problem. Same artifact and pin as :core; the serialization compiler plugin is not
    // applied because nothing here is @Serializable.
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.12.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.12.0")
    // Test-only, never shipped. #6 requires proofs be verified byte-equivalent against the
    // server repo's DpopProver, and the honest way to do that from here is to verify them
    // with the same library the server verifies with — a hand-rolled test verifier would
    // share this module's own assumptions and prove much less.
    testImplementation("com.nimbusds:nimbus-jose-jwt:10.10")

    // Instrumented only. Same coroutines-test pin as the unit tests; the runner and the
    // AndroidX JUnit extension are what `connectedDebugAndroidTest` needs to find and run them.
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.12.0")
}
