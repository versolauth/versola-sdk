// Encrypted persistence: refresh token, raw ID token, pending authorization request,
// DPoP key reference. See spec/state-machine.md's persistence summary for what lives
// here versus memory-only.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlinx.binary-compatibility-validator")
}

android {
    namespace = "kz.versola.sdk.storage"
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
    api(project(":core"))
    // androidx.security:security-crypto was listed here by #4's scaffolding and is dropped
    // in #5: #7 rules EncryptedSharedPreferences out (deprecated at 1.1.0, no further
    // releases, main-thread violations and keyset corruption on some OEMs). The Keystore
    // AES-256-GCM key below is managed directly, with no Tink keyset to corrupt.

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    // The Keystore itself has no JVM implementation, but KeyGenParameterSpec is a plain
    // framework class: Robolectric is enough to assert what the storage key is asked for,
    // per API level, without the emulator CI does not have. Same version as :browser.
    testImplementation("org.robolectric:robolectric:4.17")
}
