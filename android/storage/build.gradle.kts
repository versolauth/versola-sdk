// Encrypted persistence: refresh token, raw ID token, pending authorization request,
// DPoP key reference. See spec/state-machine.md's persistence summary for what lives
// here versus memory-only.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlinx.binary-compatibility-validator")
}

android {
    namespace = "versola.sdk.storage"
    compileSdk = 37

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

    testOptions {
        unitTests.isIncludeAndroidResources = true
        unitTests.all {
            // Robolectric's API 36 image on JDK 21: ApplicationSharedMemory reaches the raw
            // file descriptor through jdk.internal.access, which the module system hides from
            // the unnamed module unless exported here.
            it.jvmArgs("--add-exports", "java.base/jdk.internal.access=ALL-UNNAMED")
        }
    }
}

kotlin {
    compilerOptions {
        // Java 17 bytecode for consumers, whatever JDK runs the build (develop.md: 21).
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
    explicitApi()
}

dependencies {
    api(project(":oauth-core"))
    // androidx.security:security-crypto was listed here by #4's scaffolding and is dropped
    // in #5: #7 rules EncryptedSharedPreferences out (deprecated at 1.1.0, no further
    // releases, main-thread violations and keyset corruption on some OEMs). The Keystore
    // AES-256-GCM key below is managed directly, with no Tink keyset to corrupt.
    //
    // DataStore is what #7 names in its place, and it is what the credential file needs that
    // the pending slot did not: several fields, written from several places, on one
    // consistent view. implementation, not api — no DataStore type is on this module's ABI,
    // so a consumer never has to know it is there.
    implementation("androidx.datastore:datastore:1.3.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    // The Keystore itself has no JVM implementation, but KeyGenParameterSpec is a plain
    // framework class: Robolectric is enough to assert what the storage key is asked for,
    // per API level, without the emulator CI does not have. Same version as :browser.
    testImplementation("org.robolectric:robolectric:4.17")

    // Instrumented only. Same coroutines-test pin as the unit tests; the runner and the
    // AndroidX JUnit extension are what `connectedDebugAndroidTest` needs to find and run them.
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
}

apiValidation {
    // Wiring behind the opt-in marker is not public API: keep it out of the dump so that
    // apiCheck holds this module to the surface an app can actually use (architecture
    // review F6).
    nonPublicMarkers.add("versola.oauth.core.VersolaInternalApi")
}

// Published (gradle/publishing.gradle.kts): the coordinates are io.versola:storage-android.
extra["publishing.artifactId"] = "storage-android"
extra["publishing.name"] = "Versola secure storage (Android)"
extra["publishing.description"] = "Keystore-wrapped storage of the refresh token, ID token and pending authorization request for the Versola OAuth SDKs on Android."
apply(from = rootProject.file("gradle/publishing.gradle.kts"))
