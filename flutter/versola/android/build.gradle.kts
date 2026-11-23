// The Android half of the versola plugin: glue over io.versola:versola-android, the Versola
// facade of this repository (android/sdk). The artefact is not published yet and has no
// publishing configuration; the example app resolves it from this checkout with a composite build
// (example/android/settings.gradle.kts), so the plugin is built against the SDK source it ships
// with.
group = "versola.sdk.flutter"
version = "0.3.1"

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "versola.sdk.flutter"
    compileSdk = 37 // the repository's libraries compile against 37 (OkHttp 5.5.1); a dependent must too

    defaultConfig {
        // The SDK's floor (android/sdk): Keystore-wrapped stores and Auth Tab need API 26.
        minSdk = 26
        // What an app must compile against, which is not compileSdk above (see android/dpop): the
        // glue links only Context and Log (API 1). The app's check also applies the SDK's
        // dependencies' values (OkHttp's 37 today), which are the higher ones.
        aarMetadata { minCompileSdk = 1 }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") { java.srcDirs("src/main/kotlin") }
        getByName("test") { java.srcDirs("src/test/kotlin") }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

dependencies {
    // The Versola facade; its state, errors and claims are what the bridge converts. Where a
    // composite build is used (the example app) it substitutes the repository's :sdk project for
    // these coordinates.
    implementation("io.versola:versola-android:0.3.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
}
