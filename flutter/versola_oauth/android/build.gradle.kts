// The Android half of the versola_oauth plugin: glue over kz.versola:oauth-android, the
// generic facade of this repository (android/oauth). The artefact is not published yet, so an
// app resolves it from the repository itself with a composite build (example/android/settings.gradle.kts).
group = "versola.oauth.flutter"
version = "0.1.0"

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "versola.oauth.flutter"
    compileSdk = 36

    defaultConfig {
        // The SDK's floor (android/oauth): Keystore-wrapped stores and Auth Tab need API 26.
        minSdk = 26
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
    // The generic facade; its state, errors and claims are what the bridge converts. The
    // version is nominal until the artefact is published: the composite build substitutes the
    // repository's :oauth project for these coordinates.
    implementation("kz.versola:oauth-android:0.1.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
}
