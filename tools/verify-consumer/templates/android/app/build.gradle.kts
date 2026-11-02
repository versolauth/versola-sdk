plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.example.verify"
    // The floors the README gives an integrator: compileSdk 37 (OkHttp 5.5.1 needs it of a
    // dependent) and minSdk 26.
    compileSdk = 37

    defaultConfig {
        applicationId = "com.example.verify"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        versionName = "1"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // The one line a consumer writes. The SDK is one artefact: its AAR holds the protocol engine, the
    // DPoP, storage, browser and OkHttp parts, and its POM names only third-party libraries.
    implementation("io.versola:oauth-android:@VERSION@")
}
