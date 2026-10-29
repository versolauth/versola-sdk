// The authenticated HTTP client: attaches DPoP proofs (or bearer, per discovery),
// single-flight refresh, nonce retry. See #1 §2 — edge accepts both schemes.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlinx.binary-compatibility-validator")
}

android {
    namespace = "versola.sdk.okhttp"
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
    api(project(":oauth-core"))
    implementation(project(":dpop"))
    // Pinned to 5.4.0: 5.5.0's AAR declares minCompileSdk=37, ahead of any SDK Platform
    // release available at scaffolding time. Revisit once compileSdk 37 is installable.
    api("com.squareup.okhttp3:okhttp:5.4.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testImplementation("com.squareup.okhttp3:mockwebserver3:5.4.0")
}
