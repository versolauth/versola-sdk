// The authenticated HTTP client: attaches DPoP proofs (or bearer, per discovery),
// single-flight refresh, nonce retry. See #1 §2 — edge accepts both schemes.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlinx.binary-compatibility-validator")
}

android {
    namespace = "versola.sdk.okhttp"
    compileSdk = 37

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
    compilerOptions {
        // Java 17 bytecode for consumers, whatever JDK runs the build (develop.md: 21).
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
    explicitApi()
}

dependencies {
    api(project(":oauth-core"))
    implementation(project(":dpop"))
    api("com.squareup.okhttp3:okhttp:5.5.1")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testImplementation("com.squareup.okhttp3:mockwebserver3:5.5.1")
}

apiValidation {
    // Wiring behind the opt-in marker is not public API: keep it out of the dump so that
    // apiCheck holds this module to the surface an app can actually use (architecture
    // review F6).
    nonPublicMarkers.add("versola.oauth.core.VersolaInternalApi")
}

// Published (gradle/publishing.gradle.kts): the coordinates are kz.versola:okhttp-android.
extra["publishing.artifactId"] = "okhttp-android"
extra["publishing.name"] = "Versola OkHttp integration (Android)"
extra["publishing.description"] = "OkHttp interceptor that attaches the access token, with DPoP proofs, to requests for configured origins."
apply(from = rootProject.file("gradle/publishing.gradle.kts"))
