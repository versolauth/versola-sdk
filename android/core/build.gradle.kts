// What is Versola-specific in the protocol layer: the edge back channel (`BackChannel.Edge`),
// its native endpoints and the errors only edge produces. Everything RFC-shaped lives in
// :oauth-core (ADR 0001); this module depends on it, never the reverse.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.serialization")
    id("org.jetbrains.kotlinx.binary-compatibility-validator")
}

android {
    namespace = "versola.sdk.core"
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
    compilerOptions {
        // Java 17 bytecode for consumers, whatever JDK runs the build (develop.md: 21).
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        // The edge half reaches the protocol core's wiring (the request executor, the form
        // body, the grant's code) through the opt-in marker rather than through `internal`,
        // which stops at the module boundary.
        optIn.add("versola.oauth.core.VersolaInternalApi")
    }
}

dependencies {
    // Everything RFC-shaped, and the types on this module's ABI (VersolaError, TokenClient,
    // the configuration), come from the protocol core.
    api(project(":oauth-core"))
    // The Android dispatcher the facade's callers run on; the core itself needs only -core.
    api("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")
    // `/native/start`'s answer is parsed with the same reflection-free serializer as discovery.
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.12.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testImplementation("com.squareup.okhttp3:mockwebserver3:5.4.0")
}

apiValidation {
    // Wiring behind the opt-in marker is not public API: keep it out of the dump so that
    // apiCheck holds this module to the surface an app can actually use (architecture
    // review F6).
    nonPublicMarkers.add("versola.oauth.core.VersolaInternalApi")
}

// Published (gradle/publishing.gradle.kts): the coordinates are kz.versola:versola-core-android.
extra["publishing.artifactId"] = "versola-core-android"
extra["publishing.name"] = "Versola core (Android)"
extra["publishing.description"] = "What is specific to the Versola server in the protocol layer: the edge back channel and its native endpoints."
apply(from = rootProject.file("gradle/publishing.gradle.kts"))
