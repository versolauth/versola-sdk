// The generic facade: OAuthClient, the public API of spec/oauth-sdk-api.md, over the same
// protocol core as the Versola facade (ADR 0001). It knows no Versola endpoint: configuration
// is an issuer (or explicit endpoints) and a client id, defaults are the standards' (Bearer,
// PAR when advertised), and provider differences are capabilities read from discovery
// (spec/providers.md). This is the module kz.versola:oauth-android maps to.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlinx.binary-compatibility-validator")
}

android {
    namespace = "versola.oauth"
    compileSdk = 37

    defaultConfig {
        minSdk = 26
        // No targetSdk on a library module; see :core.
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
    explicitApi()
    compilerOptions {
        // Java 17 bytecode for consumers, whatever JDK runs the build (develop.md: 21).
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        // The facade is the wiring: it constructs the flow, the coordinator and the starter,
        // which are opt-in for everyone else.
        optIn.add("versola.oauth.core.VersolaInternalApi")
    }
}

dependencies {
    // On the ABI: the configuration, the state, the errors, the claims (oauth-core) and the
    // OkHttp interceptor an app installs (okhttp).
    api(project(":oauth-core"))
    api(project(":okhttp"))
    // Platform halves, reused unchanged: the Keystore-wrapped stores, the system browser and
    // the hardware DPoP key. None of them is Versola-specific.
    implementation(project(":storage"))
    // api: the app re-declares VersolaRedirectActivity in its manifest (the merge snippet in
    // its KDoc), so the class must be on the app's compile classpath or lint reports
    // MissingClass for it; the sample app found this.
    api(project(":browser"))
    // api: KeyAttestation is on this module's ABI (keyAttestation()).
    api(project(":dpop"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testImplementation("com.squareup.okhttp3:mockwebserver3:5.5.1")
    testImplementation("org.robolectric:robolectric:4.17")
    testImplementation("androidx.test:core:1.7.0")
}

apiValidation {
    // Wiring behind the opt-in marker is not public API: keep it out of the dump so that
    // apiCheck holds this module to the surface an app can actually use (architecture
    // review F6).
    nonPublicMarkers.add("versola.oauth.core.VersolaInternalApi")
}
