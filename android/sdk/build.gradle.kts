// The facade: Versola.configure(...) and the authorization flow that ties discovery, the
// pending-request store and the browser together. It exists because the entry point in
// #1 §1 has to see :browser and :storage at once, and neither may depend on the other.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlinx.binary-compatibility-validator")
}

android {
    namespace = "versola.sdk"
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
        // The facade is the wiring: it constructs the flow and the coordinator, which are
        // opt-in for everyone else.
        optIn.add("versola.oauth.core.VersolaInternalApi")
    }
}

dependencies {
    api(project(":oauth-core"))
    api(project(":core"))
    api(project(":browser"))
    api(project(":dpop"))
    api(project(":storage"))
    api(project(":okhttp"))

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testImplementation("org.robolectric:robolectric:4.17")
    testImplementation("androidx.test:core:1.7.0")
}

apiValidation {
    // Wiring behind the opt-in marker is not public API: keep it out of the dump so that
    // apiCheck holds this module to the surface an app can actually use (architecture
    // review F6).
    nonPublicMarkers.add("versola.oauth.core.VersolaInternalApi")
}
