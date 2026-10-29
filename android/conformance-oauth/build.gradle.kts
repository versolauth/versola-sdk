// The generic facade's conformance driver (issue #46, milestone B4; conformance/README.md,
// "Providers"): the scenarios tagged `facade: [oauth]` in spec/conformance/, run as Robolectric
// unit tests against a real OpenID Provider staged from conformance/providers/ (Keycloak today).
// Robolectric only because OAuthClient.create takes a Context for its storage directory; the
// network is real, through a rewriting proxy the tests own (ProviderProxy), and the browser leg
// is the provider's login form driven over HTTP (HttpLoginBrowser), as the Versola driver does.
//
// Every test is skipped (JUnit assumption) unless OAUTH_CONFORMANCE_ISSUER is set, so
// `./gradlew test` in android.yml's build job stays a unit run; conformance.yml sets it.
// Nothing is published from this module.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "versola.oauth.conformance"
    compileSdk = 36

    defaultConfig {
        minSdk = 26
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
            // The provider's address and the test user come from the environment, the way
            // conformance/providers/*/docker-compose.yml documents; forwarded to the test JVM.
            it.environment("OAUTH_CONFORMANCE_ISSUER", System.getenv("OAUTH_CONFORMANCE_ISSUER") ?: "")
            it.environment("OAUTH_CONFORMANCE_PROVIDER", System.getenv("OAUTH_CONFORMANCE_PROVIDER") ?: "")
            it.environment("OAUTH_CONFORMANCE_USERNAME", System.getenv("OAUTH_CONFORMANCE_USERNAME") ?: "")
            it.environment("OAUTH_CONFORMANCE_PASSWORD", System.getenv("OAUTH_CONFORMANCE_PASSWORD") ?: "")
            // A scenario that failed is diagnosed from its transcript.
            it.testLogging { events("failed", "skipped"); showStandardStreams = true }
            // A run against a live provider is never up to date and never worth caching: the
            // environment is not a tracked input, so the build cache would otherwise serve a
            // previous run's results (27 skipped, from a run with no provider) for a new one.
            it.outputs.upToDateWhen { false }
            it.outputs.doNotCacheIf("runs against a live provider") { true }
        }
    }
}

kotlin {
    compilerOptions {
        // Java 17 bytecode for consumers, whatever JDK runs the build (develop.md: 21).
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        // The driver replaces the browser leg and the Keystore-wrapped key through the opt-in
        // constructor; apps cannot without saying so.
        optIn.add("versola.oauth.core.VersolaInternalApi")
    }
}

dependencies {
    testImplementation(project(":oauth"))
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
    testImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.12.0")
    testImplementation("com.squareup.okhttp3:okhttp:5.4.0")
    // The proxy in front of the provider and the protected resources are MockWebServers with
    // a dispatcher, the same server the unit tier stubs with; here it forwards.
    testImplementation("com.squareup.okhttp3:mockwebserver3:5.4.0")
    testImplementation("org.robolectric:robolectric:4.17")
    testImplementation("androidx.test:core:1.7.0")
}
