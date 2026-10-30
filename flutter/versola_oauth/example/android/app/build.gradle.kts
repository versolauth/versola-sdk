import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "kz.versola.versola_oauth_example"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "kz.versola.versola_oauth_example"
        // The SDK's floor (android/oauth), above Flutter's default of 24.
        minSdk = 26
        targetSdk = flutter.targetSdkVersion
        // Uses the version code from pubspec.yaml. When using split APKs, 1000 * ABI_VERSION
        // is added automatically by Flutter. (https://developer.android.com/studio/build/configure-apk-splits#configure-APK-versions)
        // You can force using the value of versionCode by specifying the `-P force-version-code-ignoring-abi=true`
        // flag during build.
        versionCode = flutter.versionCode
        versionName = flutter.versionName
    }

    // The bridge conformance tests (src/test; conformance/README.md, "Through the Flutter bridge"):
    // Robolectric unit tests that drive the plugin's host API against a real OpenID Provider. They
    // share the Android conformance driver's support classes by source (below), so the test options
    // are the ones of android/conformance-oauth/build.gradle.kts.
    testOptions {
        // No isIncludeAndroidResources: it would package the app's merged assets into the unit-test
        // run, and with the Flutter Gradle plugin that is an undeclared dependency on
        // copyFlutterAssetsDebug. The tests need the framework's resources only, which
        // Robolectric supplies.
        unitTests.all {
            // Robolectric's API 36 image on JDK 21: ApplicationSharedMemory reaches the raw file
            // descriptor through jdk.internal.access, which the module system hides from the
            // unnamed module unless exported here.
            it.jvmArgs("--add-exports", "java.base/jdk.internal.access=ALL-UNNAMED")
            // The provider's address and the test user come from the environment, as
            // conformance/providers/*/docker-compose.yml documents.
            it.environment("OAUTH_CONFORMANCE_ISSUER", System.getenv("OAUTH_CONFORMANCE_ISSUER") ?: "")
            it.environment("OAUTH_CONFORMANCE_PROVIDER", System.getenv("OAUTH_CONFORMANCE_PROVIDER") ?: "")
            it.environment("OAUTH_CONFORMANCE_USERNAME", System.getenv("OAUTH_CONFORMANCE_USERNAME") ?: "")
            it.environment("OAUTH_CONFORMANCE_PASSWORD", System.getenv("OAUTH_CONFORMANCE_PASSWORD") ?: "")
            it.testLogging { events("failed", "skipped"); showStandardStreams = true }
            // A run against a live provider is never up to date and never worth caching.
            it.outputs.upToDateWhen { false }
            it.outputs.doNotCacheIf("runs against a live provider") { true }
        }
    }

    // The driver's support classes (Provider, ProviderProxy, HttpLoginBrowser, Transcript,
    // ResourceServer, HarnessSigner, ProviderConformance) are compiled from where they live, not
    // copied: one driver, two ways to reach the SDK. Its scenario files are the native drivers'
    // and stay out (the KotlinCompile filter below).
    sourceSets.getByName("test").java.srcDir("../../../../../android/conformance-oauth/src/test/kotlin")

    buildTypes {
        release {
            // TODO: Add your own signing config for the release build.
            // Signing with the debug keys for now, so `flutter run --release` works.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

// The native driver's scenarios are not this module's tests: they drive OAuthClient directly and
// run in :conformance-oauth. Only its support classes are shared.
tasks.withType<KotlinCompile>().configureEach {
    if (name.contains("UnitTest")) {
        exclude("**/versola/oauth/conformance/Scenario*")
        // The driver replaces the browser leg and the Keystore-wrapped key through the opt-in
        // constructor, as android/conformance-oauth does; apps cannot without saying so.
        compilerOptions.optIn.add("versola.oauth.core.VersolaInternalApi")
    }
}

dependencies {
    // The generic facade itself, for the driver's wiring (the opt-in create); the composite
    // build in settings.gradle.kts substitutes the repository's :oauth for these coordinates.
    testImplementation("kz.versola:oauth-android:0.1.0")
    // The six pins below are a second copy of android/conformance-oauth/build.gradle.kts, whose
    // support classes are compiled into this module too: keep them equal, in the same change.
    // Dependabot watches /android only, so a bump there does not reach this file by itself.
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.11.0")
    testImplementation("com.squareup.okhttp3:okhttp:5.4.0")
    // The proxy in front of the provider and the protected resources are MockWebServers.
    testImplementation("com.squareup.okhttp3:mockwebserver3:5.4.0")
    testImplementation("org.robolectric:robolectric:4.17")
    testImplementation("androidx.test:core:1.7.0")
}

flutter {
    source = "../.."
}
