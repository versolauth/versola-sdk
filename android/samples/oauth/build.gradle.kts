// A minimal app over the generic facade (OAuthClient), built with R8 on: a release build with
// `isMinifyEnabled = true` and the stock `proguard-android-optimize.txt` rules, and an empty
// `proguard-rules.pro`, is the proof that the SDK needs no consumer keep rules (architecture
// review F9). Nothing is published from this module.
plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// The provider the sample talks to. Defaults are placeholders on example.com; point the app at a
// real provider with -PsampleIssuer=... and friends (README.md).
fun sampleProperty(name: String, default: String): String =
    providers.gradleProperty(name).orElse(default).get()

android {
    namespace = "versola.samples.oauth"
    compileSdk = 36

    defaultConfig {
        applicationId = "versola.samples.oauth"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        buildConfigField("String", "ISSUER", "\"${sampleProperty("sampleIssuer", "https://id.example.com")}\"")
        buildConfigField("String", "CLIENT_ID", "\"${sampleProperty("sampleClientId", "sample-app")}\"")
        buildConfigField(
            "String", "REDIRECT_URI",
            "\"${sampleProperty("sampleRedirectUri", "https://app.example.com/oauth")}\"",
        )
        buildConfigField(
            "String", "POST_LOGOUT_REDIRECT_URI",
            "\"${sampleProperty("samplePostLogoutRedirectUri", "https://app.example.com/signed-out")}\"",
        )
        buildConfigField(
            "String", "RESOURCE_URL",
            "\"${sampleProperty("sampleResourceUrl", "https://api.example.com/me")}\"",
        )
    }

    buildFeatures {
        buildConfig = true
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                // Empty on purpose: the SDK needs no keep rules.
                "proguard-rules.pro",
            )
            // No signingConfig: the release APK is built unsigned. Nothing here is distributed.
        }
    }

    // The smoke test runs on the debug build (the default), not the minified one. AGP builds a
    // test APK without the artefacts the app's graph already has, and R8 strips those from the
    // app when it does not use them (androidx.tracing, parts of the Kotlin stdlib), so a test
    // of the minified build only starts once the app keeps them, which is a keep rule, which is
    // what this module exists to show the SDK needs none of. The R8 proof is the release build
    // itself; the device proof is the smoke test on the debug build.

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        // Only the instrumented test uses the opt-in: it substitutes the browser leg, since a
        // test cannot drive a real Custom Tab. The app itself uses the public API alone.
        optIn.add("versola.oauth.core.VersolaInternalApi")
    }
}

dependencies {
    implementation(project(":oauth"))
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.11.0")

    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("com.squareup.okhttp3:mockwebserver3:5.4.0")
    androidTestImplementation("com.squareup.okhttp3:okhttp:5.4.0")
    androidTestImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.11.0")
}
