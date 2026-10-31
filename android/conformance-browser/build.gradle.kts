// The browser-leg device tier: UI Automator tests that drive the real system browser (Chrome's
// Auth Tab and Custom Tabs) on an emulator, against a provider container, through the host app
// in :conformance-browser-app. An instrumentation package of its own (com.android.test), not
// androidTest of the app, so that a test can kill the app's process and keep running: scenario 12.
//
// The provider is reached at the address its discovery announces, so `adb reverse` forwards the
// container's port to the emulator's loopback (develop.md). The tests are skipped, not failed,
// unless an issuer is passed (-Pandroid.testInstrumentationRunnerArguments.issuer=...).
plugins {
    id("com.android.test")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "versola.conformance.browser"
    compileSdk = 37

    defaultConfig {
        minSdk = 26
        targetSdk = 37
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    targetProjectPath = ":conformance-browser-app"
    // Instrument this package, not the app: by default a test module instruments its target, so
    // the instrumentation lives in the app's process and `kill` of that process (scenario 12) would
    // end the test run with it. Self-instrumenting keeps the tests in their own process while they
    // drive and kill the host app's.
    experimentalProperties["android.experimental.self-instrumenting"] = true

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
    implementation("androidx.test:runner:1.7.0")
    implementation("androidx.test.ext:junit:1.3.0")
    // UI Automator drives Chrome, which is another app: Espresso cannot. Apache-2.0, Google,
    // released from the androidx.test repository.
    implementation("androidx.test.uiautomator:uiautomator:2.4.0")
}
