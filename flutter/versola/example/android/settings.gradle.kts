pluginManagement {
    val flutterSdkPath =
        run {
            val properties = java.util.Properties()
            file("local.properties").inputStream().use { properties.load(it) }
            val flutterSdkPath = properties.getProperty("flutter.sdk")
            require(flutterSdkPath != null) { "flutter.sdk not set in local.properties" }
            flutterSdkPath
        }

    includeBuild("$flutterSdkPath/packages/flutter_tools/gradle")

    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

plugins {
    id("dev.flutter.flutter-plugin-loader") version "1.0.0"
    // The same AGP and Kotlin as the repository's Android build (android/build.gradle.kts):
    // an included build cannot load a second version of either plugin.
    id("com.android.application") version "9.5.0" apply false
    id("org.jetbrains.kotlin.android") version "2.4.21" apply false
}

// io.versola:versola-android is not published yet: the plugin's dependency on it is satisfied by
// the repository's own Android build, included here with the artefact substituted by the :sdk
// project (whose :oauth-core, :core, :browser, :dpop, :storage and :okhttp project dependencies
// resolve inside that build). An app outside this repository drops this block once the artefact is
// on Maven Central.
//
// io.versola:oauth-android is substituted too, with :oauth: the plugin depends on versola_oauth for
// the shared Dart types, and Flutter builds every plugin in the app's graph, so the generic
// plugin's Kotlin glue is compiled here as well and resolves its own artefact.
includeBuild("../../../../android") {
    dependencySubstitution {
        substitute(module("io.versola:versola-android")).using(project(":sdk"))
        substitute(module("io.versola:oauth-android")).using(project(":oauth"))
    }
}

include(":app")
