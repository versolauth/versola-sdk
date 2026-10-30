// Root build file. Version catalogue for plugins applied per-module; no code lives here.
// See #4 for the layout this scaffolds and #1 §4 for the API 26 / target 36 floor.
plugins {
    id("com.android.library") version "9.5.0" apply false
    // The sample app (samples/oauth) is the only application module: the minified build that
    // proves no consumer keep rules are needed (architecture review F9).
    id("com.android.application") version "9.5.0" apply false
    // Applied explicitly (opting out of AGP 9's built-in Kotlin) - see gradle.properties.
    id("org.jetbrains.kotlin.android") version "2.4.21" apply false
    // The protocol core (:oauth-core) is a plain Kotlin/JVM module: no android.* import, so it
    // compiles and tests without AGP and stays shareable (ADR 0001).
    id("org.jetbrains.kotlin.jvm") version "2.4.21" apply false
    // Version tracks the Kotlin plugin above: the serialization compiler plugin ships with
    // the compiler and is not independently versioned.
    id("org.jetbrains.kotlin.plugin.serialization") version "2.4.21" apply false
    id("org.jetbrains.kotlinx.binary-compatibility-validator") version "0.18.2" apply false
}

// Coordinates for the modules that publish, and only those: gradle/publishing.gradle.kts assigns
// them. Giving every project the group would make `:oauth` and `:samples:oauth` the same module to
// Gradle (same group, same name, same version) and the sample would depend on itself.
// -PreleaseVersion overrides the development version for one build: it is what release.yml passes,
// from the tag, so a release never depends on a file someone forgot to edit.
val releaseVersion = providers.gradleProperty("releaseVersion").orNull
val publishVersion = releaseVersion ?: (property("VERSION_NAME") as String)
extra["publishGroup"] = property("GROUP") as String
extra["publishVersion"] = publishVersion

// The Central Portal takes one zip in Maven repository layout. Each published module writes into
// the same local repository (the `bundle` repository of gradle/publishing.gradle.kts); this task
// zips it. Nothing here talks to a server: uploading is release.yml's job, with credentials that
// only the maintainer has. Unsigned unless -PsigningKey is given, and refused as a bundle then
// (Central rejects an unsigned deployment) unless -PallowUnsignedBundle is passed for a local look.
val bundleRepository = layout.buildDirectory.dir("central-bundle/repo")

val cleanCentralBundle by tasks.registering(Delete::class) {
    delete(layout.buildDirectory.dir("central-bundle"))
}

val centralBundle by tasks.registering(Zip::class) {
    group = "publishing"
    description = "Zips every published module into a Maven Central Portal bundle (no upload)."
    archiveFileName.set("versola-$publishVersion.zip")
    destinationDirectory.set(layout.buildDirectory.dir("central-bundle"))
    from(bundleRepository)
    // Resolved when the graph is built, after every module has applied its publishing setup.
    dependsOn(provider {
        subprojects.filter { it.plugins.hasPlugin("maven-publish") }
            .map { "${it.path}:publishAllPublicationsToBundleRepository" }
    })
    doFirst {
        val signed = providers.gradleProperty("signingKey").isPresent
        check(signed || providers.gradleProperty("allowUnsignedBundle").isPresent) {
            "the bundle is unsigned: pass -PsigningKey (and -PsigningPassword), or -PallowUnsignedBundle to look at it locally"
        }
        check(!publishVersion.endsWith("-SNAPSHOT")) {
            "Central refuses a SNAPSHOT version; pass -PreleaseVersion=<x.y.z>"
        }
    }
}

// Every module's publish-to-bundle starts from an empty repository, so a bundle holds exactly the
// versions of this run and never a leftover from an earlier one.
subprojects {
    tasks.matching { it.name == "publishAllPublicationsToBundleRepository" }.configureEach {
        dependsOn(rootProject.tasks.named("cleanCentralBundle"))
    }
}
