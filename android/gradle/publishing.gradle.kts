// What the one published module shares: a Maven publication with the POM Maven Central requires, a
// sources jar and a javadoc jar, PGP signatures when a key is given, and a local `bundle`
// repository that the root project's `centralBundle` task zips. Applied from `:oauth`'s build file
// after it has set
//
//     extra["publishing.artifactId"], extra["publishing.name"], extra["publishing.description"],
//     extra["publishing.mergeModules"]
//
// The Android SDK is published as ONE artefact. The build keeps its modules (layering, the
// no-`android.*` rule of the core, per-module `apiCheck`), and the publication folds them in:
// the AAR holds the classes of `:oauth` and of every module listed in `publishing.mergeModules`
// (one `classes.jar`, a duplicate class is a build error), the manifest of `:browser`, and the
// POM is derived from the third-party libraries those modules declare, so it names no
// `io.versola:*` coordinate and cannot drift from the build files. What the merge does not carry
// (resources, assets, native libraries, consumer ProGuard rules in any merged module) fails the
// build instead of being dropped silently: the day a module gains one, the merge has to learn it.
//
// Nothing in here publishes to a server. `publish` without a remote repository writes only to the
// `bundle` repository (and mavenLocal when asked); release.yml uploads the zip with credentials that
// are the maintainer's (.claude/rules/ci-release.md).
import java.io.ByteArrayOutputStream
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import org.gradle.api.artifacts.ExternalModuleDependency
import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.plugins.signing.SigningExtension

apply(plugin = "maven-publish")
apply(plugin = "signing")

// The coordinates of the published module; set here, not for every project (build.gradle.kts, root).
group = rootProject.extra["publishGroup"] as String
version = rootProject.extra["publishVersion"] as String

val artifactIdOfModule = extra["publishing.artifactId"] as String
val nameOfModule = extra["publishing.name"] as String
val descriptionOfModule = extra["publishing.description"] as String

@Suppress("UNCHECKED_CAST")
val mergeModules = extra["publishing.mergeModules"] as List<String>
val publishVersion = version.toString()
val mergedDir = layout.buildDirectory.dir("merged-aar")

// The modules' own artefacts. Looked up lazily: `:oauth` can be configured before the modules it
// merges, and a task is only asked for once the whole build is configured.
val aarModules = mergeModules.filter { it != ":oauth-core" }
fun aarOf(path: String) = provider { project(path).tasks.named("bundleReleaseAar").get().outputs.files.singleFile }
val ownAar = provider { tasks.named("bundleReleaseAar").get().outputs.files.singleFile }
val coreJar = provider { project(":oauth-core").tasks.named("jar").get().outputs.files.singleFile }

val mergedAar = tasks.register("mergedReleaseAar") {
    group = "publishing"
    description = "Builds the one AAR that is published: this module plus the modules in publishing.mergeModules."
    dependsOn("bundleReleaseAar")
    dependsOn(provider { aarModules.map { "$it:bundleReleaseAar" } })
    dependsOn(provider { ":oauth-core:jar" })
    val output = mergedDir.map { it.file("$artifactIdOfModule-$publishVersion.aar") }
    outputs.file(output)
    doLast {
        val own = ownAar.get()
        val others = aarModules.map { it to aarOf(it).get() }
        val jars = listOf(":oauth" to own) + others

        fun entries(zip: ZipFile) = zip.entries().asSequence().toList()
        val target = output.get().asFile
        target.parentFile.mkdirs()

        // What an AAR can carry that this merge does not: say so rather than lose it.
        for ((path, aar) in others) ZipFile(aar).use { zip ->
            val unmerged = entries(zip).map { it.name }.filter { name ->
                !name.endsWith("/") && name != "AndroidManifest.xml" && name != "classes.jar" &&
                    name != "R.txt" && name != "public.txt" && !name.startsWith("META-INF/")
            }
            check(unmerged.isEmpty()) { "$path carries $unmerged, which the merged AAR does not carry (gradle/publishing.gradle.kts)" }
        }

        // One classes.jar. A class or file present twice is an error; each module's own
        // `.kotlin_module` has a different name, and the jars' manifests are the one exception.
        val merged = ByteArrayOutputStream()
        val seen = HashSet<String>()
        ZipOutputStream(merged).use { out ->
            fun add(source: ZipFile, owner: String) {
                for (entry in entries(source)) {
                    if (entry.isDirectory || entry.name == "META-INF/MANIFEST.MF") continue
                    check(seen.add(entry.name)) { "${entry.name} is in more than one merged module (second: $owner)" }
                    out.putNextEntry(ZipEntry(entry.name).apply { time = 0L })
                    source.getInputStream(entry).use { it.copyTo(out) }
                    out.closeEntry()
                }
            }
            for ((path, aar) in jars) ZipFile(aar).use { zip ->
                val inner = entries(zip).first { it.name == "classes.jar" }
                val tmp = File.createTempFile("classes", ".jar")
                try {
                    zip.getInputStream(inner).use { input -> tmp.outputStream().use { input.copyTo(it) } }
                    ZipFile(tmp).use { add(it, path) }
                } finally {
                    tmp.delete()
                }
            }
            ZipFile(coreJar.get()).use { add(it, ":oauth-core") }
        }

        // The manifest is :browser's (the only merged module with one), under this module's
        // package: its activities are named in full, so the package only anchors the R class.
        val ownPackage = ZipFile(own).use { zip ->
            val text = zip.getInputStream(zip.getEntry("AndroidManifest.xml")).readBytes().toString(Charsets.UTF_8)
            Regex("""package="([^"]+)"""").find(text)!!.groupValues[1]
        }
        val browserAar = aarOf(":browser").get()
        val manifest = ZipFile(browserAar).use { zip ->
            val text = zip.getInputStream(zip.getEntry("AndroidManifest.xml")).readBytes().toString(Charsets.UTF_8)
            val declared = Regex("""package="([^"]+)"""").find(text)!!.groupValues[1]
            text.replace("""package="$declared"""", """package="$ownPackage"""")
        }
        check("android:name=\"versola.sdk.browser.VersolaRedirectActivity\"" in manifest) {
            "the merged manifest lost VersolaRedirectActivity"
        }

        ZipOutputStream(target.outputStream()).use { out ->
            fun put(name: String, bytes: ByteArray) {
                out.putNextEntry(ZipEntry(name).apply { time = 0L })
                out.write(bytes)
                out.closeEntry()
            }
            ZipFile(own).use { zip ->
                for (entry in entries(zip)) {
                    if (entry.isDirectory || entry.name == "classes.jar" || entry.name == "AndroidManifest.xml") continue
                    put(entry.name, zip.getInputStream(entry).readBytes())
                }
            }
            put("AndroidManifest.xml", manifest.toByteArray())
            put("classes.jar", merged.toByteArray())
        }
    }
}

// The sources of every merged module, so the sources jar is the whole artefact's.
val mergedSources = tasks.register<Jar>("mergedSourcesJar") {
    archiveBaseName.set(artifactIdOfModule)
    archiveClassifier.set("sources")
    destinationDirectory.set(mergedDir)
    isReproducibleFileOrder = true
    isPreserveFileTimestamps = false
    duplicatesStrategy = DuplicatesStrategy.FAIL
    for (path in listOf(":oauth") + mergeModules) {
        for (dir in listOf("src/main/kotlin", "src/main/java")) {
            val root = project(path).projectDir.resolve(dir)
            if (root.isDirectory) from(root)
        }
    }
}

// The Kotlin modules have no Javadoc; Central allows a placeholder jar ("a README pointing to more
// information"). The API reference is the KDoc in the sources jar and the spec.
val mergedJavadoc = tasks.register<Jar>("mergedJavadocJar") {
    archiveBaseName.set(artifactIdOfModule)
    archiveClassifier.set("javadoc")
    destinationDirectory.set(mergedDir)
    isReproducibleFileOrder = true
    isPreserveFileTimestamps = false
    from(resources.text.fromString(
        "The API reference of this library is the KDoc in the -sources jar, and spec/oauth-sdk-api.md in " +
            "https://github.com/versolauth/versola-sdk.\n",
    )) { rename { "README.txt" } }
}

extensions.configure<PublishingExtension>("publishing") {
    repositories {
        maven {
            name = "bundle"
            url = uri(rootProject.layout.buildDirectory.dir("central-bundle/repo"))
        }
    }
}

afterEvaluate {
    val publishing = extensions.getByType<PublishingExtension>()
    publishing.publications {
        create<MavenPublication>("release") {
            artifactId = artifactIdOfModule
            artifact(mergedAar) { extension = "aar" }
            artifact(mergedSources)
            artifact(mergedJavadoc)
            pom {
                packaging = "aar"
                name.set(nameOfModule)
                description.set(descriptionOfModule)
                url.set("https://github.com/versolauth/versola-sdk")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("versolauth")
                        name.set("Versola")
                        url.set("https://versola.io")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/versolauth/versola-sdk.git")
                    developerConnection.set("scm:git:ssh://git@github.com/versolauth/versola-sdk.git")
                    url.set("https://github.com/versolauth/versola-sdk")
                }
                // The third-party libraries of this module and the merged ones, taken from what they
                // declare: `api` ones are compile scope (they are on the app's compile classpath
                // today through the project dependencies), `implementation` ones runtime scope. A
                // project dependency is skipped: its classes are inside the AAR.
                withXml {
                    val compile = linkedMapOf<String, ExternalModuleDependency>()
                    val runtime = linkedMapOf<String, ExternalModuleDependency>()
                    for (path in listOf(":oauth") + mergeModules) {
                        val module = project(path)
                        for ((configuration, into) in listOf("api" to compile, "implementation" to runtime)) {
                            module.configurations.findByName(configuration)?.allDependencies
                                ?.filterIsInstance<ExternalModuleDependency>()
                                ?.forEach { into.putIfAbsent("${it.group}:${it.name}", it) }
                        }
                    }
                    runtime.keys.removeAll(compile.keys)
                    val dependencies = asNode().appendNode("dependencies")
                    for ((scope, set) in listOf("compile" to compile, "runtime" to runtime)) {
                        for (dependency in set.values.sortedBy { "${it.group}:${it.name}" }) {
                            check(dependency.version != null) { "${dependency.group}:${dependency.name} has no version" }
                            dependencies.appendNode("dependency").apply {
                                appendNode("groupId", dependency.group)
                                appendNode("artifactId", dependency.name)
                                appendNode("version", dependency.version)
                                appendNode("scope", scope)
                            }
                        }
                    }
                }
            }
        }
    }

    // In-memory ASCII-armoured key from the environment (ORG_GRADLE_PROJECT_signingKey in CI), so
    // no key file exists on a runner. Without a key nothing is signed and nothing here fails: an
    // ordinary `assemble` or a local look at the bundle must not need one.
    extensions.configure<SigningExtension>("signing") {
        val key = providers.gradleProperty("signingKey").orNull
        if (key != null) {
            useInMemoryPgpKeys(key, providers.gradleProperty("signingPassword").orNull)
            sign(publishing.publications)
        }
    }
}
