// What every published module shares: a Maven publication with the POM Maven Central requires, a
// sources jar and a javadoc jar, PGP signatures when a key is given, and a local `bundle`
// repository that the root project's `centralBundle` task zips. Applied from a module's build file
// after it has set
//
//     extra["publishing.artifactId"], extra["publishing.name"], extra["publishing.description"]
//
// Nothing in here publishes to a server. `publish` without a remote repository writes only to the
// `bundle` repository (and mavenLocal when asked); release.yml uploads the zip with credentials that
// are the maintainer's (.claude/rules/ci-release.md).
import org.gradle.api.publish.PublishingExtension
import org.gradle.api.publish.maven.MavenPublication
import org.gradle.plugins.signing.SigningExtension

apply(plugin = "maven-publish")
apply(plugin = "signing")

// The coordinates of a published module; set here, not for every project (build.gradle.kts, root).
group = rootProject.extra["publishGroup"] as String
version = rootProject.extra["publishVersion"] as String

val artifactIdOfModule = extra["publishing.artifactId"] as String
val nameOfModule = extra["publishing.name"] as String
val descriptionOfModule = extra["publishing.description"] as String
val isAndroidLibrary = plugins.hasPlugin("com.android.library")

if (isAndroidLibrary) {
    // The sources jar and the javadoc jar Central requires. The modules are Kotlin, so the javadoc
    // jar is the placeholder Central allows ("a README pointing to more information" is the
    // allowed form); the API reference is the KDoc in the sources jar and the spec.
    // Through the Groovy builder, not the typed DSL: this script is compiled against Gradle's API
    // only, and AGP's classes are not on its classpath (they are on each module's, which is why
    // the module build files can type `android { }`). The calls are those of AGP's
    // `android.publishing.singleVariant`.
    extensions.getByName("android").withGroovyBuilder {
        "publishing" {
            "singleVariant"("release") {
                "withSourcesJar"()
                "withJavadocJar"()
            }
        }
    }
} else {
    extensions.configure<JavaPluginExtension>("java") {
        withSourcesJar()
        withJavadocJar()
    }
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
            from(components[if (isAndroidLibrary) "release" else "java"])
            artifactId = artifactIdOfModule
            pom {
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
                        url.set("https://versola.kz")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/versolauth/versola-sdk.git")
                    developerConnection.set("scm:git:ssh://git@github.com/versolauth/versola-sdk.git")
                    url.set("https://github.com/versolauth/versola-sdk")
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
