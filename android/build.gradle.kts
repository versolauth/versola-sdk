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
