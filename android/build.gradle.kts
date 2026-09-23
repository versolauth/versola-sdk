// Root build file. Version catalogue for plugins applied per-module; no code lives here.
// See #4 for the layout this scaffolds and #1 §4 for the API 26 / target 36 floor.
plugins {
    id("com.android.library") version "9.4.1" apply false
    // Applied explicitly (opting out of AGP 9's built-in Kotlin) - see gradle.properties.
    id("org.jetbrains.kotlin.android") version "2.4.20" apply false
    // Version tracks the Kotlin plugin above: the serialization compiler plugin ships with
    // the compiler and is not independently versioned.
    id("org.jetbrains.kotlin.plugin.serialization") version "2.4.20" apply false
    id("org.jetbrains.kotlinx.binary-compatibility-validator") version "0.18.2" apply false
}
