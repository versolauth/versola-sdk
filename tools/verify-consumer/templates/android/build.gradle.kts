// Plugin versions are the repository's own (android/build.gradle.kts), substituted by the script,
// so the consumer is built with the toolchain the SDK is built with.
plugins {
    id("com.android.application") version "@AGP_VERSION@" apply false
    id("org.jetbrains.kotlin.android") version "@KOTLIN_VERSION@" apply false
}
