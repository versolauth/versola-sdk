#!/usr/bin/env bash
# Builds a throwaway Android app that depends on the PUBLISHED SDK, the way a customer's does.
#
#   tools/verify-consumer/android.sh 0.1.0
#
# The app has `mavenCentral()` and `google()` and nothing else, one
# `implementation("io.versola:oauth-android:<version>")`, compileSdk 37 and minSdk 26, and a
# Kotlin file that names OAuthClient and OAuthConfiguration. `./gradlew assembleDebug` therefore
# fails unless Maven Central serves the AAR, its POM and Gradle metadata, and every module they
# name (oauth-core, dpop-android, storage-android, browser-android, okhttp-android), and unless
# the AARs compile and their manifests merge. It does not use android/ in this repository: a build
# against the repository would prove the sources, which android.yml already does, not the release.
#
# Needs JDK 21 on JAVA_HOME (develop.md) and ANDROID_HOME with platform android-37.0 (develop.md;
# CI installs it explicitly). Gradle version, AGP and Kotlin are read from this repository, so
# the consumer is built with the toolchain the SDK is. The steps are common.sh's;
# android-bundle.sh (the same app before the upload) composes the same ones.
set -euo pipefail
# shellcheck source=tools/verify-consumer/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

version="${1:-}"
require_version "$version"

prepare_android_consumer "$version"
# Exactly the two repositories the README tells an integrator to have: nothing else may serve io.versola.
set_android_repositories "        google()
        mavenCentral()"
check_android_resolution "$version" "is $version on Maven Central yet?"
assemble_android_consumer
echo "verify-consumer: android OK ($version)"
