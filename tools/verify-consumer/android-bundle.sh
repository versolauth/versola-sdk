#!/usr/bin/env bash
# Builds the throwaway Android app of android.sh against an UNZIPPED Maven Central bundle, before
# anything is uploaded, without any key.
#
#   unzip -q android/build/central-bundle/versola-0.2.0.zip -d /tmp/bundle
#   tools/verify-consumer/android-bundle.sh /tmp/bundle 0.2.0
#
# It is the same app as android.sh's (templates/android, compileSdk 37, minSdk 26, one
# `implementation("io.versola:oauth-android:<version>")`, the same resolution checks, the same
# `assembleDebug`); only where the SDK comes from differs. io.versola is served by the bundle
# directory used as a local Maven repository, and by nothing else: `exclusiveContent` keeps Central,
# Google and anything else from answering for that group, so a module the bundle lacks, or metadata
# naming a version the bundle lacks, fails here instead of resolving from Central. google() and
# mavenCentral() stay for the third-party dependencies (OkHttp, AndroidX, Kotlin) and the plugins.
#
# The release is read from its POM (the SDK is published without Gradle metadata: a Gradle metadata
# file describes a component, and the one AAR is merged from several modules, see
# android/gradle/publishing.gradle.kts), which is what Gradle, Maven and everything else take.
#
# What it proves: a consumer resolves oauth-android, with no other io.versola module, from these files, and compiles and packages against them. What it does not prove: that the signatures
# verify (check-bundle.sh looks for their presence; Central verifies them), that Central accepts
# the bundle, or that Central serves it (android.sh after the publication proves that).
#
# Needs JDK 21 on JAVA_HOME and ANDROID_HOME with platform android-37.0 (develop.md).
set -euo pipefail
# shellcheck source=tools/verify-consumer/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

dir="${1:-}"
version="${2:-}"
[[ -d "$dir/io/versola" ]] || fail "usage: android-bundle.sh <unzipped bundle directory> X.Y.Z (no io/versola in '$dir')"
require_version "$version"
dir="$(cd "$dir" && pwd)"
# The path goes into a Kotlin string in the generated settings file: a plain path only.
[[ "$dir" =~ ^[A-Za-z0-9._/+-]+$ ]] || fail "the bundle path '$dir' may only hold letters, digits and . _ / + -"

# The bundle at $1 as the repository for io.versola, and how its metadata is read (a Gradle
# `metadataSources` line, $2).
bundle_repositories() { # directory metadata-sources
  echo "        exclusiveContent {
            forRepository { maven { url = uri(\"file://$1\"); metadataSources { $2 } } }
            filter { includeGroup(\"io.versola\") }
        }
        google()
        mavenCentral()"
}

hint="the bundle at $dir does not provide it"
prepare_android_consumer "$version"
set_android_repositories "$(bundle_repositories "$dir" 'mavenPom(); artifact()')"
check_android_resolution "$version" "$hint"
assemble_android_consumer
echo "verify-consumer: android OK from the bundle ($version)"
