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
# The release is read twice, because consumers read it in two ways. First by its Gradle metadata
# (.module), which is what a Gradle build takes when it is there, and the app is assembled from
# that. Then by its POMs alone, which is what a Maven consumer and anything that ignores Gradle
# metadata takes (on a copy of the bundle without the .module files: a Gradle build reads the
# metadata whenever a POM points to it): the same six modules must resolve at the version from the
# POMs too. Either one broken fails the script.
#
# What it proves: a consumer resolves oauth-android and the five modules its metadata names from
# these files, and compiles and packages against them. What it does not prove: that the signatures
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
set_android_repositories "$(bundle_repositories "$dir" 'gradleMetadata()')"
check_android_resolution "$version" "$hint, by its Gradle metadata"
assemble_android_consumer

echo "verify-consumer: resolved and assembled from the Gradle metadata, now the POMs alone"
pom_only="$WORK/bundle-poms-only"
cp -R "$dir" "$pom_only"
find "$pom_only" -name '*.module*' -delete
[[ "$pom_only" =~ ^[A-Za-z0-9._/+-]+$ ]] || fail "the work directory '$pom_only' may only hold letters, digits and . _ / + -"
set_android_repositories "$(bundle_repositories "$pom_only" 'mavenPom(); artifact()')"
check_android_resolution "$version" "$hint, by its POMs"
echo "verify-consumer: android OK from the bundle ($version)"
