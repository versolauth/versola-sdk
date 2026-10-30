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
# the consumer is built with the toolchain the SDK is.
set -euo pipefail
# shellcheck source=tools/verify-consumer/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

version="${1:-}"
require_version "$version"

[[ -n "${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}" ]] || fail "ANDROID_HOME is not set (develop.md)"

# One place to read a plugin version from: the file the whole build is pinned by. A pattern that
# stops matching must fail here, not produce an empty version in the generated project.
plugin_version() { # plugin id
  local v
  v="$(sed -n "s|.*id(\"$1\") version \"\([0-9][^\"]*\)\".*|\1|p" "$VERIFY_ROOT/android/build.gradle.kts" | head -1)"
  [[ -n "$v" ]] || fail "no version for plugin $1 in android/build.gradle.kts"
  echo "$v"
}
agp="$(plugin_version com.android.application)"
kotlin="$(plugin_version org.jetbrains.kotlin.android)"

make_work_dir
app="$WORK/app"
mkdir -p "$app"
cp -R "$VERIFY_ROOT/tools/verify-consumer/templates/android/." "$app/"
render_templates "$app" "AGP_VERSION=$agp" "KOTLIN_VERSION=$kotlin" "VERSION=$version"

# The repository's wrapper, so the Gradle version (and its checksum policy) is the pinned one and
# is not chosen here a second time.
cp "$VERIFY_ROOT/android/gradlew" "$app/gradlew"
mkdir -p "$app/gradle"
cp -R "$VERIFY_ROOT/android/gradle/wrapper" "$app/gradle/wrapper"

cd "$app"
echo "verify-consumer: io.versola:oauth-android:$version, AGP $agp, Kotlin $kotlin, $(sed -n 's/^distributionUrl=.*gradle-\(.*\)-bin.zip/Gradle \1/p' gradle/wrapper/gradle-wrapper.properties)"

# The dependency report first: it says which version of each module resolved, and a module that
# resolved to something other than <version> (a POM that still names a SNAPSHOT or an older
# release) is a failure even when it happens to compile.
./gradlew --console=plain :app:dependencies --configuration debugRuntimeClasspath > "$WORK/dependencies.txt" \
  || { cat "$WORK/dependencies.txt" >&2; fail "dependency resolution failed"; }
# An unresolvable dependency does not fail the report task, it prints FAILED beside it.
if grep -q "FAILED" "$WORK/dependencies.txt"; then
  cat "$WORK/dependencies.txt" >&2
  fail "a dependency did not resolve from mavenCentral()/google() (is $version on Maven Central yet?)"
fi
for artifact in oauth-android oauth-core dpop-android storage-android browser-android okhttp-android; do
  grep -qE "io\.versola:$artifact:$version( |$)" "$WORK/dependencies.txt" \
    || { cat "$WORK/dependencies.txt" >&2; fail "io.versola:$artifact:$version is not in the resolved runtime classpath"; }
  echo "verify-consumer: resolved io.versola:$artifact:$version"
done

./gradlew --console=plain assembleDebug
test -f app/build/outputs/apk/debug/app-debug.apk || fail "assembleDebug produced no APK"
echo "verify-consumer: android OK ($version)"
