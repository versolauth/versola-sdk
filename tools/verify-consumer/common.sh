# Shared by android.sh, android-bundle.sh, ios.sh and flutter.sh; sourced, never run. No secrets are read or needed:
# everything these scripts fetch is public.
#
# Contract of every script here: run from anywhere (they locate the repository from their own
# path), take the version or ref as the one argument, build a throwaway project in a temp
# directory outside the repository, and exit non-zero on any failure. VERIFY_KEEP=1 keeps the
# temp directory so a failure can be looked at; it is printed either way.

# The repository root, from this file's location, so the scripts work from any directory.
VERIFY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# What the scripts verify is a *published* thing: the public repository and what it released.
VERIFY_REPO_URL="https://github.com/versolauth/versola-sdk"

fail() { echo "verify-consumer: $*" >&2; exit 1; }

# X.Y.Z, no leading v: the tag is the version (docs/releasing.md). Rejecting anything else also
# keeps an argument that came from a workflow input out of a path or a manifest.
require_version() {
  [[ "${1:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "expected a version X.Y.Z (no leading v), got '${1:-}'"
}

# Makes WORK, a fresh directory outside the repository, and removes it on exit unless VERIFY_KEEP=1.
make_work_dir() {
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/verify-consumer.XXXXXX")"
  echo "verify-consumer: working in $WORK"
  if [[ "${VERIFY_KEEP:-}" == "1" ]]; then
    trap 'echo "verify-consumer: kept $WORK" >&2' EXIT
  else
    trap 'rm -rf "$WORK"' EXIT
  fi
}

# Replaces @NAME@ placeholders in every file under a directory. `sed` without -i: BSD and GNU
# disagree on its argument, and a temp file is the portable form.
render_templates() { # dir NAME=value...
  local dir="$1"; shift
  local file expr arg tmp
  expr=()
  for arg in "$@"; do
    expr+=(-e "s|@${arg%%=*}@|${arg#*=}|g")
  done
  while IFS= read -r -d '' file; do
    tmp="$file.rendered"
    sed "${expr[@]}" "$file" > "$tmp"
    mv "$tmp" "$file"
  done < <(find "$dir" -type f -print0)
}

# The throwaway Android app of templates/android, built against io.versola:oauth-android:<version>;
# shared by android.sh (after the release: Central and Google only) and android-bundle.sh (before
# the upload: the bundle for io.versola, Central and Google for the rest). The caller composes:
#
#   prepare_android_consumer <version>       a fresh app in WORK, the current directory is the app
#   set_android_repositories <text>          what the settings file's repositories block holds
#   check_android_resolution <version> <hint>   all six modules resolve at <version>
#   assemble_android_consumer                assembleDebug and the APK
#
# Gradle version, AGP and Kotlin are read from this repository, so the consumer is built with the
# toolchain the SDK is, and its wrapper is the one used, so the Gradle version (and its checksum
# policy) is the pinned one and is not chosen here a second time.

# One place to read a plugin version from: the file the whole build is pinned by. A pattern that
# stops matching must fail here, not produce an empty version in the generated project.
plugin_version() { # plugin id
  local v
  v="$(sed -n "s|.*id(\"$1\") version \"\([0-9][^\"]*\)\".*|\1|p" "$VERIFY_ROOT/android/build.gradle.kts" | head -1)"
  [[ -n "$v" ]] || fail "no version for plugin $1 in android/build.gradle.kts"
  echo "$v"
}

prepare_android_consumer() { # version
  local version="$1" agp kotlin
  [[ -n "${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}" ]] || fail "ANDROID_HOME is not set (develop.md)"
  agp="$(plugin_version com.android.application)"
  kotlin="$(plugin_version org.jetbrains.kotlin.android)"

  make_work_dir
  APP="$WORK/app"
  mkdir -p "$APP"
  cp -R "$VERIFY_ROOT/tools/verify-consumer/templates/android/." "$APP/"
  render_templates "$APP" "AGP_VERSION=$agp" "KOTLIN_VERSION=$kotlin" "VERSION=$version"
  # The unfilled settings file, so that the repositories can be set more than once.
  cp "$APP/settings.gradle.kts" "$WORK/settings.gradle.kts.template"
  # The floor the README gives an integrator, which the app must keep building against.
  grep -q 'compileSdk = 37$' "$APP/app/build.gradle.kts" || fail "the consumer app does not use compileSdk 37"

  cp "$VERIFY_ROOT/android/gradlew" "$APP/gradlew"
  mkdir -p "$APP/gradle"
  cp -R "$VERIFY_ROOT/android/gradle/wrapper" "$APP/gradle/wrapper"

  cd "$APP" || fail "cannot enter $APP"
  echo "verify-consumer: io.versola:oauth-android:$version, AGP $agp, Kotlin $kotlin, $(sed -n 's/^distributionUrl=.*gradle-\(.*\)-bin.zip/Gradle \1/p' gradle/wrapper/gradle-wrapper.properties), compileSdk 37"
}

# Fills the `__REPOSITORIES__` line of the template's settings.gradle.kts with the text given
# (ENVIRON, not `awk -v`, so a backslash in it is not interpreted).
set_android_repositories() { # repositories-text
  local file="$APP/settings.gradle.kts"
  REPOSITORIES="$1" awk '$0 == "__REPOSITORIES__" { print ENVIRON["REPOSITORIES"]; next } { print }' \
    "$WORK/settings.gradle.kts.template" > "$file"
  ! grep -q '__REPOSITORIES__' "$file" || fail "the repositories placeholder was not replaced"
}

# The dependency report says which version of each module resolved, and a module that resolved to
# something other than <version> (a POM that still names a SNAPSHOT or an older release) is a
# failure even when it happens to compile.
check_android_resolution() { # version unresolved-hint
  local version="$1" hint="$2" artifact
  ./gradlew --console=plain :app:dependencies --configuration debugRuntimeClasspath > "$WORK/dependencies.txt" \
    || { cat "$WORK/dependencies.txt" >&2; fail "dependency resolution failed"; }
  # An unresolvable dependency does not fail the report task, it prints FAILED beside it.
  if grep -q "FAILED" "$WORK/dependencies.txt"; then
    grep -B1 "FAILED" "$WORK/dependencies.txt" >&2
    fail "a dependency did not resolve ($hint)"
  fi
  # Gradle settles a conflict between two requests for a module by taking the higher, so a metadata
  # file naming an older release of a module would resolve to <version> and look fine; the report
  # still prints the request ("io.versola:oauth-core:0.1.0 -> 0.2.0"), and that is a failure too.
  if grep -E 'io\.versola:[a-z-]+:' "$WORK/dependencies.txt" | grep -vE "io\.versola:[a-z-]+:$version( |$)"; then
    fail "something under io.versola asks for a version other than $version (the lines above)"
  fi
  for artifact in oauth-android oauth-core dpop-android storage-android browser-android okhttp-android; do
    grep -qE "io\.versola:$artifact:$version( |$)" "$WORK/dependencies.txt" \
      || { cat "$WORK/dependencies.txt" >&2; fail "io.versola:$artifact:$version is not in the resolved runtime classpath"; }
    echo "verify-consumer: resolved io.versola:$artifact:$version"
  done
}

assemble_android_consumer() {
  ./gradlew --console=plain assembleDebug
  test -f app/build/outputs/apk/debug/app-debug.apk || fail "assembleDebug produced no APK"
}
