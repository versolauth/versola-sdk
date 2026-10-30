#!/usr/bin/env bash
# Refuses a release tag that disagrees with what the three platforms would publish.
#
#   tools/check-release-version.sh 0.1.0
#
# One version for every platform while the project is 0.x (docs/releasing.md): the Android
# artefacts take it from the tag (-PreleaseVersion), SwiftPM resolves the tag itself, and pub.dev
# publishes what flutter/versola_oauth/pubspec.yaml says. The last is the one that can drift,
# along with the Android coordinate the Flutter plugin pins, so this reads those two files and the
# changelog and fails on any disagreement. Run from the repository root; reads files only.
set -euo pipefail

tag="${1:?usage: check-release-version.sh X.Y.Z}"
if [[ ! "$tag" =~ ^([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
  echo "not a release tag: '$tag' (expected X.Y.Z, no leading v)" >&2
  exit 1
fi
version="${BASH_REMATCH[1]}"

fail=0
check() { # description, actual
  if [[ "$2" != "$version" ]]; then
    echo "mismatch: $1 is '$2', the tag says '$version'" >&2
    fail=1
  fi
}

pubspec="$(sed -n 's/^version: *//p' flutter/versola_oauth/pubspec.yaml | head -1 | tr -d '\r')"
check "flutter/versola_oauth/pubspec.yaml version" "$pubspec"

pinned="$(sed -n 's/.*"io\.versola:oauth-android:\([^"]*\)".*/\1/p' flutter/versola_oauth/android/build.gradle.kts | head -1)"
check "the oauth-android version the Flutter plugin depends on" "$pinned"

gradle_version="$(sed -n 's/^version = "\(.*\)"$/\1/p' flutter/versola_oauth/android/build.gradle.kts | head -1)"
check "the version in flutter/versola_oauth/android/build.gradle.kts" "$gradle_version"

if ! grep -qE "^## ${version//./\\.}( |$)" flutter/versola_oauth/CHANGELOG.md; then
  echo "mismatch: flutter/versola_oauth/CHANGELOG.md has no '## $version' entry" >&2
  fail=1
fi

# The development version moves ahead of the last release; it must never be below this one.
dev="$(sed -n 's/^VERSION_NAME=//p' android/gradle.properties | head -1)"
dev_base="${dev%-SNAPSHOT}"
lowest="$(printf '%s\n%s\n' "$dev_base" "$version" | sort -V | head -1)"
if [[ "$lowest" != "$version" ]]; then
  echo "mismatch: android/gradle.properties VERSION_NAME is '$dev', below the release '$version'" >&2
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi
echo "release $version is consistent: pubspec, plugin pin, changelog, development version"
