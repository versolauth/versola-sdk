#!/usr/bin/env bash
# Sets the version of the next release everywhere check-release-version.sh looks, so that the
# release is "merge this, then push the tag" and nobody edits five files by hand.
#
#   tools/prepare-release.sh 0.2.0
#
# Edits, in place: the Flutter plugin's pubspec.yaml version, the `version` and the
# `io.versola:oauth-android` pin in its android/build.gradle.kts, a `## X.Y.Z` entry at the top of
# its CHANGELOG.md (the subjects of the commits since the previous tag; edit them into prose), and
# VERSION_NAME in android/gradle.properties (X.Y.Z-SNAPSHOT: the development version may not be
# below the release). Then runs check-release-version.sh. Touches no git state and talks to no
# server: prepare-release.yml wraps it in a branch and a pull request. Run from the repository root.
set -euo pipefail

version="${1:?usage: prepare-release.sh X.Y.Z}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "not a version: '$version' (expected X.Y.Z, no leading v)" >&2
  exit 1
fi

previous="$(git describe --tags --abbrev=0 --match '[0-9]*.[0-9]*.[0-9]*' 2>/dev/null || true)"
if [[ -n "$previous" ]]; then
  highest="$(printf '%s\n%s\n' "$previous" "$version" | sort -V | tail -1)"
  if [[ "$highest" != "$version" || "$previous" == "$version" ]]; then
    echo "$version is not above the previous release $previous" >&2
    exit 1
  fi
  range="$previous..HEAD"
else
  range="HEAD"
fi
# The subjects only: a commit body is free text that ends up in a changelog.
subjects="$(git log --no-merges --pretty='- %s' "$range" -- android ios flutter spec | head -50)"

python3 -I - "$version" "$subjects" <<'PY'
import re
import sys

version, subjects = sys.argv[1], sys.argv[2]

def edit(path, pattern, replacement, count=1):
    text = open(path).read()
    new, n = re.subn(pattern, replacement, text, count=count, flags=re.M)
    if n != count:
        sys.exit(f"{path}: expected {count} match(es) of {pattern!r}, found {n}")
    open(path, "w").write(new)

edit("flutter/versola_oauth/pubspec.yaml", r"^version: .*$", f"version: {version}")
edit("flutter/versola_oauth/android/build.gradle.kts", r'^version = ".*"$', f'version = "{version}"')
edit("flutter/versola_oauth/android/build.gradle.kts",
     r'"io\.versola:oauth-android:[^"]*"', f'"io.versola:oauth-android:{version}"')
edit("android/gradle.properties", r"^VERSION_NAME=.*$", f"VERSION_NAME={version}-SNAPSHOT")

path = "flutter/versola_oauth/CHANGELOG.md"
text = open(path).read()
if re.search(rf"^## {re.escape(version)}( |$)", text, flags=re.M):
    sys.exit(f"{path}: already has an entry for {version}")
entry = f"## {version}\n\n{subjects or '- No changes recorded.'}\n\n"
open(path, "w").write(entry + text)
PY

tools/check-release-version.sh "$version"
echo "now: review the CHANGELOG.md entry, merge, then tag $version from main"
