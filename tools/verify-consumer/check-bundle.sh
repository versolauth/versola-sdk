#!/usr/bin/env bash
# Checks an unzipped Maven Central bundle before it is uploaded, without any key.
#
#   unzip -q android/build/central-bundle/versola-0.1.0.zip -d /tmp/bundle
#   tools/verify-consumer/check-bundle.sh /tmp/bundle 0.1.0
#
# The six artefacts of the SDK are present at the version (a POM, Gradle metadata, an AAR or JAR),
# and every artefact file has a sibling .asc. Presence only: verifying the signatures needs the
# public key from a keyserver, which is Central's job, and the private key never reaches this
# script. Checksum files and the .asc files themselves are not artefacts.
set -euo pipefail
# shellcheck source=tools/verify-consumer/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

dir="${1:-}"
version="${2:-}"
[[ -d "$dir/io/versola" ]] || fail "usage: check-bundle.sh <unzipped bundle directory> X.Y.Z (no io/versola in '$dir')"
require_version "$version"

for artifact in oauth-android oauth-core dpop-android storage-android browser-android okhttp-android; do
  d="$dir/io/versola/$artifact/$version"
  [[ -d "$d" ]] || fail "the bundle has no io.versola:$artifact:$version"
  [[ -f "$d/$artifact-$version.pom" && -f "$d/$artifact-$version.module" ]] \
    || fail "io.versola:$artifact:$version lacks its POM or Gradle metadata"
  compgen -G "$d/$artifact-$version.aar" > /dev/null || compgen -G "$d/$artifact-$version.jar" > /dev/null \
    || fail "io.versola:$artifact:$version has neither an AAR nor a JAR"
done
echo "verify-consumer: the bundle holds all six modules at $version"

missing=0
while IFS= read -r -d '' file; do
  case "$file" in
    *.asc|*.md5|*.sha1|*.sha256|*.sha512) continue ;;
  esac
  [[ -f "$file.asc" ]] || { echo "verify-consumer: unsigned: ${file#"$dir"/}" >&2; missing=1; }
done < <(find "$dir/io/versola" -path "*/$version/*" -type f -print0)
[[ "$missing" == 0 ]] || fail "the bundle holds files without a PGP signature (Central rejects an unsigned deployment)"
echo "verify-consumer: every artefact file of $version has a .asc signature"
