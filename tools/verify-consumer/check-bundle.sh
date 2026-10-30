#!/usr/bin/env bash
# Checks an unzipped Maven Central bundle before it is uploaded, without any key.
#
#   unzip -q android/build/central-bundle/versola-0.1.0.zip -d /tmp/bundle
#   tools/verify-consumer/check-bundle.sh /tmp/bundle 0.1.0
#
# The six artefacts of the SDK are present at the version (a POM, Gradle metadata, an AAR or JAR),
# each has sources and javadoc jars, every artefact file has its checksums and a sibling .asc, and
# every POM names the tag and depends only on io.versola modules that are in the bundle. The
# signatures are checked for presence only: verifying them needs the public key from a keyserver,
# which is Central's job, and the private key never reaches this script. Checksum files and the
# .asc files themselves are not artefacts.
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

# Sources and javadoc jars (Central requires both) and the checksums Central verifies, beside every
# artefact file; and the POMs: each names its own version as the tag and depends only on io.versola
# modules that are in this same bundle, at the same version. A POM that still said a SNAPSHOT or an
# older release, or named a module the bundle lacks, resolves on nobody's machine.
for artifact in oauth-android oauth-core dpop-android storage-android browser-android okhttp-android; do
  d="$dir/io/versola/$artifact/$version"
  for classifier in sources javadoc; do
    [[ -f "$d/$artifact-$version-$classifier.jar" ]] || fail "io.versola:$artifact:$version has no $classifier jar (Central requires it)"
  done
done
sums=0
while IFS= read -r -d '' file; do
  case "$file" in
    *.asc|*.md5|*.sha1|*.sha256|*.sha512) continue ;;
  esac
  [[ -f "$file.md5" && -f "$file.sha1" ]] || { echo "verify-consumer: no checksums: ${file#"$dir"/}" >&2; sums=1; }
done < <(find "$dir/io/versola" -path "*/$version/*" -type f -print0)
[[ "$sums" == 0 ]] || fail "the bundle holds files without their md5 and sha1 checksums"
echo "verify-consumer: every artefact file of $version has its checksums, and every module its sources and javadoc"

python3 -I - "$dir" "$version" <<'PY'
import os
import sys
import xml.etree.ElementTree as ET

root, version = sys.argv[1], sys.argv[2]
ns = {"m": "http://maven.apache.org/POM/4.0.0"}
modules = ["oauth-android", "oauth-core", "dpop-android", "storage-android", "browser-android", "okhttp-android"]
problems = []
for artifact in modules:
    pom = os.path.join(root, "io/versola", artifact, version, f"{artifact}-{version}.pom")
    tree = ET.parse(pom).getroot()
    own = tree.findtext("m:version", namespaces=ns)
    if own != version:
        problems.append(f"{artifact}: the POM says version {own}, the tag says {version}")
    for dep in tree.findall("m:dependencies/m:dependency", ns):
        if dep.findtext("m:groupId", namespaces=ns) != "io.versola":
            continue
        name = dep.findtext("m:artifactId", namespaces=ns)
        wanted = dep.findtext("m:version", namespaces=ns)
        if wanted != version:
            problems.append(f"{artifact}: depends on io.versola:{name}:{wanted}, not {version}")
        if not os.path.isdir(os.path.join(root, "io/versola", name, wanted or version)):
            problems.append(f"{artifact}: depends on io.versola:{name}:{wanted}, which is not in the bundle")
if problems:
    print("verify-consumer: " + "\n verify-consumer: ".join(problems), file=sys.stderr)
    sys.exit(1)
print("verify-consumer: every POM names the tag and every io.versola dependency is in the bundle")
PY
