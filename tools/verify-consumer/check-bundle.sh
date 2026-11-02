#!/usr/bin/env bash
# Checks an unzipped Maven Central bundle before it is uploaded, without any key.
#
#   unzip -q android/build/central-bundle/versola-0.1.0.zip -d /tmp/bundle
#   tools/verify-consumer/check-bundle.sh /tmp/bundle 0.1.0
#
# The SDK is one artefact, io.versola:oauth-android: the bundle holds it at the version (a POM and an
# AAR) and nothing else under io/versola, it has sources and javadoc jars, every artefact file has its
# checksums and a sibling .asc, and its POM names the tag and depends on no io.versola module (the
# other modules are inside the AAR, whose manifest carries the redirect activity). The
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

artifact=oauth-android
d="$dir/io/versola/$artifact/$version"
[[ -d "$d" ]] || fail "the bundle has no io.versola:$artifact:$version"
[[ -f "$d/$artifact-$version.pom" && -f "$d/$artifact-$version.aar" ]] \
  || fail "io.versola:$artifact:$version lacks its POM or its AAR"
others="$(find "$dir/io/versola" -mindepth 1 -maxdepth 1 -type d ! -name "$artifact")"
[[ -z "$others" ]] || fail "the bundle holds artefacts besides oauth-android (the SDK is published as one): $others"
unzip -p "$d/$artifact-$version.aar" AndroidManifest.xml | grep -q 'versola.sdk.browser.VersolaRedirectActivity' \
  || fail "the AAR's manifest does not declare VersolaRedirectActivity (the browser module was not merged)"
unzip -l "$d/$artifact-$version.aar" | grep -q ' classes.jar$' || fail "the AAR has no classes.jar"
echo "verify-consumer: the bundle holds io.versola:oauth-android:$version and nothing else"

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
for classifier in sources javadoc; do
  [[ -f "$d/$artifact-$version-$classifier.jar" ]] || fail "io.versola:$artifact:$version has no $classifier jar (Central requires it)"
done
sums=0
while IFS= read -r -d '' file; do
  case "$file" in
    *.asc|*.md5|*.sha1|*.sha256|*.sha512) continue ;;
  esac
  [[ -f "$file.md5" && -f "$file.sha1" ]] || { echo "verify-consumer: no checksums: ${file#"$dir"/}" >&2; sums=1; }
done < <(find "$dir/io/versola" -path "*/$version/*" -type f -print0)
[[ "$sums" == 0 ]] || fail "the bundle holds files without their md5 and sha1 checksums"
echo "verify-consumer: every artefact file of $version has its checksums, and the artefact its sources and javadoc"

python3 -I - "$dir" "$version" <<'PY'
import os
import sys
import xml.etree.ElementTree as ET

root, version = sys.argv[1], sys.argv[2]
ns = {"m": "http://maven.apache.org/POM/4.0.0"}
pom = os.path.join(root, "io/versola/oauth-android", version, f"oauth-android-{version}.pom")
tree = ET.parse(pom).getroot()
problems = []
own = tree.findtext("m:version", namespaces=ns)
if own != version:
    problems.append(f"the POM says version {own}, the tag says {version}")
if tree.findtext("m:packaging", namespaces=ns) != "aar":
    problems.append("the POM's packaging is not aar (a Gradle consumer would look for a jar)")
for dep in tree.findall("m:dependencies/m:dependency", ns):
    if dep.findtext("m:groupId", namespaces=ns) == "io.versola":
        problems.append(f"depends on io.versola:{dep.findtext('m:artifactId', namespaces=ns)}: the modules are inside the AAR")
if problems:
    print("verify-consumer: " + "\n verify-consumer: ".join(problems), file=sys.stderr)
    sys.exit(1)
print("verify-consumer: the POM names the tag, packages an aar and depends on no io.versola module")
PY
