#!/usr/bin/env bash
# Waits until Maven Central serves a release of the Android SDK, then exits 0; exits 1 on timeout.
#
#   tools/verify-consumer/wait-for-central.sh 0.1.0
#
# The Central deployment is USER_MANAGED (docs/releasing.md): the release workflow uploads and
# validates the bundle, and the maintainer publishes it in the Portal with a click, which can be
# hours later. Central then needs a few more minutes before repo1.maven.org serves the files. So
# the check of what a consumer sees cannot start at the tag; this polls for the POM of the entry
# point, io.versola:oauth-android, the artefact whose POM names the other five. It asks repo1
# itself, not the Portal API: that is the host a Gradle build with mavenCentral() reads.
#
# VERIFY_POLL_INTERVAL (seconds, default 60) and VERIFY_POLL_ATTEMPTS (default 180, so three
# hours) are there so the script can be tried locally in seconds.
set -euo pipefail
# shellcheck source=tools/verify-consumer/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

version="${1:-}"
require_version "$version"
interval="${VERIFY_POLL_INTERVAL:-60}"
attempts="${VERIFY_POLL_ATTEMPTS:-180}"
[[ "$interval" =~ ^[0-9]+$ && "$attempts" =~ ^[1-9][0-9]*$ ]] || fail "VERIFY_POLL_INTERVAL and VERIFY_POLL_ATTEMPTS must be integers"

url="https://repo1.maven.org/maven2/io/versola/oauth-android/$version/oauth-android-$version.pom"
for ((attempt = 1; attempt <= attempts; attempt++)); do
  # --fail turns a 404 into a non-zero exit; a network error is retried like a 404 (the next
  # attempt is a minute away), so a blip does not end a three-hour wait.
  if curl --fail --silent --location --head --output /dev/null "$url"; then
    echo "verify-consumer: $url is on Maven Central (attempt $attempt)"
    exit 0
  fi
  echo "verify-consumer: not on Maven Central yet (attempt $attempt of $attempts): $url"
  if ((attempt < attempts)); then sleep "$interval"; fi
done
fail "io.versola:oauth-android:$version did not appear on Maven Central within $((interval * (attempts - 1))) seconds; was the deployment published in the Portal?"
