#!/usr/bin/env bash
# Builds a throwaway Swift package that depends on the PUBLISHED SDK by URL, the way an app does.
#
#   tools/verify-consumer/ios.sh 0.1.0
#
# The package has `.package(url: ".../versola-sdk", exact: "<version>")`, the product
# `VersolaOAuth`, an iOS 17.4 floor and a Swift file that does `import OAuthClient` and names
# OAuthClient and OAuthConfiguration. It is built for the iOS simulator with xcodebuild, so the
# tag must exist in the public repository, its Package.swift must parse and resolve, and the
# VersolaOAuth product (OAuthClient, OAuthCore, the Keychain, ASWebAuthenticationSession and
# Secure Enclave halves, the privacy manifest resource) must compile for iOS. Not `swift build`:
# that compiles for the macOS host, and the SDK's iOS-only code paths would not be built.
#
# Why the throwaway package's own scheme and not the SDK package's: a library product of the
# throwaway package gets its own scheme, named after the product, and builds the dependency graph
# under it.
#
# Needs macOS with Xcode and an iOS simulator runtime (develop.md).
set -euo pipefail
# shellcheck source=tools/verify-consumer/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

version="${1:-}"
require_version "$version"
[[ "$(uname -s)" == "Darwin" ]] || fail "needs macOS: xcodebuild builds for the iOS simulator"

make_work_dir
pkg="$WORK/VerifyConsumer"
mkdir -p "$pkg"
cp -R "$VERIFY_ROOT/tools/verify-consumer/templates/ios/." "$pkg/"
repo_name="$(basename "${VERIFY_REPO_URL%.git}")"
render_templates "$pkg" "REPO_URL=$VERIFY_REPO_URL" "REPO_NAME=$repo_name" "VERSION=$version"

cd "$pkg"
echo "verify-consumer: $VERIFY_REPO_URL exact $version, product VersolaOAuth"

# Resolution on its own first, so "the tag does not exist" or "the manifest does not parse" is
# reported as that and not as a wall of build output.
swift package resolve || fail "swift package resolve failed: the tag $version cannot be resolved from $VERIFY_REPO_URL"
grep -q "\"version\" : \"$version\"" Package.resolved \
  || { cat Package.resolved >&2; fail "Package.resolved does not pin $version"; }

# -derivedDataPath inside the work directory keeps the build out of the user's DerivedData.
# CODE_SIGNING_ALLOWED=NO: a library has nothing to sign and no team is needed.
xcodebuild build -quiet \
  -scheme VerifyConsumer \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath "$WORK/DerivedData" \
  CODE_SIGNING_ALLOWED=NO
echo "verify-consumer: ios OK ($version)"
