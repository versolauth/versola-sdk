#!/usr/bin/env bash
# Builds a throwaway Flutter app that depends on the plugin by GIT, the way an app does today.
#
#   tools/verify-consumer/flutter.sh 0.1.0                        # the release tag, from GitHub
#   VERIFY_REPO_URL="file://$PWD" tools/verify-consumer/flutter.sh "$(git rev-parse HEAD)"  # a commit
#
# `flutter create` makes the app, `flutter pub add versola_oauth --git-url <repo> --git-path
# flutter/versola_oauth --git-ref <ref>` adds the plugin, Android gets compileSdk 37 and minSdk 26
# and iOS the 17.4 deployment target (README.md: what an integrator sets), and the app is built
# with `flutter build apk --debug` and, on macOS, `flutter build ios --no-codesign --debug`.
#
# Why this exists: the example app lives inside the checkout, so it cannot show a break that only
# appears when the plugin is somewhere else. Flutter symlinks the plugin into the app and
# SwiftPM resolved the plugin's relative `path:` against that symlink; the checkout built, the git
# dependency did not (the fix is in flutter/versola_oauth/ios/versola_oauth/Package.swift, and this
# script is the check that would have caught it). Pass a commit SHA with VERIFY_REPO_URL=file://...
# to test a change before it is pushed anywhere, or the tag to test what was released.
#
# Needs the Flutter version pinned in flutter/.fvmrc (CI installs it with subosito/flutter-action;
# locally the script also finds ~/fvm/versions/<version>), JDK 21 on JAVA_HOME and ANDROID_HOME
# for the APK, Xcode for the iOS build.
set -euo pipefail
# shellcheck source=tools/verify-consumer/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

ref="${1:-}"
# A tag, a branch or a SHA. The leading character is restricted so the value can never be read as
# an option by git or pub.
[[ "$ref" =~ ^[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || fail "expected a git ref (tag, branch or SHA), got '${ref}'"

# flutter/.fvmrc is the one place the version is chosen (develop.md). Reading it with jq is what
# flutter.yml does; sed keeps this script free of a tool the macOS image may lack.
pinned="$(sed -n 's/.*"flutter"[[:space:]]*:[[:space:]]*"\([0-9][0-9.]*\)".*/\1/p' "$VERIFY_ROOT/flutter/.fvmrc")"
[[ -n "$pinned" ]] || fail "no Flutter version in flutter/.fvmrc"
if [[ -x "$HOME/fvm/versions/$pinned/bin/flutter" ]]; then
  PATH="$HOME/fvm/versions/$pinned/bin:$PATH"
fi
command -v flutter > /dev/null || fail "flutter is not on PATH (pinned: $pinned)"
actual="$(flutter --version --machine | sed -n 's/.*"frameworkVersion"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
[[ "$actual" == "$pinned" ]] || fail "Flutter $actual is installed, flutter/.fvmrc pins $pinned"

# Which halves to build: "android ios" by default. A pull request builds only "ios": the plugin's
# Android half resolves the PUBLISHED io.versola:oauth-android that its build.gradle.kts pins, so a
# commit that already uses native API the last release lacks cannot build as a git dependency
# until the release exists (the example app's APK in flutter.yml covers Android in the pull request,
# against the checkout's own build). The release check builds both.
platforms="${VERIFY_PLATFORMS:-android ios}"
for platform in $platforms; do
  [[ "$platform" == android || "$platform" == ios ]] || fail "VERIFY_PLATFORMS names android and/or ios, got '$platform'"
done

make_work_dir
cd "$WORK"
echo "verify-consumer: plugin $VERIFY_REPO_URL @ $ref, Flutter $pinned, platforms: $platforms"

flutter create --org com.example --platforms android,ios verify_app > "$WORK/create.log" 2>&1 \
  || { cat "$WORK/create.log" >&2; fail "flutter create failed"; }
cd verify_app

# `pub add` writes the git dependency in the form pubspec.yaml documents and runs `pub get`, which
# is where a ref that does not exist, or a pubspec.yaml that does not parse at that ref, fails.
flutter pub add versola_oauth \
  --git-url "$VERIFY_REPO_URL" --git-path flutter/versola_oauth --git-ref "$ref"

# Android: the plugin compiles against 37 and so must the app (flutter.compileSdkVersion is lower
# under the pinned Flutter). Every substitution is checked, so a template that moves in a later
# Flutter fails here instead of silently building with the wrong floor.
gradle_file=android/app/build.gradle.kts
[[ -f "$gradle_file" ]] || fail "$gradle_file not found: the Flutter app template changed"
sed -e 's|compileSdk = .*|compileSdk = 37|' -e 's|minSdk = .*|minSdk = 26|' "$gradle_file" > "$gradle_file.new"
mv "$gradle_file.new" "$gradle_file"
grep -q 'compileSdk = 37' "$gradle_file" && grep -q 'minSdk = 26' "$gradle_file" \
  || fail "could not set compileSdk 37 / minSdk 26 in $gradle_file"

# iOS: the plugin's Package.swift declares 17.4, and SwiftPM refuses a lower app target.
sed 's|IPHONEOS_DEPLOYMENT_TARGET = [0-9.]*;|IPHONEOS_DEPLOYMENT_TARGET = 17.4;|' ios/Runner.xcodeproj/project.pbxproj > ios/Runner.xcodeproj/project.pbxproj.new
mv ios/Runner.xcodeproj/project.pbxproj.new ios/Runner.xcodeproj/project.pbxproj
grep -q 'IPHONEOS_DEPLOYMENT_TARGET = 17.4;' ios/Runner.xcodeproj/project.pbxproj \
  || fail "could not set the iOS deployment target in project.pbxproj"

flutter pub get

if [[ " $platforms " == *" android "* ]]; then
  echo "verify-consumer: flutter build apk --debug"
  flutter build apk --debug
  test -f build/app/outputs/flutter-apk/app-debug.apk || fail "flutter build apk produced no APK"
fi

if [[ " $platforms " != *" ios "* ]]; then
  echo "verify-consumer: the iOS build is not requested"
elif [[ "$(uname -s)" == "Darwin" ]]; then
  echo "verify-consumer: flutter build ios --no-codesign --debug"
  flutter build ios --no-codesign --debug
else
  echo "verify-consumer: not macOS, skipping the iOS build"
fi
echo "verify-consumer: flutter OK ($ref)"
