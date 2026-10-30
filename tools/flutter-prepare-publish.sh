#!/usr/bin/env bash
# Makes the Flutter plugin consumable from pub.dev: its iOS half depends on this repository's
# Swift package by path (../../../..), which exists only inside a checkout. In a published package
# it has to be the release tag.
#
#   tools/flutter-prepare-publish.sh 0.1.0
#
# Rewrites flutter/versola_oauth/ios/versola_oauth/Package.swift in place; nothing else. The
# repository must be reachable by the consumer's SwiftPM (public) for the published plugin to
# resolve: docs/releasing.md. Run from the repository root; the change is for the publishing job's
# working copy and is not committed.
set -euo pipefail

version="${1:?usage: flutter-prepare-publish.sh X.Y.Z}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "not a version: '$version'" >&2
  exit 1
fi

python3 -I - "$version" <<'PY'
import re
import sys

version = sys.argv[1]
path = "flutter/versola_oauth/ios/versola_oauth/Package.swift"
text = open(path).read()

local = '.package(name: "Versola", path: "../../../..")'
remote = f'.package(url: "https://github.com/versolauth/versola-sdk", exact: "{version}")'
if local not in text:
    sys.exit(f"{path}: the path dependency on the repository package is not where this script expects it")
text = text.replace(local, remote)

# A package named by URL has the identity of the last path component of the URL.
product = '.product(name: "VersolaOAuth", package: "Versola")'
if product not in text:
    sys.exit(f"{path}: the VersolaOAuth product reference is not where this script expects it")
text = text.replace(product, '.product(name: "VersolaOAuth", package: "versola-sdk")')

open(path, "w").write(text)
print(f"{path}: depends on versola-sdk {version} by URL")
PY
