#!/usr/bin/env bash
# PostToolUse (Edit|Write): the protocol core stays plain JVM. `android/core` and `android/okhttp`
# contain no `android.*` import today (architecture review 2026-10-12, section 4), which is what
# keeps the core convertible to a Kotlin/JVM module and, later, shareable; `android/oauth-core`
# (issue #46) is JVM by construction. Run on the file just written so the mistake is seen at once.
# Exit 2 sends stderr to Claude. Needs jq.
set -uo pipefail

command -v jq >/dev/null || { echo "check-core-purity: jq not found, check skipped" >&2; exit 1; }

path=$(jq -r '.tool_input.file_path // empty')
case "$path" in
  */android/core/src/main/*.kt|*/android/okhttp/src/main/*.kt|*/android/oauth-core/src/main/*.kt) ;;
  *) exit 0 ;;
esac
[ -f "$path" ] || exit 0

hits=$(grep -nE '^import (android|androidx)\.' "$path")
if [ -n "$hits" ]; then
  {
    echo "Android framework import in the protocol core; it must stay plain JVM (.claude/rules/android-kotlin.md). Move the platform half to :storage, :browser, :dpop or the facade module:"
    echo "$hits"
  } >&2
  exit 2
fi
exit 0
