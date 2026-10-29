#!/usr/bin/env bash
# PostToolUse (Edit|Write): a scenario under spec/conformance/ is validated the way spec.yml does
# (schema, id = file name, index row in README.md) as soon as it is written. Exit 2 sends stderr
# to Claude; a missing toolchain is reported, not treated as a pass. Needs jq and python3 with
# tools/requirements.txt installed.
set -uo pipefail

command -v jq >/dev/null || { echo "check-scenario-edit: jq not found, check skipped" >&2; exit 1; }

path=$(jq -r '.tool_input.file_path // empty')
case "$path" in
  */spec/conformance/*.yaml|*/spec/conformance/README.md|*/spec/conformance/schema.json) ;;
  *) exit 0 ;;
esac

root="${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
cd "$root" || exit 1
command -v python3 >/dev/null || { echo "check-scenario-edit: python3 not found; run 'python3 tools/validate-scenarios.py' before committing" >&2; exit 1; }

if ! out=$(python3 tools/validate-scenarios.py 2>&1); then
  case "$out" in
    *ModuleNotFoundError*|*"No module named"*)
      echo "check-scenario-edit: python dependencies missing ('pip install -r tools/requirements.txt'); scenario validation not run" >&2
      exit 1 ;;
  esac
  { echo "Scenario validation failed (spec.yml will fail the same way):"; echo "$out"; } >&2
  exit 2
fi
exit 0
