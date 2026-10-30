# Shared by android.sh, ios.sh and flutter.sh; sourced, never run. No secrets are read or needed:
# everything these scripts fetch is public.
#
# Contract of every script here: run from anywhere (they locate the repository from their own
# path), take the version or ref as the one argument, build a throwaway project in a temp
# directory outside the repository, and exit non-zero on any failure. VERIFY_KEEP=1 keeps the
# temp directory so a failure can be looked at; it is printed either way.

# The repository root, from this file's location, so the scripts work from any directory.
VERIFY_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# What the scripts verify is a *published* thing. The public repository is the default; the PR
# job of flutter.yml points this at the checked-out workspace (file://) to test the commit under
# review before it is anywhere public.
VERIFY_REPO_URL="${VERIFY_REPO_URL:-https://github.com/versolauth/versola-sdk}"

fail() { echo "verify-consumer: $*" >&2; exit 1; }

# X.Y.Z, no leading v: the tag is the version (docs/releasing.md). Rejecting anything else also
# keeps an argument that came from a workflow input out of a path or a manifest.
require_version() {
  [[ "${1:-}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "expected a version X.Y.Z (no leading v), got '${1:-}'"
}

# Makes WORK, a fresh directory outside the repository, and removes it on exit unless VERIFY_KEEP=1.
make_work_dir() {
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/verify-consumer.XXXXXX")"
  echo "verify-consumer: working in $WORK"
  if [[ "${VERIFY_KEEP:-}" == "1" ]]; then
    trap 'echo "verify-consumer: kept $WORK" >&2' EXIT
  else
    trap 'rm -rf "$WORK"' EXIT
  fi
}

# Replaces @NAME@ placeholders in every file under a directory. `sed` without -i: BSD and GNU
# disagree on its argument, and a temp file is the portable form.
render_templates() { # dir NAME=value...
  local dir="$1"; shift
  local file expr arg tmp
  expr=()
  for arg in "$@"; do
    expr+=(-e "s|@${arg%%=*}@|${arg#*=}|g")
  done
  while IFS= read -r -d '' file; do
    tmp="$file.rendered"
    sed "${expr[@]}" "$file" > "$tmp"
    mv "$tmp" "$file"
  done < <(find "$dir" -type f -print0)
}
