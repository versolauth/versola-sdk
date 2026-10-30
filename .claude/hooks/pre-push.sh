#!/usr/bin/env bash
# PreToolUse (Bash, only for `git push ...`): what AGENTS.md "Git" forbids of a push.
#  1. never force-push;
#  2. never push to main/master (work happens on a feature branch);
#  3. never push a release tag (X.Y.Z, a suffix allowed): pushing one runs release.yml, which signs
#     and uploads to Maven Central, and a Central release cannot be withdrawn. `--tags`,
#     `--follow-tags` and `--mirror` are refused too, since they carry tags the command does not
#     name. The operator can lift 3 for one session by exporting VERSOLA_ALLOW_RELEASE_TAG_PUSH=1
#     in the environment the hook runs in; an assignment written inside the command is not read,
#     so the agent cannot grant it to itself.
# Needs jq.
set -uo pipefail

command -v jq >/dev/null || { echo "pre-push: jq not found, push guard skipped" >&2; exit 1; }

cmd=$(jq -r '.tool_input.command // empty')
root="${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"

deny() {
  jq -n --arg r "$1" '{hookSpecificOutput:{hookEventName:"PreToolUse",permissionDecision:"deny",permissionDecisionReason:$r}}'
  exit 0
}

# Only the part from `git push` on, up to a command separator.
push=$(sed -E 's/.*(git[[:space:]]+push)/\1/; s/(\&\&|\|\||;|\|).*//' <<<"$cmd")
case "$push" in "git push"*) ;; *) exit 0 ;; esac

# 1. force
if grep -qE '(^|[[:space:]])(-f|--force|--force-with-lease(=[^[:space:]]*)?|--force-if-includes)([[:space:]]|$)' <<<"$push" \
   || grep -qE '[[:space:]]\+[^[:space:]]+' <<<"$push"; then
  deny "Force-push is not allowed (AGENTS.md Git). Ask the operator."
fi

# 2. target branch: positional args after `git push` are <remote> [<refspec>...]; no refspec means the current branch.
set -f; set -- $push; set +f   # no globbing of a `*` in a refspec against the working tree
shift 2
positional=()
for a in "$@"; do case "$a" in -*) ;; *) positional+=("$a") ;; esac; done
current=$(git -C "$root" branch --show-current 2>/dev/null)
targets=()
if [ "${#positional[@]}" -le 1 ]; then
  targets+=("$current")
else
  for spec in "${positional[@]:1}"; do
    dst="${spec##*:}"; dst="${dst#refs/heads/}"
    [ "$dst" = "HEAD" ] && dst="$current"
    targets+=("$dst")
  done
fi
for t in "${targets[@]}"; do
  case "$t" in main|master) deny "Pushing to '$t' is not allowed (AGENTS.md Git): push a feature branch and open a pull request." ;; esac
done

# 3. release tags. Spelled out in the command (`origin 0.1.1`, `refs/tags/0.1.1`, `0.1.1:0.1.1`,
# `HEAD:refs/tags/0.2.0`, `:0.1.1` for a delete, `tag 1.0.0`) or not (`'refs/tags/*:refs/tags/*'`,
# `--tags`, `--follow-tags`, `push.followTags`, a remote's configured refspec): the text of the
# command cannot show the second kind, so git is asked what it would push. A shell expansion in the
# command (`$TAG`, a command substitution) is not expanded here and cannot be checked, so it is
# refused when it appears in a refspec.
if [ "${VERSOLA_ALLOW_RELEASE_TAG_PUSH:-}" != "1" ]; then
  tag_re='^(refs/tags/)?[0-9]+\.[0-9]+\.[0-9]+'
  tag_deny="Pushing a release tag is not allowed: a pushed X.Y.Z tag runs release.yml and uploads to Maven Central, which cannot be undone (AGENTS.md Ask Before, docs/releasing.md). The maintainer tags; if the operator wants this push, they export VERSOLA_ALLOW_RELEASE_TAG_PUSH=1 in the session's environment."
  for a in "$@"; do
    case "$a" in --tags|--follow-tags|--mirror) deny "$tag_deny ($a carries every tag)." ;; esac
  done
  refs=()
  [ "${#positional[@]}" -gt 1 ] && refs=("${positional[@]:1}")
  for spec in ${refs[@]+"${refs[@]}"}; do
    case "$spec" in
      *\$*|*\`*) deny "Cannot check a refspec that contains a shell expansion ($spec): write the ref out, so the guard can tell whether it is a release tag (VERSOLA_ALLOW_RELEASE_TAG_PUSH=1 lifts the tag guard)." ;;
    esac
    spec="${spec#+}"
    for side in "${spec%%:*}" "${spec##*:}"; do
      if [[ "$side" =~ $tag_re ]]; then deny "$tag_deny"; fi
    done
  done
  # What git itself would push, globs, `tag`, followTags and configured refspecs expanded. Nothing is
  # sent; a failure (offline, rejected) still prints the lines it got to, so the exit status is ignored.
  set -f; read -ra words <<<"$push"; set +f
  words=("${words[@]//\'/}"); words=("${words[@]//\"/}")   # the quotes the shell would have removed
  dry=$(git -C "$root" push --dry-run --porcelain "${words[@]:2}" 2>/dev/null || true)
  while IFS=$'\t' read -r flag refspec _; do
    [ "$flag" = "=" ] && continue
    case "$refspec" in *:*) dst="${refspec##*:}" ;; *) continue ;; esac
    if [[ "$dst" =~ ^refs/tags/[0-9]+\.[0-9]+\.[0-9]+ ]]; then deny "$tag_deny (git would push $dst)."; fi
  done <<<"$dry"
fi
exit 0
