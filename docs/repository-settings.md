# Repository settings

What the GitHub repository settings of `versolauth/versola-sdk` have to be for the release
pipeline and the scanners to mean what `docs/releasing.md`, `SECURITY.md` and
`.claude/rules/ci-release.md` say they mean. These are settings, not files: nothing in a pull
request applies them. **Nothing in this document has been applied. It is a runbook for the
repository owner**, and the commands need an admin token (`gh auth status` shows the account; the
ruleset and environment calls need the `repo` scope, which an admin has).

## Why they matter

The workflows are only as trustworthy as who can change and trigger them. As read through the API on
2026-10-30 (GET only):

- `main` has no branch protection (`GET .../branches/main/protection` answers 404). The one
  ruleset, `Default`, has empty `include` and `exclude` lists, so it targets no ref at all. Two
  collaborators (`Lekerr`, `BKJN1`) have write access, so any of them can push to `main`, or push a
  branch carrying a workflow that reads the secrets.
- The signing key and the Portal token (`MAVEN_SIGNING_KEY`, `MAVEN_SIGNING_PASSWORD`,
  `SONATYPE_USERNAME`, `SONATYPE_PASSWORD`) are repository secrets. The environment `maven-central`
  that `release.yml` names exists but has no secrets, no reviewers and no deployment policy, so its
  `environment:` line gates nothing: a workflow on any branch can read the repository secrets.
- There is no tag ruleset. A pushed `X.Y.Z` tag runs `release.yml`, signs and uploads to Maven
  Central, and a Central release cannot be withdrawn; SwiftPM and the Flutter git dependency resolve
  the same tags. `release.yml` checks the tagged commit is on `main`, which protects against
  tagging a side branch and nothing else.
- `sha_pinning_required` is `false` in the Actions permissions (every workflow is pinned to a commit
  SHA as of the branch that adds this file, so it can be switched on once that is merged).

Already fine, and worth keeping: default workflow permissions are `read`, workflows cannot approve
pull requests, secret scanning, push protection and Dependabot security updates are enabled.

All commands below use `gh api` against `repos/versolauth/versola-sdk`. Read the JSON before
running it; the first two create rulesets and can lock the owner out of `main` if edited carelessly
(the way to undo is at the end).

## 1. A ruleset for `main`

What it does: no deletion, no force-push, a pull request for every change, and the checks that run
on every pull request must pass. What it does not have, on purpose: the `update` rule. It blocks
every update of the branch except by a bypass actor, a merge of a pull request included, so a
ruleset with it locks `main` for everybody (the inert `Default` ruleset has it, and would do exactly
that the moment its `include` list were filled in).

Decisions to make before running it:

- **Reviews.** One approval and a code-owner review (`.github/CODEOWNERS` is the owner alone). The
  owner cannot approve their own pull request, so the JSON gives the repository `admin` role a
  bypass in `pull_request` mode: the owner can merge their own pull request after the checks pass,
  and cannot push to `main` directly. A second maintainer makes the bypass unnecessary; then drop
  `bypass_actors`.
- **Which checks are required.** Only a check that runs on every pull request can be required: a
  workflow skipped by its `paths:` filter leaves a required check "Expected", and the pull request
  can never merge. Those are `scenarios`, `markdown` and `workflows` (`spec.yml`) and `secrets`,
  `dependency-review`, `trivy-repo` and `semgrep` (`security.yml`). The platform checks (`build`,
  `instrumented (36)` of `android.yml`; `build` of `ios.yml`; `dart`, `android`, `ios` of
  `flutter.yml`; the `providers` rows of `conformance.yml`) are filtered by path and are **not**
  listed. To require them, either remove the `paths:` filters or add one always-running job that
  `needs:` them with `if: always()` and fails when a needed job failed, and require that job.
- **Names are not unique.** `build` is the job name in `android.yml` and in `ios.yml`, and
  `scenarios` in `spec.yml` and in `conformance.yml` (the second is skipped on pull requests, which
  counts as passing). A ruleset matches on the name, so a required `scenarios` is satisfied or
  failed by both; this is workable and confusing, and a rename of one job is the clean fix.
- **CodeQL** is not required: the PR run has one matrix row named `codeql (java-kotlin,
  ubuntu-latest)` and `security.yml` has not run since 22007e9, so the name is unconfirmed. Look at
  a pull request's check list after the first green `security.yml` and add it.
- `integration_id` 15368 is GitHub Actions: only a check posted by it satisfies the rule, a status
  posted by any other app under the same name does not.

```bash
cat > /tmp/ruleset-main.json <<'JSON'
{
  "name": "main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "bypass_actors": [
    { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request" }
  ],
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 1,
        "dismiss_stale_reviews_on_push": true,
        "require_code_owner_review": true,
        "require_last_push_approval": false,
        "required_review_thread_resolution": true
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": false,
        "required_status_checks": [
          { "context": "scenarios", "integration_id": 15368 },
          { "context": "markdown", "integration_id": 15368 },
          { "context": "workflows", "integration_id": 15368 },
          { "context": "secrets", "integration_id": 15368 },
          { "context": "dependency-review", "integration_id": 15368 },
          { "context": "trivy-repo", "integration_id": 15368 },
          { "context": "semgrep", "integration_id": 15368 }
        ]
      }
    }
  ]
}
JSON
gh api -X POST repos/versolauth/versola-sdk/rulesets --input /tmp/ruleset-main.json
# the inert one, once the new one is confirmed active:
gh api -X DELETE repos/versolauth/versola-sdk/rulesets/26187436
```

`actor_id` 5 is the built-in `admin` repository role. Dependabot and other write-access bots get no
bypass and go through the pull request like anyone else.

## 2. A ruleset for release tags

The tag is the release. This restricts who can create one, and stops one being moved or deleted
afterwards (a moved tag would make SwiftPM, the Flutter git dependency and the GitHub release
disagree about what `0.1.1` is). The pattern is the one `release.yml` is triggered by, in the
ruleset's `fnmatch` syntax (a suffix such as `-rc1` also matches here, and is not released by
`release.yml`: that stays the maintainer's to avoid). The admin role bypasses `always`, because
the maintainer creates the tag; the `release.yml` job never creates one (`gh release create
--verify-tag` needs it to exist), and the `prepare-release` workflow only opens a pull request.

```bash
cat > /tmp/ruleset-tags.json <<'JSON'
{
  "name": "release tags",
  "target": "tag",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["refs/tags/[0-9]*.[0-9]*.[0-9]*"], "exclude": [] } },
  "bypass_actors": [
    { "actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always" }
  ],
  "rules": [
    { "type": "creation" },
    { "type": "update" },
    { "type": "deletion" }
  ]
}
JSON
gh api -X POST repos/versolauth/versola-sdk/rulesets --input /tmp/ruleset-tags.json
```

Consequence for the runbook in `docs/releasing.md` ("a run that fails leaves the tag... delete the
tag and tag again"): the owner deletes and re-creates through the bypass; nobody else can. Check
that `0.1.0` is not affected: existing tags are not renamed by a ruleset, they only become
undeletable and unmovable by non-admins.

## 3. Move the release secrets into the `maven-central` environment

Today any job on any branch of the repository can read the four secrets. Environment secrets are
released to a job only after the environment's rules pass, so with reviewers and a tag policy a
branch pushed by a writer cannot get at the signing key at all, and a release waits for a person.

1. Decide the reviewers: the owner's user id is `134854076` (`gh api users/<login> -q .id` for
   anyone else). With a single maintainer, `prevent_self_review` has to stay `false`, or nobody can
   approve their own release; with two, set it `true`.
2. Create the environment's protection (a `PUT`, which replaces the environment's settings):

   ```bash
   cat > /tmp/env-maven-central.json <<'JSON'
   {
     "wait_timer": 0,
     "prevent_self_review": false,
     "can_admins_bypass": false,
     "reviewers": [ { "type": "User", "id": 134854076 } ],
     "deployment_branch_policy": { "protected_branches": false, "custom_branch_policies": true }
   }
   JSON
   gh api -X PUT repos/versolauth/versola-sdk/environments/maven-central --input /tmp/env-maven-central.json
   gh api -X POST repos/versolauth/versola-sdk/environments/maven-central/deployment-branch-policies \
     -f name='[0-9]*.[0-9]*.[0-9]*' -f type=tag
   ```

   `release.yml` runs on a tag, so the policy names tags (a branch policy would refuse the run). A
   job started by a branch push that names `environment: maven-central` is refused.
3. Add the secrets to the environment, then delete the repository ones. `gh secret set` prompts for
   the value (or reads stdin): do not put a value on a command line, in a file in the repository or
   in a chat.

   ```bash
   for s in MAVEN_SIGNING_KEY MAVEN_SIGNING_PASSWORD SONATYPE_USERNAME SONATYPE_PASSWORD; do
     gh secret set "$s" --env maven-central --repo versolauth/versola-sdk
   done
   # after a release with the new setup has run green, not before:
   for s in MAVEN_SIGNING_KEY MAVEN_SIGNING_PASSWORD SONATYPE_USERNAME SONATYPE_PASSWORD; do
     gh secret delete "$s" --repo versolauth/versola-sdk
   done
   ```

   The key is the one `docs/releasing.md` ("One-time setup", step 3) describes. If the repository
   secrets have been readable by writers until now, consider whether the signing key and the
   Portal token should be rotated rather than moved; that is the owner's call and not something this
   file can judge.
4. `COCOAPODS_TRUNK_TOKEN` and `NPM_TOKEN` do not exist (those jobs are `if: false`); when one is
   created it goes into its own environment the same way. pub.dev's tag-based login uses the
   `pub.dev` environment `docs/releasing.md` mentions.

The variable `MAVEN_CENTRAL_PUBLISHING_TYPE` (`USER_MANAGED` unless set to `AUTOMATIC`) can stay a
repository variable: it is not a secret, but an `AUTOMATIC` value removes the Portal click, so the
people who can change it should be the people who can approve the environment.

## 4. Require SHA-pinned actions

Every workflow pins every action to a full commit SHA with the version in a comment, and `spec.yml`'s
`workflows` job lints them. Making the platform enforce it means a workflow that names a tag
(`actions/checkout@v7`) fails to start, whoever wrote it. Do it after the pinning change is merged,
or every workflow currently on `main` that is not pinned stops.

```bash
gh api -X PUT repos/versolauth/versola-sdk/actions/permissions \
  -F enabled=true -f allowed_actions=all -F sha_pinning_required=true
```

Dependabot's `github-actions` entry bumps the SHA and the comment together.

## Check it

```bash
gh api repos/versolauth/versola-sdk/rulesets -q '.[] | {id, name, target, enforcement}'
gh api repos/versolauth/versola-sdk/rules/branches/main -q '[.[].type]'
gh api repos/versolauth/versola-sdk/environments/maven-central \
  -q '{protection_rules: [.protection_rules[].type], deployment_branch_policy, can_admins_bypass}'
gh api repos/versolauth/versola-sdk/environments/maven-central/deployment-branch-policies -q '.branch_policies'
gh api repos/versolauth/versola-sdk/actions/permissions -q .sha_pinning_required
gh api repos/versolauth/versola-sdk/actions/secrets -q '[.secrets[].name]'     # no MAVEN_* or SONATYPE_*
gh api repos/versolauth/versola-sdk/actions/secrets/MAVEN_SIGNING_KEY          # 404 once moved
```

Then try the settings, in a throwaway pull request and a throwaway tag in a fork or after the next
real release: a push to `main` from a non-admin is refused, a pull request without the required
checks cannot merge, a tag push by a non-admin is refused, and a run of `release.yml` stops at
`maven-central` waiting for approval.

## Undo

```bash
gh api repos/versolauth/versola-sdk/rulesets -q '.[] | "\(.id) \(.name)"'
gh api -X DELETE repos/versolauth/versola-sdk/rulesets/<id>
gh api -X PUT repos/versolauth/versola-sdk/actions/permissions -F enabled=true -f allowed_actions=all -F sha_pinning_required=false
gh api -X DELETE repos/versolauth/versola-sdk/environments/maven-central   # also removes its secrets
```

## What this does not cover

A second maintainer, signed commits (`required_signatures`) and linear history are policy choices
and are not in the rulesets above. The `.github/CODEOWNERS` file only has force once the pull
request rule requires a code-owner review, which is what section 1 turns on. The organisation's
Actions policy (an allow-list of actions, fork pull-request approval) is read at the organisation
level and was not readable with the token this was written with.
