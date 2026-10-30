# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Report it privately through GitHub: the repository's **Security** tab →
**Report a vulnerability** (private vulnerability reporting). Include what you found, how to
reproduce it, the affected package and version or commit, the platform (Android API level, iOS
version) and the impact you expect.

Targets we hold ourselves to (best effort until a response process is formalised; the same
numbers as the server's [policy](https://github.com/versolauth/versola/blob/main/SECURITY.md)):

| Step | Target |
|---|---|
| Acknowledge the report | 3 business days |
| Initial assessment and severity | 10 business days |
| Fix or mitigation for critical/high | 30 days |
| Coordinated disclosure | agreed with the reporter, normally after a fix is released |

## Supported versions

Only the latest release of each package receives security fixes. A fix ships as a new release of
the affected package; there are no backports.

## Scope

In scope: the published packages.

| Platform | Package |
|---|---|
| Android | `io.versola:oauth-android` and the modules it depends on (`oauth-core`, `dpop-android`, `storage-android`, `browser-android`, `okhttp-android`) |
| iOS | the Swift products declared in `Package.swift` |
| Flutter | `versola_oauth` |

Out of scope:

- the sample and demo apps;
- rooted or jailbroken devices running a patched binary, and a debugger attached to the app;
- findings that need the integrating app's own signing key;
- findings that need a compromised server, authorization server or administrator account (report
  those to [versolauth/versola](https://github.com/versolauth/versola)).

## What to expect from us

We credit reporters who want it, publish a GitHub security advisory for fixed vulnerabilities,
and do not take action against good-faith research that follows this policy.

## Vulnerability management

Dependabot proposes updates for Gradle, Swift Package Manager, pub, Python tooling, GitHub Actions
and the conformance container images (`.github/dependabot.yml`). Gradle resolves every artefact
against a recorded checksum (`android/gradle/verification-metadata.xml`), every action is pinned to a
commit SHA, and the Gradle dependency graph is submitted to GitHub from `security.yml`.

Scanning runs in `.github/workflows/security.yml` on pull requests, pushes to `main`, weekly
and on demand. TruffleHog checks verified secrets in PR/push commit ranges. Trivy scans the
working tree for secrets and known high/critical vulnerabilities with available fixes, and
Semgrep gates on ERROR findings. CodeQL analyzes Kotlin and Swift; dependency review gates
PRs introducing high/critical vulnerable dependencies. CodeQL and Semgrep findings appear in
the Security tab. CodeQL and dependency review require a license if the repo becomes private.

Trivy only covers supported manifests present in the checkout; it does not resolve Gradle's
transitive graph. No scanner proves the absence of vulnerabilities. Dependabot alerts and
security updates, GitHub secret scanning and push protection are enabled in repository settings.

| Severity | Fix or accept within |
|---|---|
| Critical | 7 days |
| High | 30 days |
| Medium | 90 days |

A finding is accepted rather than fixed only by recording it with the reason, the owner and a
re-evaluation date, in the tool's own suppression or an issue linked from it. Findings without a
fix upstream are tracked until one exists.
