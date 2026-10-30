# Documentation

The SDK documentation will be hosted at <https://docs.versola.kz>; today that site documents the
Versola server and has no SDK section. Until the SDK section exists, this repository is the
source: this directory, [`spec/`](../spec/) and the per-platform READMEs.

## Guides

- [`providers/`](providers/): setup guides for each provider the generic `OAuthClient` is used
  with. The capability matrix and the documented limits they rest on are in
  [`spec/providers.md`](../spec/providers.md).
- [`migrating-from-appauth.md`](migrating-from-appauth.md): moving an app from AppAuth to the
  generic SDK.

- [`releasing.md`](releasing.md): the maintainer's runbook for a release (Maven Central, Swift
  Package Manager, pub.dev) and what has to exist before the first one.

## Decision records

- [`adr/0001-generic-sdk-naming-and-layering.md`](adr/0001-generic-sdk-naming-and-layering.md):
  what the generic SDK is called on each registry, and which code the two facades share.

## Reviews

- [`reviews/architecture-review-2026-10-12.md`](reviews/architecture-review-2026-10-12.md): the
  architecture review whose findings (F1, F5, F9, F11 and others) the code and the rules cite.
- [`reviews/code-review-2026-10-12.md`](reviews/code-review-2026-10-12.md): the code review of the
  same date.

## Elsewhere in the repository

- Root [`README.md`](../README.md): status per platform and a quick start.
- Platform READMEs: [`android/README.md`](../android/README.md),
  [`ios/README.md`](../ios/README.md),
  [`flutter/versola_oauth/README.md`](../flutter/versola_oauth/README.md).
- [`spec/`](../spec/): the normative specification (API, state machine, errors, retry policy,
  provider matrix, conformance scenarios).
- [`conformance/README.md`](../conformance/README.md): what each test tier proves.
- [`develop.md`](../develop.md), [`AGENTS.md`](../AGENTS.md), [`REVIEW.md`](../REVIEW.md) and
  [`SECURITY.md`](../SECURITY.md).
