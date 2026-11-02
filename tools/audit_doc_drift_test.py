#!/usr/bin/env python3
"""Audit tests for documentation / spec / source drift (audit items D5a, D6 to D11).

Run from anywhere:  python3 -I tools/audit_doc_drift_test.py

Every test asserts the CORRECT, consistent state and is expected to FAIL until the drift it
names is fixed. A test marked "design" asserts one of two reasonable outcomes (the proposed one).
Nothing here edits the README, the spec or the sources; it only reads them.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def squash(text: str) -> str:
    """Collapse whitespace so a sentence wrapped over two lines still matches."""
    return re.sub(r"\s+", " ", text)


class D5Readme(unittest.TestCase):
    def test_audit_d5_readme_names_the_redirect_activity_and_assetlinks(self):
        """AUDIT: D5. The Android quick start never says the app must declare an intent filter on
        VersolaRedirectActivity (and, for an https redirect, publish assetlinks.json)."""
        readme = read("README.md")
        self.assertIn("VersolaRedirectActivity", readme)
        self.assertIn("assetlinks", readme)


class D6Ios(unittest.TestCase):
    def test_audit_d6_readme_names_the_webcredentials_associated_domain(self):
        """AUDIT: D6. An https callback on iOS needs the `webcredentials` associated-domains
        service (docs/reviews/architecture-review-2026-10-12.md F11, REVIEW.md); the README is silent."""
        self.assertIn("webcredentials", read("README.md"))


class D7SpecDrift(unittest.TestCase):
    def test_audit_d7_spec_does_not_claim_a_kotlin_oauth_error_class_that_does_not_exist(self):
        """AUDIT: D7. spec/errors.md's Kotlin column says `sealed class OAuthError` with VersolaError
        an alias; the code has only VersolaError."""
        errors = read("spec/errors.md")
        claims = "`sealed class OAuthError` (`VersolaError` is a type alias" in errors
        defined = any(
            re.search(r"\b(sealed )?class OAuthError\b|typealias VersolaError", p.read_text(encoding="utf-8"))
            for p in (ROOT / "android").rglob("*.kt")
            if "/src/main/" in str(p)
        )
        self.assertTrue(defined or not claims, "spec claims Kotlin `OAuthError`; no such class or alias in android/*/src/main")

    def test_audit_d7_dart_error_names_in_spec_match_the_dart_classes(self):
        """AUDIT: D7. spec/errors.md's Dart column says Recoverable/Reauthenticate/StepUp/Configuration;
        the Dart classes are RecoverableError, ReauthenticateError, StepUpError, ConfigurationError."""
        errors = read("spec/errors.md")
        dart = "\n".join(p.read_text(encoding="utf-8") for p in (ROOT / "flutter/versola_oauth/lib").rglob("*.dart"))
        rows = [line for line in errors.splitlines() if re.match(r"\| (Recoverable|Reauthenticate|Step-up|Configuration) \|", line)]
        self.assertEqual(4, len(rows), "the platform-mapping rows moved")
        wrong = []
        for row in rows:
            dart_cell = row.split("|")[4].strip().strip("`")
            name = dart_cell.split("(")[0]
            if not re.search(rf"\bclass {name}\b", dart):
                wrong.append(f"{name} (spec) has no Dart class of that name")
        self.assertEqual([], wrong)

    def test_audit_d7_pending_request_expiry_cause_is_named_as_in_code(self):
        """AUDIT: D7. spec/errors.md:194 says `Recoverable`, cause `Expired`; the cause is
        PendingRequestExpired everywhere else."""
        self.assertNotRegex(read("spec/errors.md"), r"cause `Expired`")

    def test_audit_d7_spec_does_not_call_plain_classes_data_classes(self):
        """AUDIT: D7. spec/oauth-sdk-api.md section 13 says `OAuthConfiguration(...)` data class and
        `LoginOptions` data class; the Kotlin types are plain classes (no equals/copy promised)."""
        spec = read("spec/oauth-sdk-api.md")
        for name, path in (
            ("OAuthConfiguration", "android/oauth/src/main/kotlin/versola/oauth/OAuthConfiguration.kt"),
            ("LoginOptions", "android/oauth/src/main/kotlin/versola/oauth/LoginOptions.kt"),
        ):
            says_data = re.search(rf"`{name}(\(\.\.\.\))?` data class", spec) is not None
            is_data = re.search(rf"\bdata class {name}\b", read(path)) is not None
            self.assertTrue(is_data or not says_data, f"spec says `{name}` is a data class; the source declares a plain class")

    def test_audit_d7_jwks_uri_is_not_optional_in_spec_when_code_requires_it(self):
        """AUDIT: D7. spec/oauth-sdk-api.md:56 lists an optional `jwksUri`; ProviderEndpoints.jwksUri is
        a required, non-null constructor parameter ("an ID token that cannot be verified is refused")."""
        required = re.search(r"public val jwksUri: String,", read("android/oauth/src/main/kotlin/versola/oauth/OAuthConfiguration.kt"))
        optional_in_spec = re.search(r"optional `jwksUri`", read("spec/oauth-sdk-api.md"))
        self.assertFalse(required and optional_in_spec, "spec says jwksUri is optional; the code requires it")

    def test_audit_d7_core_kdoc_does_not_name_configure_for_the_generic_facade(self):
        """AUDIT: D7. VersolaError.InvalidConfiguration (VersolaError.kt:253) and RetryPolicy.Default
        (RetryPolicy.kt:87) are shared by both facades but their KDoc names only `configure()`, which
        the generic facade (OAuthClient.create) does not have. Expected: neutral or both names.
        (spec/errors.md:190 is about BackChannel.Edge, a Versola-facade rule, where configure() is real.)"""
        for path in ("android/oauth-core/src/main/kotlin/versola/oauth/core/VersolaError.kt",
                     "android/oauth-core/src/main/kotlin/versola/oauth/core/RetryPolicy.kt"):
            for line in read(path).splitlines():
                if "`configure()`" in line:
                    self.assertIn("create(", line, f"{path}: `configure()` only: {line.strip()}")

    def test_audit_d7_offline_access_warning_location_agrees_between_spec_files(self):
        """AUDIT: D7. oauth-sdk-api.md section 8 says the warning is logged once at create();
        providers.md says at the first login; the code (SessionCoordinator.login) does the latter."""
        api = squash(read("spec/oauth-sdk-api.md"))
        providers = squash(read("spec/providers.md"))
        api_where = re.search(r"logs once, at (`create\(\)`|the first login)", api)
        prov_where = re.search(r"warns once, at (`create\(\)`|the first login)", providers)
        self.assertIsNotNone(api_where, "oauth-sdk-api.md wording changed")
        self.assertIsNotNone(prov_where, "providers.md wording changed")
        self.assertEqual(api_where.group(1), prov_where.group(1))

    def test_audit_d7_errors_spec_does_not_say_android_userinfo_has_no_dpop_retry(self):
        """AUDIT: D7. spec/errors.md:119 says the Android UserInfo client does not retry
        InvalidDpopProof yet; HttpUserInfoClient handles Outcome.InvalidDpopProof with a retry."""
        implemented = "Outcome.InvalidDpopProof ->" in read("android/oauth-core/src/main/kotlin/versola/oauth/core/UserInfo.kt")
        stale = "the Android UserInfo client does not retry yet" in squash(read("spec/errors.md"))
        self.assertFalse(implemented and stale, "stale sentence: the Android UserInfo client does retry")


class D8DocHygiene(unittest.TestCase):
    def test_audit_d8_no_garbled_redacted_text_in_sources_or_spec(self):
        """AUDIT: D8. TokenBinding.kt:7,17,26 and spec/state-machine.md:248 contain '[redacted]'
        where a word was scrubbed ("bearer [redacted]]]]]]"); documentation must read."""
        offenders = []
        for rel in ("android/oauth-core/src/main/kotlin/versola/oauth/core/TokenBinding.kt", "spec/state-machine.md"):
            for number, line in enumerate(read(rel).splitlines(), 1):
                if "[redacted" in line:
                    offenders.append(f"{rel}:{number}")
        self.assertEqual([], offenders)

    def test_audit_d8_dpop_kdoc_does_not_claim_to_be_the_default(self):
        """AUDIT: D8 (design). TokenBinding.Dpop's KDoc says "The default. DPoP whenever the provider
        advertises it"; the generic facade's default is Bearer (OAuthConfiguration.tokenBinding)."""
        source = read("android/oauth-core/src/main/kotlin/versola/oauth/core/TokenBinding.kt")
        kdoc = re.search(r"/\*\*((?:(?!\*/).)*?)\*/\s*public data class Dpop", source, re.S).group(1)
        self.assertNotRegex(kdoc, r"The default\.\s*\*?\s*DPoP whenever")

    def test_audit_d8_okhttp_pin_comment_matches_the_pinned_version(self):
        """AUDIT: D8. oauth-core/build.gradle.kts says "the same 5.4.0 pin" but depends on OkHttp 5.5.1."""
        gradle = read("android/oauth-core/build.gradle.kts")
        pinned = re.search(r'com\.squareup\.okhttp3:okhttp:([\d.]+)"', gradle).group(1)
        for stated in re.findall(r"(\d+\.\d+\.\d+) pin", gradle):
            self.assertEqual(pinned, stated, "a comment names another OkHttp version than the dependency line")

    def test_audit_d8_flutter_android_gradle_does_not_say_not_published_yet(self):
        """AUDIT: D8. flutter/versola_oauth/android/build.gradle.kts says the artefact is "not
        published yet"; release.yml says 0.1.0 is on Maven Central."""
        gradle = squash(read("flutter/versola_oauth/android/build.gradle.kts"))
        release = squash(read(".github/workflows/release.yml"))
        on_central = "which is on Maven Central" in release
        self.assertFalse(on_central and "not published yet" in gradle)

    def test_audit_d8_agents_md_uses_the_ios_simulator_ci_uses(self):
        """AUDIT: D8. AGENTS.md:32 says iPhone 16; develop.md and ios.yml moved to iPhone 17."""
        ios = read(".github/workflows/ios.yml")
        in_ci = re.search(r'name=(iPhone \d+)"', ios).group(1)
        in_agents = re.search(r'name=(iPhone \d+)"', read("AGENTS.md")).group(1)
        self.assertEqual(in_ci, in_agents)

    def test_audit_d8_agents_md_does_not_say_the_flutter_plugin_does_not_exist(self):
        """AUDIT: D8. AGENTS.md:37 says Flutter commands apply "once the plugin exists"; flutter/versola_oauth exists."""
        self.assertTrue((ROOT / "flutter/versola_oauth/pubspec.yaml").exists())
        self.assertNotIn("once the plugin exists", squash(read("AGENTS.md")))

    def test_audit_d8_flutter_changelog_does_not_contradict_the_pre_1_0_stability_row(self):
        """AUDIT: D8. README says the API is pre-1.0.0 and can change; the Flutter CHANGELOG's first
        entry says "The API stays production ready"."""
        first_entry = read("flutter/versola_oauth/CHANGELOG.md").split("\n## ")[0]
        self.assertNotIn("production ready", first_entry)


class D9ApiSurface(unittest.TestCase):
    # Plausibly wiring: built by the facades, never by an integrator, so rule 9 of
    # spec/oauth-sdk-api.md (wiring is internal or behind @VersolaInternalApi) keeps them out of the dump.
    WIRING = (
        "DiscoveryService", "PendingAuthorizationCodec", "HttpTokenClient",
        "HttpDiscoveryClient", "FileProviderMetadataCache", "TokenRequestExecutor", "SessionCoordinator",
        "AuthorizationFlow",
    )

    def test_audit_d9_wiring_classes_are_not_in_the_public_api_dump(self):
        """AUDIT: D9. oauth-core.api lists 114 public types, among them wiring that spec rule 9 says is
        internal or opt-in (DiscoveryService, PendingAuthorizationCodec, ...). MtlsEndpointAliases is not listed: ProviderMetadata exposes it, so it stays public.."""
        dump = read("android/oauth-core/api/oauth-core.api")
        public = re.findall(r"^public [^\n]*?class versola/oauth/core/(\w+)", dump, re.M)
        leaked = sorted(set(public) & set(self.WIRING))
        self.assertEqual([], leaked, "wiring classes in the public API dump")


class D10SwiftKotlinParity(unittest.TestCase):
    def test_audit_d10_swift_configuration_keeps_storage_key_fingerprint_and_to_metadata_internal(self):
        """AUDIT: D10. Kotlin keeps storageKey, fingerprint and ProviderEndpoints.toMetadata() internal;
        OAuthConfiguration.swift exposes all three as `public`."""
        swift = read("ios/Sources/OAuthClient/OAuthConfiguration.swift")
        public = [name for name, pattern in (
            ("storageKey", r"public (let|var) storageKey\b"),
            ("fingerprint", r"public (let|var) fingerprint\b"),
            ("toMetadata", r"public func toMetadata\b"),
        ) if re.search(pattern, swift)]
        self.assertEqual([], public, "public in Swift, internal in Kotlin")

    def test_audit_d10_swift_dpop_label_is_require_hardware(self):
        """AUDIT: D10. Kotlin is Dpop(requireHardware); Swift is `.dpop(required:)`, and the spec
        (section 3) calls it `required`, which also collides with the Required case of pushedAuthorization."""
        values = read("ios/Sources/OAuthCore/Values.swift")
        self.assertRegex(values, r"case dpop\(requireHardware: Bool")


class D11ApiCompatCi(unittest.TestCase):
    def test_audit_d11_ios_workflow_checks_public_api_breaks(self):
        """AUDIT: D11. AGENTS.md says the Swift ABI holds us; ios.yml has no api-digester step."""
        self.assertRegex(read(".github/workflows/ios.yml"), r"diagnose-api-breaking-changes|api-digester")

    def test_audit_d11_flutter_workflow_checks_public_api_breaks(self):
        """AUDIT: D11. AGENTS.md says the Dart API holds us; flutter.yml has no API dump or diff step."""
        self.assertRegex(read(".github/workflows/flutter.yml"), r"(?i)dart-apitool|dart_apitool|api[-_ ]?dump|api[-_ ]diff|breaking[-_ ]change")


if __name__ == "__main__":
    unittest.main(verbosity=2)
