import XCTest
@testable import OAuthCore

final class AuthorizationResponseValidatorTests: XCTestCase {
    private let issuer = AuthzKit.issuer

    private func url(_ query: String, base: String = AuthzKit.redirect) -> URL {
        URL(string: query.isEmpty ? base : "\(base)?\(query)")!
    }

    private func validate(
        _ query: String, base: String = AuthzKit.redirect,
        pending: PendingAuthorizationRequest = AuthzKit.pending(), issSupported: Bool = false
    ) throws -> AuthorizationGrant {
        try AuthorizationResponseValidator.validate(
            redirect: url(query, base: base), pending: pending, issuer: issuer, issParameterSupported: issSupported
        )
    }

    private func assertFails(
        _ expected: OAuthError, _ query: String, base: String = AuthzKit.redirect,
        pending: PendingAuthorizationRequest = AuthzKit.pending(), issSupported: Bool = false,
        file: StaticString = #filePath, line: UInt = #line
    ) {
        XCTAssertThrowsError(try validate(query, base: base, pending: pending, issSupported: issSupported),
                             file: file, line: line) {
            XCTAssertEqual($0 as? OAuthError, expected, file: file, line: line)
        }
    }

    // MARK: Positive

    func testAValidRedirectYieldsAGrantCarryingWhatTheExchangeNeeds() throws {
        let pending = PendingAuthorizationRequest(
            state: "state-1", nonce: "nonce-1", codeVerifier: String(repeating: "v", count: 43),
            scopes: ["openid", "profile"], redirectUri: AuthzKit.redirect, createdAt: AuthzKit.now,
            resources: ["https://api.example.com"], extensions: ["blob": "sealed"]
        )
        let grant = try validate("code=abc&state=state-1&iss=https%3A%2F%2Fid.example.com", pending: pending)
        XCTAssertEqual(grant.code, "abc")
        XCTAssertEqual(grant.codeVerifier, pending.codeVerifier)
        XCTAssertEqual(grant.redirectUri, AuthzKit.redirect)
        XCTAssertEqual(grant.resources, ["https://api.example.com"])
        XCTAssertEqual(grant.extensions, ["blob": "sealed"])
        XCTAssertEqual(grant.nonce, "nonce-1")
        XCTAssertEqual(grant.scopes, ["openid", "profile"])
        XCTAssertEqual(grant.state, "state-1")
        XCTAssertEqual(grant.iss, issuer)
    }

    func testTheGrantNeverPrintsItsSecrets() throws {
        let grant = try validate("code=secret-code&state=state-1")
        XCTAssertEqual(grant.description, "AuthorizationGrant(redacted)")
        XCTAssertFalse("\(grant)".contains("secret-code"))
    }

    func testAMissingIssIsAcceptedWhenNothingRequiresIt() throws {
        XCTAssertNoThrow(try validate("code=abc&state=state-1", issSupported: false))
    }

    // MARK: state

    func testAWrongStateIsRefused() {
        assertFails(.configuration(.stateMismatch), "code=abc&state=other")
        assertFails(.configuration(.stateMismatch), "code=abc&state=state-1x")
        assertFails(.configuration(.stateMismatch), "code=abc&state=state-")
    }

    func testAMissingOrEmptyStateIsRefusedAsAMismatch() {
        assertFails(.configuration(.stateMismatch), "code=abc")
        assertFails(.configuration(.stateMismatch), "code=abc&state=")
        assertFails(.configuration(.stateMismatch), "")
    }

    func testStateIsCheckedBeforeIss() {
        assertFails(.configuration(.stateMismatch), "code=abc&state=other&iss=https%3A%2F%2Fevil.example.org", issSupported: true)
        assertFails(.configuration(.stateMismatch), "code=abc&state=other", issSupported: true)
    }

    func testStateIsCheckedBeforeAProvidersErrorSoAnInjectedErrorCannotShortCircuit() {
        assertFails(.configuration(.stateMismatch), "error=access_denied&state=other")
    }

    func testARepeatedStateIsMalformedRatherThanFirstWins() {
        assertFails(.configuration(.malformedAuthorizationResponse), "code=abc&state=state-1&state=other")
        assertFails(.configuration(.malformedAuthorizationResponse), "code=abc&state=other&state=state-1")
    }

    // MARK: iss

    func testAMissingIssFailsWhenTheProviderAdvertisesSupport() {
        assertFails(.configuration(.issuerMismatch(expected: issuer, received: nil)),
                    "code=abc&state=state-1", issSupported: true)
    }

    func testAMissingIssFailsWhenThePendingRequestRequiresIt() {
        assertFails(.configuration(.issuerMismatch(expected: issuer, received: nil)),
                    "code=abc&state=state-1", pending: AuthzKit.pending(issRequired: true))
    }

    func testAnIssThatDiffersIsRefusedWhetherOrNotSupportIsAdvertised() {
        let evil = "https://evil.example.org"
        let query = "code=abc&state=state-1&iss=https%3A%2F%2Fevil.example.org"
        assertFails(.configuration(.issuerMismatch(expected: issuer, received: evil)), query, issSupported: false)
        assertFails(.configuration(.issuerMismatch(expected: issuer, received: evil)), query, issSupported: true)
    }

    func testAnIssWithAnAddedTrailingSlashIsRefused() {
        for supported in [false, true] {
            assertFails(.configuration(.issuerMismatch(expected: issuer, received: issuer + "/")),
                        "code=abc&state=state-1&iss=https%3A%2F%2Fid.example.com%2F", issSupported: supported)
        }
    }

    func testAnIssuerWithATrailingSlashRequiresThatExactSlash() throws {
        let expected = issuer + "/"
        XCTAssertNoThrow(try AuthorizationResponseValidator.validate(
            redirect: url("code=abc&state=state-1&iss=https%3A%2F%2Fid.example.com%2F"),
            pending: AuthzKit.pending(), issuer: expected, issParameterSupported: true))
        XCTAssertThrowsError(try AuthorizationResponseValidator.validate(
            redirect: url("code=abc&state=state-1&iss=https%3A%2F%2Fid.example.com"),
            pending: AuthzKit.pending(), issuer: expected, issParameterSupported: true)) {
            XCTAssertEqual($0 as? OAuthError, .configuration(.issuerMismatch(expected: expected, received: self.issuer)))
        }
    }

    func testAnIssThatMerelyStartsWithTheIssuerIsRefused() {
        assertFails(.configuration(.issuerMismatch(expected: issuer, received: "https://id.example.com.evil.example.org")),
                    "code=abc&state=state-1&iss=https%3A%2F%2Fid.example.com.evil.example.org")
    }

    func testIssIsCheckedBeforeAProvidersError() {
        assertFails(.configuration(.issuerMismatch(expected: issuer, received: "https://evil.example.org")),
                    "error=access_denied&state=state-1&iss=https%3A%2F%2Fevil.example.org")
    }

    // MARK: error

    func testAccessDeniedIsAuthorizationDenied() {
        assertFails(.reauthenticate(.authorizationDenied), "error=access_denied&state=state-1")
    }

    func testTheInteractionCodesAreInteractionRequiredCarryingTheCode() {
        for code in ["login_required", "consent_required", "interaction_required", "account_selection_required"] {
            assertFails(.reauthenticate(.interactionRequired(code: code)), "error=\(code)&state=state-1")
        }
    }

    func testAnyOtherErrorIsAConfigurationFaultWithItsDescription() {
        assertFails(.configuration(.authorizationRejected(code: "invalid_scope", description: "no such scope")),
                    "error=invalid_scope&error_description=no%20such+scope&state=state-1")
        assertFails(.configuration(.authorizationRejected(code: "unmet_authentication_requirements", description: nil)),
                    "error=unmet_authentication_requirements&state=state-1")
    }

    /// `spec/errors.md`: RFC 6749 4.1.2.1's "the server could not handle the request now" is the
    /// provider having a bad moment, `Recoverable(Server)`, never a deployment fault.
    func testServerErrorAndTemporarilyUnavailableAreRecoverableServerFailures() {
        assertFails(.recoverable(.server(status: 500, retryAfterMillis: nil, attempts: 1, elapsedMillis: 0)), "error=server_error&state=state-1")
        assertFails(.recoverable(.server(status: 503, retryAfterMillis: nil, attempts: 1, elapsedMillis: 0)), "error=temporarily_unavailable&state=state-1")
    }

    func testAnErrorWinsOverACodeInTheSameRedirect() {
        assertFails(.reauthenticate(.authorizationDenied), "error=access_denied&code=abc&state=state-1")
    }

    // MARK: code

    func testAMissingOrEmptyCodeIsMalformed() {
        assertFails(.configuration(.malformedAuthorizationResponse), "state=state-1")
        assertFails(.configuration(.malformedAuthorizationResponse), "code=&state=state-1")
    }

    func testARepeatedCodeIsMalformed() {
        assertFails(.configuration(.malformedAuthorizationResponse), "code=a&code=b&state=state-1")
    }

    // MARK: redirect target

    func testRedirectPortsMatchOnlyWhenTheirEffectiveValuesAgree() throws {
        let cases: [(String, String, Bool)] = [
            ("https://app.example.com/callback", "https://app.example.com:443/callback", true),
            ("https://app.example.com:443/callback", "https://app.example.com/callback", true),
            ("HTTPS://app.example.com/callback", "HTTPS://app.example.com:443/callback", true),
            ("http://localhost/callback", "http://localhost:80/callback", true),
            ("http://localhost:80/callback", "http://localhost/callback", true),
            ("https://app.example.com:8443/callback", "https://app.example.com:8443/callback", true),
            ("https://app.example.com/callback", "https://app.example.com:8443/callback", false),
            ("https://app.example.com:8443/callback", "https://app.example.com/callback", false),
            ("https://app.example.com:8443/callback", "https://app.example.com:9443/callback", false),
            ("http://localhost/callback", "http://localhost:8080/callback", false),
            ("com.example.app://callback/path", "com.example.app://callback:443/path", false),
            ("com.example.app://callback:1234/path", "com.example.app://callback:1234/path", true),
        ]
        for (expected, received, matches) in cases {
            let pending = PendingAuthorizationRequest(
                state: "state-1", nonce: "n", codeVerifier: String(repeating: "v", count: 43),
                scopes: [], redirectUri: expected, createdAt: AuthzKit.now)
            if matches {
                XCTAssertNoThrow(try validate("code=abc&state=state-1", base: received, pending: pending), received)
            } else {
                assertFails(.configuration(.malformedAuthorizationResponse), "code=abc&state=state-1",
                            base: received, pending: pending)
                assertFails(.configuration(.malformedAuthorizationResponse), "error=access_denied&state=state-1",
                            base: received, pending: pending)
            }
        }
    }

    func testARedirectToAnotherPathIsRefused() {
        assertFails(.configuration(.malformedAuthorizationResponse), "code=abc&state=state-1",
                    base: "https://app.example.com/elsewhere")
        assertFails(.configuration(.malformedAuthorizationResponse), "code=abc&state=state-1",
                    base: "https://app.example.com/callback/extra")
    }

    func testARedirectToAnotherHostOrSchemeIsRefused() {
        assertFails(.configuration(.malformedAuthorizationResponse), "code=abc&state=state-1",
                    base: "https://evil.example.org/callback")
        assertFails(.configuration(.malformedAuthorizationResponse), "code=abc&state=state-1",
                    base: "http://app.example.com/callback")
    }

    /// `spec/state-machine.md`: the redirect-URI check runs after `iss` and before the provider's own `error`.
    func testTheRedirectTargetIsCheckedAfterIssAndBeforeTheProvidersError() {
        assertFails(.configuration(.malformedAuthorizationResponse), "error=access_denied&state=state-1&iss=https%3A%2F%2Fid.example.com",
                    base: "https://evil.example.org/callback")
        assertFails(.configuration(.issuerMismatch(expected: AuthzKit.issuer, received: "https://evil.example.org")),
                    "code=abc&state=state-1&iss=https%3A%2F%2Fevil.example.org", base: "https://evil.example.org/callback")
    }

    /// The query is read as the platform delivered it: a raw `|`, `{`, `}` or space does not make a genuine redirect unreadable.
    func testAGenuineRedirectWithRawSpecialCharactersInTheQueryIsStillRead() throws {
        let raw = URL(string: AuthzKit.redirect + "?code=abc&state=state-1&x=a|b{c}")
        let url = try XCTUnwrap(raw, "Foundation refused the URL on this platform")
        let grant = try AuthorizationResponseValidator.validate(redirect: url, pending: AuthzKit.pending(), issuer: AuthzKit.issuer, issParameterSupported: false)
        XCTAssertEqual(grant.code, "abc")
    }

    func testSchemeAndHostCompareCaseInsensitivelyAndTheQueryIsIgnored() throws {
        XCTAssertNoThrow(try validate("code=abc&state=state-1", base: "HTTPS://APP.example.com/callback"))
        let withQuery = PendingAuthorizationRequest(
            state: "state-1", nonce: "n", codeVerifier: String(repeating: "v", count: 43), scopes: [],
            redirectUri: "https://app.example.com/callback?x=1", createdAt: AuthzKit.now)
        XCTAssertNoThrow(try validate("code=abc&state=state-1", pending: withQuery))
    }

    func testACustomSchemeRedirectMatches() throws {
        let pending = PendingAuthorizationRequest(
            state: "state-1", nonce: "n", codeVerifier: String(repeating: "v", count: 43), scopes: [],
            redirectUri: "com.example.app:/oauth2redirect", createdAt: AuthzKit.now)
        XCTAssertNoThrow(try validate("code=abc&state=state-1", base: "com.example.app:/oauth2redirect", pending: pending))
        XCTAssertThrowsError(try validate("code=abc&state=state-1", base: "com.example.app:/other", pending: pending))
    }

    // MARK: parseQuery

    func testParseQueryDecodesPlusAndPercentEscapes() {
        let parsed = AuthorizationResponseValidator.parseQuery(url("a=b+c&d=e%20f&g=%C3%A9&h"))
        XCTAssertEqual(parsed["a"], "b c")
        XCTAssertEqual(parsed["d"], "e f")
        XCTAssertEqual(parsed["g"], "é")
        XCTAssertEqual(parsed["h"], "")
    }

    func testParseQueryKeepsTheFirstOfARepeatedKeyAndAllowsEmptyValues() {
        let parsed = AuthorizationResponseValidator.parseQuery(url("c=1&c=2&d=&&=orphan&e=a=b"))
        XCTAssertEqual(parsed["c"], "1")
        XCTAssertEqual(parsed["d"], "")
        XCTAssertEqual(parsed["e"], "a=b")
        XCTAssertNil(parsed[""])
    }

    func testParseQueryDoesNotCrashOnMalformedPercentEscapes() {
        for query in ["a=%", "a=%zz&b=1", "a=%E0%A4%A&b=2", "%=%", "a=%%%%", "a=%2", "%zz=1&ok=1", "a=%00"] {
            guard let target = URL(string: "\(AuthzKit.redirect)?\(query)") else { continue }
            let parsed = AuthorizationResponseValidator.parseQuery(target)
            _ = parsed.count
        }
        let ok = AuthorizationResponseValidator.parseQuery(url("a=%zz&b=1"))
        XCTAssertEqual(ok["b"], "1")
        XCTAssertNotNil(ok["a"])
    }

    func testParseQueryNeverCrashesOnAGeneratedCorpus() {
        var generator = SystemRandomNumberGenerator()
        let alphabet = Array("ab=&%+;?#/.0189zZ é\u{0}\u{1F600}")
        for _ in 0..<2_000 {
            let length = Int.random(in: 0..<40, using: &generator)
            let query = String((0..<length).map { _ in alphabet.randomElement(using: &generator)! })
            if let target = URL(string: AuthzKit.redirect + "?" + query) {
                _ = AuthorizationResponseValidator.parseQuery(target)
                _ = AuthorizationResponseValidator.stateOf(target)
                _ = try? AuthorizationResponseValidator.validate(
                    redirect: target, pending: AuthzKit.pending(), issuer: issuer, issParameterSupported: true)
            }
        }
    }

    func testParseQueryOfAUrlWithoutAQueryIsEmpty() {
        XCTAssertTrue(AuthorizationResponseValidator.parseQuery(url("")).isEmpty)
    }

    func testStateOfReadsTheStateOrNil() {
        XCTAssertEqual(AuthorizationResponseValidator.stateOf(url("state=s1&code=c")), "s1")
        XCTAssertNil(AuthorizationResponseValidator.stateOf(url("code=c")))
    }

    func testAFragmentIsNotReadAsTheResponse() {
        let target = URL(string: "\(AuthzKit.redirect)#code=abc&state=state-1")!
        XCTAssertThrowsError(try AuthorizationResponseValidator.validate(
            redirect: target, pending: AuthzKit.pending(), issuer: issuer, issParameterSupported: false)) {
            XCTAssertEqual($0 as? OAuthError, .configuration(.stateMismatch))
        }
    }
}
