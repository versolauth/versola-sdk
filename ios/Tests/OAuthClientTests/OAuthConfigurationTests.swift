import XCTest
@testable import OAuthClient

final class OAuthConfigurationTests: XCTestCase {
    private let issuer = "https://auth.example.com"
    private let redirect = "https://app.example.com/callback"

    private func make(
        issuer: String? = "https://auth.example.com", endpoints: ProviderEndpoints? = nil, clientId: String = "client-1",
        redirectUri: String = "https://app.example.com/callback", postLogoutRedirectUri: String? = nil,
        scopes: Set<String> = ["openid"], protectedOrigins: Set<String> = [], endSessionEndpoint: String? = nil,
        retryPolicy: RetryPolicy = .default, clockSkewTolerance: TimeInterval = 60, unlockPolicy: UnlockPolicy = .none,
        tokenBinding: TokenBinding = .bearer
    ) throws -> OAuthConfiguration {
        try OAuthConfiguration(
            issuer: issuer, endpoints: endpoints, clientId: clientId, redirectUri: redirectUri,
            postLogoutRedirectUri: postLogoutRedirectUri, scopes: scopes, tokenBinding: tokenBinding,
            protectedOrigins: protectedOrigins, endSessionEndpoint: endSessionEndpoint, retryPolicy: retryPolicy,
            unlockPolicy: unlockPolicy, clockSkewTolerance: clockSkewTolerance
        )
    }

    private let endpoints = ProviderEndpoints(
        issuer: "https://auth.example.com", authorizationEndpoint: "https://auth.example.com/authorize",
        tokenEndpoint: "https://auth.example.com/token", jwksUri: "https://auth.example.com/jwks"
    )

    private func assertInvalid(_ body: () throws -> Any, file: StaticString = #filePath, line: UInt = #line) {
        do {
            _ = try body()
            XCTFail("expected invalidConfiguration", file: file, line: line)
        } catch OAuthError.configuration(.invalidConfiguration) {
        } catch {
            XCTFail("expected invalidConfiguration, got \(error)", file: file, line: line)
        }
    }

    // MARK: issuer xor endpoints

    func testIssuerAloneAndEndpointsAloneAreAccepted() throws {
        XCTAssertEqual(try make().issuerIdentifier, issuer)
        XCTAssertEqual(try make(issuer: nil, endpoints: endpoints).issuerIdentifier, issuer)
    }

    func testBothIssuerAndEndpointsAreRefused() {
        assertInvalid { try make(issuer: issuer, endpoints: endpoints) }
    }

    func testNeitherIssuerNorEndpointsIsRefused() {
        assertInvalid { try make(issuer: nil) }
    }

    // MARK: issuer

    func testIssuerTrailingSlashIsTrimmed() throws {
        let configuration = try make(issuer: "https://auth.example.com/")
        XCTAssertEqual(configuration.issuerIdentifier, issuer)
        XCTAssertEqual(configuration.core.issuer, issuer)
    }

    func testIssuerWithPathIsAccepted() throws {
        XCTAssertEqual(try make(issuer: "https://auth.example.com/realms/main").issuerIdentifier, "https://auth.example.com/realms/main")
    }

    func testCleartextIssuerOnARemoteHostIsRefused() {
        assertInvalid { try make(issuer: "http://auth.example.com") }
    }

    func testLoopbackHostsMayUseCleartextIssuer() throws {
        for host in ["127.0.0.1", "localhost", "[::1]"] {
            XCTAssertNoThrow(try make(issuer: "http://\(host):8080"), host)
        }
    }

    func testLookalikeLoopbackHostsAreRefused() {
        for host in ["localhost.example.com", "127.0.0.1.example.com", "10.0.2.2"] {
            assertInvalid { try make(issuer: "http://\(host)") }
        }
    }

    func testIssuerWithoutHostIsRefused() {
        assertInvalid { try make(issuer: "https:issuer") }
        assertInvalid { try make(issuer: "https://") }
        assertInvalid { try make(issuer: "not a url") }
    }

    func testIssuerWithQueryOrFragmentIsRefused() {
        assertInvalid { try make(issuer: "https://auth.example.com?tenant=1") }
        assertInvalid { try make(issuer: "https://auth.example.com#frag") }
    }

    // MARK: endpoints

    func testEveryEndpointMustBeHttps() throws {
        XCTAssertNoThrow(try make(issuer: nil, endpoints: endpoints))
        let bad = "http://auth.example.com/x"
        let variants: [ProviderEndpoints] = [
            ProviderEndpoints(issuer: issuer, authorizationEndpoint: bad, tokenEndpoint: endpoints.tokenEndpoint, jwksUri: endpoints.jwksUri),
            ProviderEndpoints(issuer: issuer, authorizationEndpoint: endpoints.authorizationEndpoint, tokenEndpoint: bad, jwksUri: endpoints.jwksUri),
            ProviderEndpoints(issuer: issuer, authorizationEndpoint: endpoints.authorizationEndpoint, tokenEndpoint: endpoints.tokenEndpoint, jwksUri: bad),
            ProviderEndpoints(issuer: issuer, authorizationEndpoint: endpoints.authorizationEndpoint, tokenEndpoint: endpoints.tokenEndpoint, jwksUri: endpoints.jwksUri, userinfoEndpoint: bad),
            ProviderEndpoints(issuer: issuer, authorizationEndpoint: endpoints.authorizationEndpoint, tokenEndpoint: endpoints.tokenEndpoint, jwksUri: endpoints.jwksUri, revocationEndpoint: bad),
            ProviderEndpoints(issuer: issuer, authorizationEndpoint: endpoints.authorizationEndpoint, tokenEndpoint: endpoints.tokenEndpoint, jwksUri: endpoints.jwksUri, endSessionEndpoint: bad),
            ProviderEndpoints(issuer: issuer, authorizationEndpoint: endpoints.authorizationEndpoint, tokenEndpoint: endpoints.tokenEndpoint, jwksUri: endpoints.jwksUri, pushedAuthorizationRequestEndpoint: bad),
        ]
        for variant in variants {
            assertInvalid { try make(issuer: nil, endpoints: variant) }
        }
    }

    func testLoopbackEndpointsMayUseCleartext() {
        let local = ProviderEndpoints(
            issuer: "http://localhost:8080", authorizationEndpoint: "http://localhost:8080/authorize",
            tokenEndpoint: "http://127.0.0.1:8080/token", jwksUri: "http://[::1]:8080/jwks"
        )
        XCTAssertNoThrow(try make(issuer: nil, endpoints: local))
    }

    func testEndpointsIssuerIsHeldToTheIssuerRules() {
        let withQuery = ProviderEndpoints(
            issuer: "https://auth.example.com?x=1", authorizationEndpoint: endpoints.authorizationEndpoint,
            tokenEndpoint: endpoints.tokenEndpoint, jwksUri: endpoints.jwksUri
        )
        assertInvalid { try make(issuer: nil, endpoints: withQuery) }
    }

    func testEndpointsBecomeMetadataWithTheAssumedCapabilities() {
        let metadata = ProviderEndpoints(
            issuer: issuer, authorizationEndpoint: "https://auth.example.com/authorize",
            tokenEndpoint: "https://auth.example.com/token", jwksUri: "https://auth.example.com/jwks",
            revocationEndpoint: "https://auth.example.com/revoke", idTokenSigningAlgValuesSupported: ["ES256"]
        ).toMetadata()
        XCTAssertEqual(metadata.issuer, issuer)
        XCTAssertEqual(metadata.jwksUri, "https://auth.example.com/jwks")
        XCTAssertEqual(metadata.revocationEndpoint, "https://auth.example.com/revoke")
        XCTAssertNil(metadata.pushedAuthorizationRequestEndpoint)
        XCTAssertEqual(metadata.codeChallengeMethodsSupported, ["S256"])
        XCTAssertEqual(metadata.responseTypesSupported, ["code"])
        XCTAssertEqual(metadata.grantTypesSupported, ["authorization_code", "refresh_token"])
        XCTAssertEqual(metadata.idTokenSigningAlgValuesSupported, ["ES256"])
        XCTAssertFalse(metadata.supportsDpop)
    }

    // MARK: client id and redirect URIs

    func testBlankClientIdIsRefused() throws {
        XCTAssertNoThrow(try make(clientId: "client-1"))
        assertInvalid { try make(clientId: "") }
        assertInvalid { try make(clientId: "   ") }
    }

    func testRedirectUriKindsAndTheirWarning() throws {
        XCTAssertNil(try make(redirectUri: "https://app.example.com/cb").redirectUriWarning)
        XCTAssertNil(try make(redirectUri: "http://127.0.0.1:5000/cb").redirectUriWarning)
        XCTAssertNil(try make(redirectUri: "http://localhost/cb").redirectUriWarning)
        let custom = try make(redirectUri: "com.example.app:/callback")
        XCTAssertNotNil(custom.redirectUriWarning)
        XCTAssertFalse(custom.redirectUriWarning!.contains("com.example.app"))
    }

    func testRedirectUriRefusals() {
        assertInvalid { try make(redirectUri: "http://app.example.com/cb") }
        assertInvalid { try make(redirectUri: "https://app.example.com/cb#frag") }
        assertInvalid { try make(redirectUri: "com.example.app:/cb#frag") }
        assertInvalid { try make(redirectUri: "/relative/path") }
        assertInvalid { try make(redirectUri: "callback") }
        assertInvalid { try make(redirectUri: "https:callback") }
        assertInvalid { try make(redirectUri: "") }
    }

    func testPostLogoutRedirectUriHasTheSameRules() throws {
        XCTAssertNoThrow(try make(postLogoutRedirectUri: "https://app.example.com/signed-out"))
        XCTAssertNoThrow(try make(postLogoutRedirectUri: "com.example.app:/signed-out"))
        XCTAssertEqual(try make(postLogoutRedirectUri: "https://app.example.com/out").core.postLogoutRedirectUri?.absoluteString, "https://app.example.com/out")
        assertInvalid { try make(postLogoutRedirectUri: "http://app.example.com/out") }
        assertInvalid { try make(postLogoutRedirectUri: "https://app.example.com/out#f") }
        assertInvalid { try make(postLogoutRedirectUri: "relative") }
    }

    // MARK: scopes

    func testScopesAreSingleTokensAndOpenidIsAdded() throws {
        let configuration = try make(scopes: ["email", "profile"])
        XCTAssertEqual(configuration.effectiveScopes, ["openid", "email", "profile"])
        XCTAssertEqual(configuration.scopes, ["email", "profile"])
        assertInvalid { try make(scopes: ["email profile"]) }
        assertInvalid { try make(scopes: ["email\tprofile"]) }
        assertInvalid { try make(scopes: [""]) }
        assertInvalid { try make(scopes: ["  "]) }
    }

    // MARK: protected origins

    func testProtectedOriginsMustBeBareOrigins() throws {
        XCTAssertNoThrow(try make(protectedOrigins: ["https://api.example.com", "https://api.example.com:8443", "https://other.example.com/"]))
        XCTAssertNoThrow(try make(protectedOrigins: ["http://localhost:9000", "http://127.0.0.1", "http://[::1]:7000"]))
        for bad in [
            "http://api.example.com", "https://api.example.com/v1", "https://api.example.com?x=1",
            "https://api.example.com#f", "api.example.com", "ftp://api.example.com", "https://user@api.example.com",
        ] {
            assertInvalid { try make(protectedOrigins: [bad]) }
        }
    }

    // MARK: end session endpoint, clock skew

    func testEndSessionEndpointMustBeHttps() throws {
        XCTAssertNoThrow(try make(endSessionEndpoint: "https://auth.example.com/logout"))
        assertInvalid { try make(endSessionEndpoint: "http://auth.example.com/logout") }
        assertInvalid { try make(endSessionEndpoint: "logout") }
    }

    func testClockSkewToleranceIsBetweenZeroAndFiveMinutes() throws {
        XCTAssertNoThrow(try make(clockSkewTolerance: 0))
        XCTAssertNoThrow(try make(clockSkewTolerance: 300))
        assertInvalid { try make(clockSkewTolerance: -1) }
        assertInvalid { try make(clockSkewTolerance: 301) }
        assertInvalid { try make(clockSkewTolerance: .nan) }
    }

    // MARK: derived values

    func testStorageKeyIsStableAndSixteenUrlSafeCharacters() throws {
        let a = try make()
        let b = try make()
        XCTAssertEqual(a.storageKey, b.storageKey)
        XCTAssertEqual(a.storageKey.count, 16)
        XCTAssertTrue(a.storageKey.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") })
        // Same issuer with or without the slash is the same client; another client id or issuer is not.
        XCTAssertEqual(try make(issuer: "https://auth.example.com/").storageKey, a.storageKey)
        XCTAssertNotEqual(try make(clientId: "client-2").storageKey, a.storageKey)
        XCTAssertNotEqual(try make(issuer: "https://other.example.com").storageKey, a.storageKey)
    }

    func testStorageKeyIsTheDocumentedHash() throws {
        // base64url(SHA-256("https://auth.example.com\nclient-1")), first 16 characters; computed with openssl.
        XCTAssertEqual(try make().storageKey, "R_qlkes3CY1b4nQd")
    }

    func testFingerprintIsEqualForEqualValuesBuiltSeparately() throws {
        let a = try make(scopes: ["profile", "email"], protectedOrigins: ["https://b.example.com", "https://a.example.com"], retryPolicy: RetryPolicy(maxAttemptsPerOrigin: 2))
        let b = try make(scopes: ["email", "profile"], protectedOrigins: ["https://a.example.com", "https://b.example.com"], retryPolicy: RetryPolicy(maxAttemptsPerOrigin: 2))
        XCTAssertEqual(a.fingerprint, b.fingerprint)
        // openid present or implied is the same configuration.
        XCTAssertEqual(try make(scopes: ["openid"]).fingerprint, try make(scopes: []).fingerprint)
    }

    func testFingerprintDiffersOnEachField() throws {
        let base = try make().fingerprint
        let differing: [OAuthConfiguration] = [
            try make(issuer: "https://other.example.com"),
            try make(issuer: nil, endpoints: endpoints),
            try make(clientId: "client-2"),
            try make(redirectUri: "https://app.example.com/other"),
            try make(postLogoutRedirectUri: "https://app.example.com/out"),
            try make(scopes: ["email"]),
            try make(protectedOrigins: ["https://api.example.com"]),
            try make(endSessionEndpoint: "https://auth.example.com/logout"),
            try make(retryPolicy: RetryPolicy(maxAttemptsPerOrigin: 2)),
            try make(retryPolicy: RetryPolicy(initialBackoff: 1)),
            try make(retryPolicy: RetryPolicy(totalBudget: 10)),
            try make(clockSkewTolerance: 30),
            try make(unlockPolicy: .onAppUnlock),
            try make(tokenBinding: .dpop(required: false)),
            try make(tokenBinding: .dpop(required: true)),
        ]
        var seen: Set<String> = [base]
        for configuration in differing {
            XCTAssertTrue(seen.insert(configuration.fingerprint).inserted, "a field did not change the fingerprint")
        }
    }

    func testFingerprintSeesAnEndpointsFieldAndNotTheLogger() throws {
        let a = try make(issuer: nil, endpoints: endpoints)
        let revoking = ProviderEndpoints(
            issuer: endpoints.issuer, authorizationEndpoint: endpoints.authorizationEndpoint,
            tokenEndpoint: endpoints.tokenEndpoint, jwksUri: endpoints.jwksUri,
            revocationEndpoint: "https://auth.example.com/revoke"
        )
        XCTAssertNotEqual(a.fingerprint, try make(issuer: nil, endpoints: revoking).fingerprint)
    }

    func testCoreConfigurationCarriesTheValidatedValues() throws {
        let core = try make(postLogoutRedirectUri: "https://app.example.com/out").core
        XCTAssertEqual(core.issuer, issuer)
        XCTAssertEqual(core.clientId, "client-1")
        XCTAssertEqual(core.redirectUri.absoluteString, redirect)
    }

    // MARK: login and logout options

    func testLoginOptionsBuildAuthorizationParameters() throws {
        let options = try LoginOptions(
            scopes: ["email"], prompt: .login, loginHint: "a@example.com", uiLocales: ["de", "en"], acrValues: ["mfa"],
            maxAge: 300, resources: ["https://api.example.com"], extraParameters: ["audience": "api"], ephemeralBrowser: true
        )
        XCTAssertEqual(options.parameters.prompt, .login)
        XCTAssertEqual(options.parameters.loginHint, "a@example.com")
        XCTAssertEqual(options.parameters.uiLocales, ["de", "en"])
        XCTAssertEqual(options.parameters.resources, ["https://api.example.com"])
        XCTAssertEqual(options.parameters.extra, ["audience": "api"])
        XCTAssertTrue(options.ephemeralBrowser)
        XCTAssertFalse(LoginOptions.default.ephemeralBrowser)
        XCTAssertNil(LoginOptions.default.scopes)
    }

    func testLoginOptionsRefuseEveryReservedExtraParameter() {
        for key in AuthorizationParameters.reserved {
            assertInvalid { try LoginOptions(extraParameters: [key: "x"]) }
        }
        assertInvalid { try LoginOptions(extraParameters: ["state": "attacker-chosen"]) }
        XCTAssertNoThrow(try LoginOptions(extraParameters: ["kc_idp_hint": "google"]))
    }

    func testLoginOptionsScopeAndMaxAgeRules() {
        assertInvalid { try LoginOptions(scopes: ["a b"]) }
        assertInvalid { try LoginOptions(maxAge: -1) }
        XCTAssertNoThrow(try LoginOptions(scopes: ["a"], maxAge: 0))
    }

    func testLogoutOptionsDefaultToBothSteps() {
        XCTAssertTrue(LogoutOptions.default.endSession)
        XCTAssertTrue(LogoutOptions.default.revoke)
        XCTAssertFalse(LogoutOptions(endSession: false).endSession)
    }
}
