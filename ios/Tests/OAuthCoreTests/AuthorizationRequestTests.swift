import XCTest
@testable import OAuthCore

final class AuthorizationRequestTests: XCTestCase {
    private func request(
        scopes: [String] = ["openid", "profile"], acrValues: [String] = [], maxAge: Int? = nil,
        dpopJkt: String? = nil, parameters: AuthorizationParameters = .none
    ) -> AuthorizationRequest {
        AuthorizationRequest.create(
            configuration: AuthzKit.configuration, scopes: scopes, acrValues: acrValues, maxAge: maxAge,
            dpopJkt: dpopJkt, parameters: parameters
        )
    }

    private func names(_ request: AuthorizationRequest) -> [String] { request.formParameters().map(\.0) }

    private func value(_ name: String, in request: AuthorizationRequest) -> String? {
        request.formParameters().first { $0.0 == name }?.1
    }

    func testMinimalRequestCarriesTheMandatoryParametersInWireOrder() {
        let r = request()
        XCTAssertEqual(names(r), [
            "response_type", "client_id", "redirect_uri", "scope", "state", "nonce",
            "code_challenge", "code_challenge_method",
        ])
        XCTAssertEqual(value("response_type", in: r), "code")
        XCTAssertEqual(value("client_id", in: r), "client-123")
        XCTAssertEqual(value("redirect_uri", in: r), AuthzKit.redirect)
        XCTAssertEqual(value("code_challenge_method", in: r), "S256")
        XCTAssertEqual(value("code_challenge", in: r), r.codeVerifier.challengeS256())
    }

    func testEveryOptionalParameterAppearsInTheOrderAndroidSendsThem() throws {
        let parameters = try AuthorizationParameters(
            prompt: .consent, loginHint: "user@example.com", uiLocales: ["de", "en"],
            resources: ["https://api.example.com/a", "https://api.example.com/b"],
            extra: ["audience": "https://api.example.com"]
        )
        let r = request(acrValues: ["urn:acr:2", "urn:acr:3"], maxAge: 300, dpopJkt: "jkt-1", parameters: parameters)
        XCTAssertEqual(names(r), [
            "response_type", "client_id", "redirect_uri", "scope", "state", "nonce",
            "code_challenge", "code_challenge_method", "acr_values", "max_age", "dpop_jkt",
            "prompt", "login_hint", "ui_locales", "resource", "resource", "audience",
        ])
        XCTAssertEqual(value("acr_values", in: r), "urn:acr:2 urn:acr:3")
        XCTAssertEqual(value("max_age", in: r), "300")
        XCTAssertEqual(value("dpop_jkt", in: r), "jkt-1")
        XCTAssertEqual(value("prompt", in: r), "consent")
        XCTAssertEqual(value("ui_locales", in: r), "de en")
        XCTAssertEqual(r.formParameters().filter { $0.0 == "resource" }.map(\.1),
                       ["https://api.example.com/a", "https://api.example.com/b"])
    }

    func testDpopJktIsAbsentWhenTheSessionIsNotKeyBound() {
        XCTAssertFalse(names(request()).contains("dpop_jkt"))
    }

    func testScopesKeepTheOrderGivenAndDropDuplicates() {
        let r = request(scopes: ["profile", "openid", "profile", "email", "openid"])
        XCTAssertEqual(r.scopes, ["profile", "openid", "email"])
        XCTAssertEqual(value("scope", in: r), "profile openid email")
    }

    func testStateNonceAndVerifierAreFreshAndDistinct() {
        let a = request(), b = request()
        XCTAssertNotEqual(a.state, b.state)
        XCTAssertNotEqual(a.nonce, b.nonce)
        XCTAssertNotEqual(a.state, a.nonce)
        XCTAssertNotEqual(a.state, a.codeVerifier.value)
        XCTAssertGreaterThanOrEqual(a.state.count, 43)
        XCTAssertGreaterThanOrEqual(a.nonce.count, 43)
    }

    func testUriEncodesSpacesAsPercent20AndReservedCharactersEverywhere() throws {
        let parameters = try AuthorizationParameters(loginHint: "a+b&c=d/e?f#g é", extra: ["x y": "1&2"])
        let uri = try request(parameters: parameters).toUri(authorizationEndpoint: "https://id.example.com/authorize")
        let text = uri.absoluteString
        XCTAssertTrue(text.contains("scope=openid%20profile"), text)
        XCTAssertFalse(text.contains("+"), text)
        XCTAssertTrue(text.contains("redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback"), text)
        XCTAssertTrue(text.contains("login_hint=a%2Bb%26c%3Dd%2Fe%3Ff%23g%20%C3%A9"), text)
        XCTAssertTrue(text.contains("x%20y=1%262"), text)
        XCTAssertTrue(text.hasPrefix("https://id.example.com/authorize?response_type=code&client_id=client-123"), text)
    }

    func testUriRoundTripsThroughTheValidatorsQueryParser() throws {
        let r = request()
        let uri = try r.toUri(authorizationEndpoint: "https://id.example.com/authorize")
        let parsed = AuthorizationResponseValidator.parseQuery(uri)
        XCTAssertEqual(parsed["state"], r.state)
        XCTAssertEqual(parsed["scope"], "openid profile")
        XCTAssertEqual(parsed["redirect_uri"], AuthzKit.redirect)
    }

    func testAnEndpointThatAlreadyHasAQueryGetsAnAmpersand() throws {
        let uri = try request().toUri(authorizationEndpoint: "https://id.example.com/authorize?tenant=a%20b")
        let text = uri.absoluteString
        XCTAssertTrue(text.hasPrefix("https://id.example.com/authorize?tenant=a%20b&response_type=code"), text)
        XCTAssertEqual(text.filter { $0 == "?" }.count, 1)
    }

    func testAnEndpointThatIsNotAUrlIsAConfigurationFault() {
        XCTAssertThrowsError(try request().toUri(authorizationEndpoint: "not a url")) {
            guard case OAuthError.configuration(.invalidConfiguration) = $0 else { return XCTFail("\($0)") }
        }
    }

    func testToPendingCarriesWhatTheExchangeAndRestoreNeed() throws {
        let parameters = try AuthorizationParameters(resources: ["https://api.example.com"])
        let r = request(scopes: ["openid"], acrValues: ["urn:acr:2"], maxAge: 60, parameters: parameters)
        let pending = r.toPending(createdAt: AuthzKit.now, issRequired: true)
        XCTAssertEqual(pending.state, r.state)
        XCTAssertEqual(pending.nonce, r.nonce)
        XCTAssertEqual(pending.codeVerifier, r.codeVerifier.value)
        XCTAssertEqual(pending.scopes, ["openid"])
        XCTAssertEqual(pending.redirectUri, AuthzKit.redirect)
        XCTAssertEqual(pending.acrValues, ["urn:acr:2"])
        XCTAssertEqual(pending.maxAge, 60)
        XCTAssertEqual(pending.createdAt, AuthzKit.now)
        XCTAssertEqual(pending.resources, ["https://api.example.com"])
        XCTAssertTrue(pending.issRequired)
        XCTAssertFalse(r.toPending(createdAt: AuthzKit.now, issRequired: false).issRequired)
    }

    func testPendingDescriptionRedactsTheVerifier() {
        let pending = request().toPending(createdAt: AuthzKit.now, issRequired: false)
        XCTAssertFalse("\(pending)".contains(pending.codeVerifier))
    }

    // MARK: FormEncoding

    func testFormEncodingLeavesTheUnreservedSetAlone() {
        XCTAssertEqual(FormEncoding.encode([("a-b._~", "Zz09-._~")]), "a-b._~=Zz09-._~")
    }

    func testFormEncodingEscapesEverythingElseAsUppercaseUtf8Percent() {
        XCTAssertEqual(FormEncoding.encode([("k", " +/=&?#%\"é€")]), "k=%20%2B%2F%3D%26%3F%23%25%22%C3%A9%E2%82%AC")
    }

    func testFormEncodingKeepsPairOrderAndRepeatedNames() {
        XCTAssertEqual(FormEncoding.encode([("b", "1"), ("a", "2"), ("b", "3")]), "b=1&a=2&b=3")
        XCTAssertEqual(FormEncoding.encode([]), "")
    }

    func testFormEncodingBodyIsTheEncodedTextAsUtf8() {
        XCTAssertEqual(FormEncoding.body([("a", "b c")]), Data("a=b%20c".utf8))
    }

    func testWithQueryAddsNothingForNoPairs() throws {
        XCTAssertEqual(try FormEncoding.withQuery("https://id.example.com/x", []).absoluteString, "https://id.example.com/x")
    }
}
