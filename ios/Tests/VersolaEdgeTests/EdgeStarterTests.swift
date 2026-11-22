import Foundation
import XCTest
@testable import OAuthCore
@testable import VersolaEdge

/// `/native/start` and the starter built on it (`spec/versola-sdk-api.md` sections 5 and 7): the form
/// edge reads, the proof of each attempt, the answer's validation and what the pending request and the
/// browser URI are made of. The Android `HttpNativeAuthorizationStarterTest` and
/// `EdgeAuthorizationStarterTest`'s twin; stubs only, the wiring against a real edge is the
/// conformance tier.
final class EdgeStarterTests: XCTestCase {
    private typealias F = EdgeFixture

    private func native(_ http: ScriptedHTTP, dpop: DpopProofFactory = F.proofSource()) throws -> HTTPNativeAuthorizationStarter {
        try HTTPNativeAuthorizationStarter(clientId: F.clientId, edgeUrl: F.edgeUrl, httpClient: http, dpop: dpop)
    }

    private func edgeStarter(_ http: ScriptedHTTP, dpop: DpopProofFactory = F.proofSource(), redirect: String = F.redirect) throws -> EdgeAuthorizationStarter {
        let configuration = CoreConfiguration(issuer: F.issuer, clientId: F.clientId, redirectUri: URL(string: redirect)!)
        return try EdgeAuthorizationStarter(configuration: configuration, native: native(http, dpop: dpop))
    }

    private func authorizationRequest(
        scopes: [String] = ["openid", "offline_access"], acrValues: [String] = [], maxAge: Int? = nil, parameters: AuthorizationParameters = .none
    ) -> AuthorizationRequest {
        // `dpopJkt` is nil: a starter that binds the key itself leaves `dpop_jkt` out of what the flow builds.
        AuthorizationRequest.create(configuration: F.configuration, scopes: scopes, acrValues: acrValues, maxAge: maxAge, dpopJkt: nil, parameters: parameters)
    }

    private func started(_ http: ScriptedHTTP, request: AuthorizationRequest? = nil) async throws -> StartedAuthorization {
        try await edgeStarter(http).start(request: request ?? authorizationRequest(), metadata: AuthzMetadata.value, now: F.now)
    }

    private enum AuthzMetadata {
        static let value = ProviderMetadata(
            issuer: F.issuer, authorizationEndpoint: "https://id.example.com/authorize", tokenEndpoint: "https://id.example.com/native/token/mobile-app"
        )
    }

    // MARK: the form

    func testStartSendsEveryParameterEdgeForwardsAndNoneItDoesNot() async throws {
        let http = ScriptedHTTP([F.answer(200, [:], F.startAnswer())])
        let parameters = try AuthorizationParameters(
            prompt: .login, loginHint: "alice@example.com", uiLocales: ["fr-CA", "en"],
            resources: ["https://api.example.com/a", "https://api.example.com/b"],
            extra: ["claims": #"{"id_token":{"email":null}}"#, "authorization_details": #"[{"type":"payment"}]"#, "audience": "not-forwarded"]
        )

        _ = try await started(http, request: authorizationRequest(scopes: ["email", "openid"], acrValues: ["sensitive", "urn:acr:2"], maxAge: 300, parameters: parameters))

        let requests = await http.requests
        XCTAssertEqual(requests.count, 1)
        let request = try XCTUnwrap(requests.first)
        XCTAssertEqual(request.method, .post)
        XCTAssertEqual(request.url.absoluteString, F.startUrl)
        let form = F.decodeForm(request)
        XCTAssertEqual(form.map(\.0), [
            "redirect_uri", "scope", "nonce", "acr_values", "max_age", "prompt", "login_hint", "ui_locales",
            "resource", "resource", "claims", "authorization_details",
        ])
        let values = Dictionary(grouping: form, by: \.0).mapValues { $0.map(\.1) }
        XCTAssertEqual(values["redirect_uri"], [F.redirect])
        XCTAssertEqual(values["scope"], ["email openid"])
        XCTAssertEqual(values["acr_values"], ["sensitive urn:acr:2"])
        XCTAssertEqual(values["max_age"], ["300"])
        XCTAssertEqual(values["prompt"], ["login"])
        XCTAssertEqual(values["login_hint"], ["alice@example.com"])
        XCTAssertEqual(values["ui_locales"], ["fr-CA en"])
        XCTAssertEqual(values["resource"], ["https://api.example.com/a", "https://api.example.com/b"])
        XCTAssertEqual(values["claims"], [#"{"id_token":{"email":null}}"#])
        XCTAssertEqual(values["authorization_details"], [#"[{"type":"payment"}]"#])
        XCTAssertEqual(values["nonce"]?.first?.isEmpty, false)
    }

    func testStartNeverSendsWhatIsEdgesToDecide() async throws {
        let http = ScriptedHTTP([F.answer(200, [:], F.startAnswer())])
        // Every optional member set, so that a name that slipped in anywhere would show.
        let parameters = try AuthorizationParameters(
            prompt: .consent, loginHint: "h", uiLocales: ["en"], resources: ["https://api.example.com"],
            extra: ["claims": "{}", "authorization_details": "[]"]
        )

        _ = try await started(http, request: authorizationRequest(acrValues: ["a"], maxAge: 1, parameters: parameters))

        let names = Set(F.decodeForm(try await http.firstRequest()).map(\.0))
        for forbidden in ["client_id", "state", "response_type", "code_challenge", "code_challenge_method", "dpop_jkt", "id_token_hint", "request_uri"] {
            XCTAssertFalse(names.contains(forbidden), "\(forbidden) is edge's and is never sent")
        }
    }

    func testOnlyTheMembersThatAreSetAreSent() async throws {
        let http = ScriptedHTTP([F.answer(200, [:], F.startAnswer())])

        _ = try await started(http, request: authorizationRequest(scopes: ["openid"]))

        let form = F.decodeForm(try await http.firstRequest())
        XCTAssertEqual(form.map(\.0), ["redirect_uri", "scope", "nonce"])
    }

    func testClaimsAndAuthorizationDetailsAreTheOnlyEntriesOfTheCoresExtraMapThatAreForwarded() async throws {
        let http = ScriptedHTTP([F.answer(200, [:], F.startAnswer())])
        let parameters = try AuthorizationParameters(extra: ["audience": "a", "kc_idp_hint": "b", "claims": "{}"])

        _ = try await started(http, request: authorizationRequest(parameters: parameters))

        let form = F.decodeForm(try await http.firstRequest())
        XCTAssertTrue(form.contains { $0.0 == "claims" && $0.1 == "{}" })
        XCTAssertFalse(form.contains { $0.0 == "audience" || $0.0 == "kc_idp_hint" })
    }

    func testRequestIsAFormPostWithoutACredentialHeader() async throws {
        let http = ScriptedHTTP([F.answer(200, [:], F.startAnswer())])
        _ = try await started(http)
        let request = try await http.firstRequest()
        XCTAssertEqual(request.headers["Content-Type"], "application/x-www-form-urlencoded")
        XCTAssertNil(request.headers["Authorization"])
        XCTAssertNotNil(request.headers["DPoP"])
    }

    // MARK: proofs

    func testProofHtuIsTheStartUrlOnEdge() async throws {
        let http = ScriptedHTTP([F.answer(200, [:], F.startAnswer())])
        _ = try await started(http)
        let claims = F.proofClaims(try await http.firstRequest())
        XCTAssertEqual(claims["htu"] as? String, F.startUrl)
        XCTAssertEqual(claims["htm"] as? String, "POST")
        XCTAssertNil(claims["ath"], "there is no access token yet")
    }

    func testNonceChallengeIsAnsweredOnceWithANewProofCarryingTheNonce() async throws {
        let challenge = F.answer(401, ["WWW-Authenticate": #"DPoP error="use_dpop_nonce""#, "DPoP-Nonce": "edge-nonce-1"])
        let http = ScriptedHTTP([challenge, F.answer(200, [:], F.startAnswer())])

        _ = try await started(http)

        let requests = await http.requests
        XCTAssertEqual(requests.count, 2)
        let first = F.proofClaims(requests[0]), second = F.proofClaims(requests[1])
        XCTAssertNil(first["nonce"])
        XCTAssertEqual(second["nonce"] as? String, "edge-nonce-1")
        XCTAssertNotEqual(first["jti"] as? String, second["jti"] as? String, "edge refuses a start proof it has seen")
    }

    func testSecondNonceChallengeIsANonceLoopAndIsNotAnsweredAgain() async {
        let challenge = F.answer(401, ["WWW-Authenticate": #"DPoP error="use_dpop_nonce""#, "DPoP-Nonce": "edge-nonce-1"])
        let http = ScriptedHTTP([challenge])

        let error = await thrown { try await self.started(http) }

        XCTAssertEqual(error, .recoverable(.nonceLoop(origin: F.edgeOrigin)))
        let count = await http.requests.count
        XCTAssertEqual(count, 2, "one answer to the challenge, and no third request")
    }

    func testNonceChallengeWithoutANonceCannotBeAnswered() async {
        let http = ScriptedHTTP([F.answer(401, ["WWW-Authenticate": #"DPoP error="use_dpop_nonce""#])])
        let error = await thrown { try await self.started(http) }
        XCTAssertEqual(error, .recoverable(.nonceLoop(origin: F.edgeOrigin)))
        let count = await http.requests.count
        XCTAssertEqual(count, 1)
    }

    func testEveryAttemptOfARepeatedStartCarriesANewProof() async throws {
        let world = RetryWorld()
        let http = ScriptedHTTP([F.answer(503, ["Retry-After": "1"]), F.answer(502), F.answer(200, [:], F.startAnswer())])
        let starter = try edgeStarter(http)
        let request = authorizationRequest()

        _ = try await world.within(world.budget()) {
            try await starter.start(request: request, metadata: AuthzMetadata.value, now: F.now)
        }

        let requests = await http.requests
        XCTAssertEqual(requests.count, 3)
        let identifiers = requests.map { F.proofClaims($0)["jti"] as? String }
        XCTAssertEqual(Set(identifiers).count, 3, "a repeat is a new request and carries a new proof")
        XCTAssertFalse(identifiers.contains(nil))
    }

    // MARK: Retry-After and the budget, keyed by edge's origin

    func testRetryAfterOnA429IsReadAndTheCallIsRepeatedUnderTheBudget() async {
        let world = RetryWorld()
        let http = ScriptedHTTP([F.answer(429, ["Retry-After": "2"])])
        let starter = try! edgeStarter(http)
        let request = authorizationRequest()

        let error = await thrown {
            try await world.within(world.budget()) { try await starter.start(request: request, metadata: AuthzMetadata.value, now: F.now) }
        }

        let count = await http.requests.count
        XCTAssertEqual(count, 3, "maxAttemptsPerOrigin requests, the first included")
        guard case .recoverable(.server(let status, let retryAfter, let attempts, _))? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertEqual(status, 429)
        XCTAssertEqual(retryAfter, 2000)
        XCTAssertEqual(attempts, 3)
        XCTAssertTrue(world.delays.allSatisfy { $0 >= 2 }, "the budget waited what edge asked: \(world.delays)")
    }

    func testRetryAfterOnA503IsReadToo() async {
        let world = RetryWorld()
        let http = ScriptedHTTP([F.answer(503, ["Retry-After": "5"]), F.answer(200, [:], F.startAnswer())])
        let starter = try! edgeStarter(http)
        let request = authorizationRequest()

        let result = await thrown {
            try await world.within(world.budget()) { try await starter.start(request: request, metadata: AuthzMetadata.value, now: F.now) }
        }

        XCTAssertNil(result)
        XCTAssertEqual(world.delays.first.map { $0 >= 5 }, true)
    }

    func testRetryAfterThatDoesNotFitTheBudgetIsHandedToTheAppWithItsValueAndNothingIsRepeated() async {
        let world = RetryWorld()
        let http = ScriptedHTTP([F.answer(429, ["Retry-After": "3600"])])
        let starter = try! edgeStarter(http)
        let request = authorizationRequest()

        let error = await thrown {
            try await world.within(world.budget()) { try await starter.start(request: request, metadata: AuthzMetadata.value, now: F.now) }
        }

        let count = await http.requests.count
        XCTAssertEqual(count, 1)
        guard case .recoverable(.server(429, let retryAfter, _, _))? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertEqual(retryAfter, 3_600_000)
    }

    func testCooldownAfterARetryAfterIsKeyedByEdgesOriginAndRefusesTheNextStartWithoutSendingIt() async {
        let world = RetryWorld()
        let cooldown = RetryCooldown(clock: world.clock)
        let http = ScriptedHTTP([F.answer(429, ["Retry-After": "3600"])])
        let starter = try! edgeStarter(http)
        let request = authorizationRequest()
        _ = await thrown {
            try await world.within(world.budget(cooldown: cooldown)) { try await starter.start(request: request, metadata: AuthzMetadata.value, now: F.now) }
        }

        let again = await thrown {
            try await world.within(world.budget(cooldown: cooldown)) { try await starter.start(request: request, metadata: AuthzMetadata.value, now: F.now) }
        }

        let count = await http.requests.count
        XCTAssertEqual(count, 1, "the second start was refused before it was sent")
        guard case .recoverable(.server(_, _, 0, _))? = again else { return XCTFail("\(String(describing: again))") }
        // The check the coordinator makes at the start of a login is on the same origin.
        let blocked = await thrown { try await cooldown.check(F.edgeOrigin) }
        XCTAssertNotNil(blocked)
    }

    // MARK: refusals

    func testA404NamesTheClientEdgeDoesNotFront() async {
        let http = ScriptedHTTP([F.answer(404)])
        let error = await thrown { try await self.started(http) }
        XCTAssertEqual(error, .configuration(.facade(name: "edge_client_unknown", detail: F.clientId)))
        XCTAssertEqual(error?.code, "configuration.edge_client_unknown")
    }

    func testA400WithAnOAuthErrorIsAnAuthorizationRejectionWithItsCodeAndDescription() async {
        let http = ScriptedHTTP([F.answer(400, [:], #"{"error":"invalid_scope","error_description":"scope x is unknown"}"#)])
        let error = await thrown { try await self.started(http) }
        XCTAssertEqual(error, .configuration(.authorizationRejected(code: "invalid_scope", description: "scope x is unknown")))
    }

    func testA400ThatIsNotAnOAuthErrorIsATokenRequestRejectionAndIsNotRepeated() async {
        let http = ScriptedHTTP([F.answer(400, [:], "<html>bad</html>")])
        let error = await thrown { try await self.started(http) }
        guard case .configuration(.tokenRequestRejected(let code, nil))? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(code.contains("no OAuth error"), code)
        let count = await http.requests.count
        XCTAssertEqual(count, 1)
    }

    func testARedirectIsNotFollowed() async {
        let http = ScriptedHTTP([F.answer(307, ["Location": "https://evil.example.com/native/start/mobile-app"])])
        let error = await thrown { try await self.started(http) }
        guard case .configuration(.tokenRequestRejected(let code, _))? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(code.contains("redirects are not followed"), code)
        XCTAssertFalse(code.contains("evil"), "the Location is not reported")
        let count = await http.requests.count
        XCTAssertEqual(count, 1)
    }

    func testATransportFailureIsANetworkError() async {
        let http = ScriptedHTTP(steps: [.fail])
        let error = await thrown { try await self.started(http) }
        guard case .recoverable(.network)? = error else { return XCTFail("\(String(describing: error))") }
    }

    // MARK: the answer

    func testEveryMemberTheSignInCannotDoWithoutIsRefusedByNameAndNeverByValue() async {
        let secret = "v1.kz-1.SECRET-VALUE"
        for member in ["request_uri", "state", "blob", "authorization_endpoint", "token_endpoint", "revocation_endpoint", "expires_in"] {
            for absent in [true, false] {
                // Absent, and (for the strings) blank.
                if !absent && member == "expires_in" { continue }
                var overrides: [String: Any?] = [member: nil]
                if !absent { overrides = [member: "  "] }
                let http = ScriptedHTTP([F.answer(200, [:], F.startAnswer(overrides.merging(["blob": member == "blob" ? nil : secret]) { a, _ in a }))])
                let error = await thrown { try await self.started(http) }
                guard case .configuration(.tokenResponseMalformed(let detail))? = error else { XCTFail("\(member): \(String(describing: error))"); continue }
                XCTAssertTrue(detail.contains(member), "\(member): \(detail)")
                XCTAssertFalse(detail.contains(secret), "the value is never in the message")
            }
        }
    }

    func testExpiresInThatIsNotPositiveIsRefused() async {
        for value in [0, -5] {
            let http = ScriptedHTTP([F.answer(200, [:], F.startAnswer(["expires_in": value]))])
            let error = await thrown { try await self.started(http) }
            guard case .configuration(.tokenResponseMalformed(let detail))? = error else { XCTFail("\(value): \(String(describing: error))"); continue }
            XCTAssertTrue(detail.contains("expires_in"), detail)
        }
    }

    func testEachOfTheThreeEndpointsMustBeHttps() async {
        for member in ["authorization_endpoint", "token_endpoint", "revocation_endpoint"] {
            for insecure in ["http://auth.example.com/x", "http://10.0.2.2/x", "ftp://auth.example.com/x", "not a url", "//auth.example.com/x"] {
                let http = ScriptedHTTP([F.answer(200, [:], F.startAnswer([member: insecure]))])
                let error = await thrown { try await self.started(http) }
                guard case .configuration(.tokenResponseMalformed(let detail))? = error else { XCTFail("\(member) \(insecure): \(String(describing: error))"); continue }
                XCTAssertTrue(detail.contains(member), detail)
                XCTAssertFalse(detail.contains(insecure), "the value is not in the message")
            }
        }
    }

    func testCleartextToALoopbackHostIsAcceptedForTheEndpoints() async throws {
        for host in ["http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"] {
            let http = ScriptedHTTP([F.answer(200, [:], F.startAnswer([
                "authorization_endpoint": host + "/authorize", "token_endpoint": host + "/token", "revocation_endpoint": host + "/revoke",
            ]))])
            let result = try await started(http)
            XCTAssertEqual(result.pending.extensions[EdgeExtension.tokenEndpoint], host + "/token")
        }
    }

    func testAnAnswerThatIsNotAStartResponseIsMalformed() async {
        for body in ["not json", "[]", "null", #"{"request_uri":1}"#, #"{"expires_in":"soon"}"#] {
            let http = ScriptedHTTP([F.answer(200, [:], body)])
            let error = await thrown { try await self.started(http) }
            guard case .configuration(.tokenResponseMalformed)? = error else { XCTFail("\(body): \(String(describing: error))"); continue }
        }
    }

    func testTheAnswersDescriptionNeverCarriesTheBlobTheStateOrTheRequestUri() throws {
        let answer = try NativeStart.parse(Data(F.startAnswer().utf8))
        for text in [answer.description, answer.debugDescription, "\(answer)", String(reflecting: answer)] {
            XCTAssertFalse(text.contains("v1.kz-1.aB-c_D.e~f"), text)
            XCTAssertFalse(text.contains("edge-state-1"), text)
            XCTAssertFalse(text.contains(F.requestUri), text)
        }
    }

    // MARK: what is persisted and what the browser opens

    func testPendingRequestCarriesEdgesStateTheBlobAndTheTwoEndpointsAndRequiresIss() async throws {
        let http = ScriptedHTTP([F.answer(200, [:], F.startAnswer())])
        let request = authorizationRequest(scopes: ["openid", "email"], acrValues: ["a"], maxAge: 30)

        let result = try await started(http, request: request)

        let pending = result.pending
        XCTAssertEqual(pending.state, "edge-state-1", "edge's state, not the flow's own")
        XCTAssertNotEqual(pending.state, request.state)
        XCTAssertEqual(pending.nonce, request.nonce)
        XCTAssertEqual(pending.codeVerifier, "", "the verifier is edge's, sealed in the blob")
        XCTAssertEqual(pending.scopes, ["openid", "email"])
        XCTAssertEqual(pending.acrValues, ["a"])
        XCTAssertEqual(pending.maxAge, 30)
        XCTAssertEqual(pending.redirectUri, F.redirect)
        XCTAssertTrue(pending.issRequired)
        XCTAssertEqual(pending.createdAt, F.now)
        XCTAssertEqual(pending.extensions, [
            EdgeExtension.blob: "v1.kz-1.aB-c_D.e~f",
            EdgeExtension.tokenEndpoint: F.tokenEndpoint,
            EdgeExtension.revocationEndpoint: F.revocationEndpoint,
        ])
    }

    func testStarterBindsTheDpopKeyItself() throws {
        XCTAssertTrue(try edgeStarter(ScriptedHTTP([])).bindsDpopKeyItself)
    }

    func testLifetimeIsExpiresInCappedAtTenMinutes() async throws {
        for (expiresIn, expected) in [(90, 90.0), (600, 600), (601, 600), (86_400, 600), (1, 1)] {
            let http = ScriptedHTTP([F.answer(200, [:], F.startAnswer(["expires_in": expiresIn]))])
            let result = try await started(http)
            XCTAssertEqual(result.pending.lifetime, expected, "expires_in \(expiresIn)")
            XCTAssertEqual(result.expiresAt, F.now.addingTimeInterval(expected), "expires_in \(expiresIn)")
            XCTAssertTrue(result.pending.isExpired(at: F.now.addingTimeInterval(expected + 1)))
            XCTAssertFalse(result.pending.isExpired(at: F.now.addingTimeInterval(expected - 0.5)))
        }
    }

    func testBrowserOpensTheAuthorizationEndpointEdgeAnsweredWithExactlyClientIdAndRequestUri() async throws {
        let http = ScriptedHTTP([F.answer(200, [:], F.startAnswer())])

        let result = try await started(http)

        let components = try XCTUnwrap(URLComponents(url: result.browserUri, resolvingAgainstBaseURL: false))
        XCTAssertEqual("\(components.scheme ?? "")://\(components.host ?? "")\(components.path)", F.authorizationEndpoint)
        XCTAssertEqual(components.queryItems?.map(\.name), ["client_id", "request_uri"])
        XCTAssertEqual(components.queryItems?.first { $0.name == "client_id" }?.value, F.clientId)
    }

    func testRequestUriRoundTripsThroughTheBrowserUriByteForByte() async throws {
        for requestUri in [F.requestUri, "urn:ietf:params:oauth:request_uri:v1.kz-2.Zz+/=", "urn:x:a b&c=d?e#f%41"] {
            let http = ScriptedHTTP([F.answer(200, [:], F.startAnswer(["request_uri": requestUri]))])

            let result = try await started(http)

            let query = result.browserUri.absoluteString.split(separator: "?", maxSplits: 1).last.map(String.init) ?? ""
            let pairs = query.split(separator: "&").map { $0.split(separator: "=", maxSplits: 1).map(String.init) }
            XCTAssertEqual(pairs.count, 2, requestUri)
            XCTAssertEqual(pairs[1][0], "request_uri")
            XCTAssertEqual(pairs[1][1].removingPercentEncoding, requestUri, "decoded once, it is the value edge sent")
            // Percent-encoded as a query value, and otherwise untouched: only the unreserved set stands bare.
            XCTAssertTrue(pairs[1][1].allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || "-._~%".contains($0)) }, pairs[1][1])
        }
        let plain = FormEncoding.percentEncode(F.requestUri)
        XCTAssertEqual(plain, "urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Av1.kz-1.AbC_d-9")
    }

    func testMetadatasAuthorizationEndpointIsNeverUsed() async throws {
        let http = ScriptedHTTP([F.answer(200, [:], F.startAnswer())])
        let metadata = ProviderMetadata(issuer: F.issuer, authorizationEndpoint: "https://issuer-decoy.example.com/authorize", tokenEndpoint: "https://id.example.com/t")

        let result = try await edgeStarter(http).start(request: authorizationRequest(), metadata: metadata, now: F.now)

        XCTAssertEqual(result.browserUri.host, "login.example.com")
        XCTAssertFalse(result.browserUri.absoluteString.contains("decoy"))
    }

    func testAnAuthorizationEndpointThatAlreadyHasAQueryGetsTheParametersAppended() async throws {
        let http = ScriptedHTTP([F.answer(200, [:], F.startAnswer(["authorization_endpoint": "https://login.example.com/authorize?tenant=t1"]))])
        let result = try await started(http)
        XCTAssertTrue(result.browserUri.absoluteString.hasPrefix("https://login.example.com/authorize?tenant=t1&client_id=mobile-app&request_uri="), result.browserUri.absoluteString)
    }

    func testNoRequestIsMadeToTheIssuerOrToAnythingButEdgesStartUrl() async throws {
        let http = ScriptedHTTP([F.answer(200, [:], F.startAnswer())])
        _ = try await started(http)
        let urls = await http.requests.map(\.url.absoluteString)
        XCTAssertEqual(urls, [F.startUrl])
    }

    // MARK: construction

    func testARedirectUriThatIsNotHttpsIsRefusedAtConstruction() {
        for redirect in ["http://app.example.com/callback", "com.example.app:/callback", "http://localhost/callback", "http://127.0.0.1/callback"] {
            XCTAssertThrowsError(try edgeStarter(ScriptedHTTP([]), redirect: redirect), redirect) { error in
                guard case .configuration(.invalidConfiguration)? = error as? OAuthError else { return XCTFail("\(error)") }
            }
        }
        XCTAssertNoThrow(try edgeStarter(ScriptedHTTP([])))
    }

    func testClientIdIsEncodedAsOnePathSegmentOfTheStartUrl() throws {
        let url = try edgeNativeUrl(F.edgeUrl, endpoint: "start", clientId: "a/b c?d")
        XCTAssertEqual(url.absoluteString, "https://id.example.com/native/start/a%2Fb%20c%3Fd")
        let trailing = try edgeNativeUrl(URL(string: "https://id.example.com/")!, endpoint: "token", clientId: "c")
        XCTAssertEqual(trailing.absoluteString, "https://id.example.com/native/token/c")
    }
}
