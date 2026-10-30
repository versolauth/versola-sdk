import CryptoKit
import Foundation
import XCTest
@testable import OAuthCore

/// A session that hands out a first token and then, on `renewAccessToken()`, the next.
private actor JoseTokenSource: AccessTokenSource {
    private var tokens: [AccessToken]
    private(set) var renewals = 0
    private(set) var reads = 0

    init(_ tokens: [AccessToken]) { self.tokens = tokens }

    func accessToken() async throws -> AccessToken {
        reads += 1
        return tokens[0]
    }

    func renewAccessToken() async throws -> AccessToken {
        renewals += 1
        if tokens.count > 1 { tokens.removeFirst() }
        return tokens[0]
    }
}

final class UserInfoClientTests: XCTestCase {
    private let endpoint = "https://issuer.example.com/userinfo?ignored=1"
    private let jwksUri = "https://issuer.example.com/jwks.json"
    private let bearer = AccessToken(value: "access-1", tokenType: "Bearer")
    private let json = ["Content-Type": "application/json"]

    private func client(_ stub: JoseStubHTTP, endpoint: String? = nil, dpop: DpopProofSource? = nil, noEndpoint: Bool = false) -> HTTPUserInfoClient {
        let resolved = endpoint ?? self.endpoint
        let uri = jwksUri
        return HTTPUserInfoClient(
            userinfoEndpoint: { noEndpoint ? nil : resolved }, httpClient: stub, dpop: dpop,
            verifier: JwsVerifier(jwksUri: { uri }, allowedAlgorithms: { [] }, jwks: JwksClient(httpClient: stub))
        )
    }

    private func rejected(_ error: Error?) -> String? {
        if case .configuration(.userInfoRejected(let detail))? = error as? OAuthError { return detail }
        return nil
    }

    // MARK: bearer

    func testBearerTokenIsSentAsBearerWithNoProofAndJsonClaimsComeBackAsText() async throws {
        let stub = JoseStubHTTP()
        await stub.enqueue("/userinfo", headers: json, text: #"{"sub":"user-1","name":"Ada","email_verified":true,"age":36,"address":{"city":"X"}}"#)

        let info = try await client(stub).fetch(tokens: JoseTokenSource([bearer]), expectedSubject: "user-1")

        XCTAssertEqual(info.subject, "user-1")
        XCTAssertEqual(info.claims["name"], "Ada")
        XCTAssertEqual(info.claims["email_verified"], "true")
        XCTAssertEqual(info.claims["age"], "36")
        XCTAssertEqual(info.claims["address"], #"{"city":"X"}"#)
        XCTAssertEqual(info.description, "UserInfo(redacted)")
        let request = await stub.requests[0]
        XCTAssertEqual(request.method, .get)
        XCTAssertEqual(request.headers["Authorization"], "Bearer access-1")
        XCTAssertNil(request.headers["DPoP"])
        XCTAssertTrue(request.headers["Accept"]?.contains("application/json") == true)
    }

    func testBearerTokenIsNotGivenAProofEvenWhenAProofSourceIsWired() async throws {
        let stub = JoseStubHTTP()
        await stub.enqueue("/userinfo", headers: json, text: #"{"sub":"user-1"}"#)
        let dpop = DpopProofFactory(key: SoftwareDpopKey())

        _ = try await client(stub, dpop: dpop).fetch(tokens: JoseTokenSource([bearer]), expectedSubject: "user-1")

        let request = await stub.requests[0]
        XCTAssertEqual(request.headers["Authorization"], "Bearer access-1")
        XCTAssertNil(request.headers["DPoP"])
    }

    func testMissingUserinfoEndpointIsProviderUnsupportedAndNothingIsSent() async {
        let stub = JoseStubHTTP()
        let error = await joseThrown { _ = try await client(stub, noEndpoint: true).fetch(tokens: JoseTokenSource([bearer]), expectedSubject: "user-1") }
        let count = await stub.requestCount()
        XCTAssertEqual(error as? OAuthError, .configuration(.providerUnsupported(capability: "userinfo")))
        XCTAssertEqual(count, 0)
    }

    // MARK: sub

    func testSubThatDiffersFromTheIdTokensIsRefusedWithoutEchoingEitherValue() async {
        let stub = JoseStubHTTP()
        await stub.enqueue("/userinfo", headers: json, text: #"{"sub":"someone-else"}"#)
        let error = await joseThrown { _ = try await client(stub).fetch(tokens: JoseTokenSource([bearer]), expectedSubject: "user-1") }
        let detail = rejected(error)
        XCTAssertNotNil(detail)
        XCTAssertFalse(detail?.contains("someone-else") == true)
        XCTAssertFalse(detail?.contains("user-1") == true)
    }

    func testResponseWithoutSubOrWithANonStringSubIsRefused() async {
        for body in [#"{"name":"Ada"}"#, #"{"sub":5}"#, #"{"sub":null}"#] {
            let stub = JoseStubHTTP()
            await stub.enqueue("/userinfo", headers: json, text: body)
            let error = await joseThrown { _ = try await client(stub).fetch(tokens: JoseTokenSource([bearer]), expectedSubject: "user-1") }
            XCTAssertNotNil(rejected(error), body)
        }
    }

    func testBodyThatIsNotAJsonObjectIsRefused() async {
        for body in ["not json", "[1]", #""user-1""#, ""] {
            let stub = JoseStubHTTP()
            await stub.enqueue("/userinfo", headers: json, text: body)
            let error = await joseThrown { _ = try await client(stub).fetch(tokens: JoseTokenSource([bearer]), expectedSubject: "user-1") }
            XCTAssertNotNil(rejected(error), body)
        }
    }

    // MARK: 401

    func testBare401SpendsOneRenewalAndOneReplayAndTheReplayAnswers() async throws {
        let stub = JoseStubHTTP()
        await stub.enqueue("/userinfo", status: 401, headers: ["WWW-Authenticate": #"Bearer error="invalid_token""#])
        await stub.enqueue("/userinfo", headers: json, text: #"{"sub":"user-1"}"#)
        let source = JoseTokenSource([bearer, AccessToken(value: "access-2", tokenType: "Bearer")])

        let info = try await client(stub).fetch(tokens: source, expectedSubject: "user-1")

        XCTAssertEqual(info.subject, "user-1")
        let renewals = await source.renewals
        let requests = await stub.requests
        XCTAssertEqual(renewals, 1)
        XCTAssertEqual(requests.map { $0.headers["Authorization"] }, ["Bearer access-1", "Bearer access-2"])
    }

    func testTwo401sEndInSessionRejectedAfterExactlyOneRenewal() async {
        let stub = JoseStubHTTP()
        await stub.enqueue("/userinfo", status: 401)
        await stub.enqueue("/userinfo", status: 401)
        await stub.enqueue("/userinfo", headers: json, text: #"{"sub":"user-1"}"#)  // a third attempt would be seen
        let source = JoseTokenSource([bearer, AccessToken(value: "access-2", tokenType: "Bearer")])

        let error = await joseThrown { _ = try await client(stub).fetch(tokens: source, expectedSubject: "user-1") }

        XCTAssertEqual(error as? OAuthError, .reauthenticate(.sessionRejected))
        let renewals = await source.renewals
        let count = await stub.requestCount()
        XCTAssertEqual(renewals, 1)
        XCTAssertEqual(count, 2)
    }

    func testOtherStatusesAreTypedNotRetried() async {
        for (status, expectRecoverable) in [(500, true), (503, true), (429, true), (403, false), (404, false), (400, false)] {
            let stub = JoseStubHTTP()
            await stub.enqueue("/userinfo", status: status)
            let source = JoseTokenSource([bearer])
            let error = await joseThrown { _ = try await client(stub).fetch(tokens: source, expectedSubject: "user-1") }
            if expectRecoverable {
                guard case .recoverable(.server(let seen, _, _, _))? = error as? OAuthError, seen == status else { return XCTFail("status \(status): \(String(describing: error))") }
            } else {
                XCTAssertEqual(rejected(error), "userinfo answered \(status)")
            }
            let count = await stub.requestCount()
            let renewals = await source.renewals
            XCTAssertEqual(count, 1, "status \(status)")
            XCTAssertEqual(renewals, 0, "status \(status)")
        }
    }

    func testRedirectIsNotFollowed() async {
        let stub = JoseStubHTTP()
        await stub.enqueue("/userinfo", status: 302, headers: ["Location": "https://evil.example.com/userinfo"])
        let error = await joseThrown { _ = try await client(stub).fetch(tokens: JoseTokenSource([bearer]), expectedSubject: "user-1") }
        XCTAssertEqual(rejected(error), "userinfo answered 302")
        let count = await stub.requestCount()
        XCTAssertEqual(count, 1)
    }

    func testTransportFailureIsARecoverableNetworkFailure() async {
        let stub = JoseStubHTTP()
        await stub.enqueueFailure("/userinfo")
        let error = await joseThrown { _ = try await client(stub).fetch(tokens: JoseTokenSource([bearer]), expectedSubject: "user-1") }
        guard case .recoverable(.network)? = error as? OAuthError else { return XCTFail("\(String(describing: error))") }
    }

    // MARK: signed responses

    private func signedJwks() async -> JoseStubHTTP {
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(JoseTestKeys.rsa.jwk(kid: "rsa"), JoseTestKeys.p256.jwk(kid: "ec")))
        return stub
    }

    func testApplicationJwtResponseIsVerifiedAgainstTheKeySetAndItsPayloadIsUsed() async throws {
        let stub = await signedJwks()
        let token = JoseTestTokens.rsa("RS256", payload: #"{"sub":"user-1","name":"Ada","n":3}"#)
        await stub.enqueue("/userinfo", headers: ["Content-Type": "application/jwt"], text: token + "\n")

        let info = try await client(stub).fetch(tokens: JoseTokenSource([bearer]), expectedSubject: "user-1")

        XCTAssertEqual(info.claims["name"], "Ada")
        XCTAssertEqual(info.claims["n"], "3")
    }

    func testEs256SignedResponseVerifiesAndAContentTypeParameterIsTolerated() async throws {
        let stub = await signedJwks()
        let token = JoseTestTokens.ec(JoseTestKeys.p256, payload: #"{"sub":"user-1"}"#, kid: "ec")
        await stub.enqueue("/userinfo", headers: ["Content-Type": "Application/JWT; charset=utf-8"], text: token)

        let info = try await client(stub).fetch(tokens: JoseTokenSource([bearer]), expectedSubject: "user-1")
        XCTAssertEqual(info.subject, "user-1")
    }

    func testCompactJwsBodyUnderAnotherContentTypeIsVerifiedToo() async throws {
        let stub = await signedJwks()
        await stub.enqueue("/userinfo", headers: ["Content-Type": "text/plain"], text: JoseTestTokens.rsa("RS256", payload: #"{"sub":"user-1"}"#))
        let info = try await client(stub).fetch(tokens: JoseTokenSource([bearer]), expectedSubject: "user-1")
        XCTAssertEqual(info.subject, "user-1")
    }

    func testSignedResponseWithABadSignatureIsRefused() async {
        let stub = await signedJwks()
        let token = JoseTestTokens.rsa("RS256", JoseTestKeys.rsaOther, payload: #"{"sub":"user-1"}"#)
        await stub.enqueue("/userinfo", headers: ["Content-Type": "application/jwt"], text: token)
        let error = await joseThrown { _ = try await client(stub).fetch(tokens: JoseTokenSource([bearer]), expectedSubject: "user-1") }
        XCTAssertEqual(rejected(error), "the signed response does not verify (signature)")
    }

    func testSignedResponseUsingAlgNoneIsRefusedAndTheKeySetIsNeverFetched() async {
        let stub = JoseStubHTTP()
        let token = JoseTestTokens.jws(header: #"{"alg":"none"}"#, payload: #"{"sub":"user-1"}"#, sign: nil)
        await stub.enqueue("/userinfo", headers: ["Content-Type": "application/jwt"], text: token)
        let error = await joseThrown { _ = try await client(stub).fetch(tokens: JoseTokenSource([bearer]), expectedSubject: "user-1") }
        let jwksRequests = await stub.requestCount(path: "/jwks.json")
        XCTAssertEqual(rejected(error), "the signed response does not verify (algorithm)")
        XCTAssertEqual(jwksRequests, 0)
    }

    func testSignedResponseThatIsNotAJwsIsRefused() async {
        let stub = JoseStubHTTP()
        await stub.enqueue("/userinfo", headers: ["Content-Type": "application/jwt"], text: "definitely not a jws")
        let error = await joseThrown { _ = try await client(stub).fetch(tokens: JoseTokenSource([bearer]), expectedSubject: "user-1") }
        XCTAssertEqual(rejected(error), "the signed response does not verify (malformed)")
    }

    func testSignedResponseWithADifferentSubIsRefused() async {
        let stub = await signedJwks()
        await stub.enqueue("/userinfo", headers: ["Content-Type": "application/jwt"], text: JoseTestTokens.rsa("RS256", payload: #"{"sub":"someone-else"}"#))
        let error = await joseThrown { _ = try await client(stub).fetch(tokens: JoseTokenSource([bearer]), expectedSubject: "user-1") }
        XCTAssertEqual(rejected(error), "sub does not match the ID token's")
    }

    func testSignedResponseWhoseKeySetCannotBeFetchedIsAServerFailure() async {
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", status: 500)
        await stub.enqueue("/userinfo", headers: ["Content-Type": "application/jwt"], text: JoseTestTokens.rsa("RS256", payload: #"{"sub":"user-1"}"#))
        let error = await joseThrown { _ = try await client(stub).fetch(tokens: JoseTokenSource([bearer]), expectedSubject: "user-1") }
        guard case .recoverable(.server(500, _, _, _))? = error as? OAuthError else { return XCTFail("\(String(describing: error))") }
    }

    // MARK: Server errors (spec/retry-policy.md, scenario 34)

    private func operationBudget() -> RetryBudget {
        RetryPolicy.default.newBudget(random: SystemRandomSource(), sleep: { _ in })
    }

    func testUserInfoIsRepeatedUnderTheOperationsBudgetOnTransientStatuses() async {
        for status in [500, 502, 503, 504, 408, 429] {
            let stub = JoseStubHTTP()
            for _ in 0..<3 { await stub.enqueue("/userinfo", status: status) }
            let source = JoseTokenSource([bearer])
            let budget = operationBudget()
            let error = await joseThrown {
                _ = try await OperationBudget.$current.withValue(budget) {
                    try await self.client(stub).fetch(tokens: source, expectedSubject: "user-1")
                }
            }
            let count = await stub.requestCount()
            XCTAssertEqual(count, 3, "HTTP \(status): maxAttemptsPerOrigin requests, original included")
            guard case .recoverable(.server(let seen, nil, 3, _))? = error as? OAuthError, seen == status else { XCTFail("HTTP \(status): \(String(describing: error))"); continue }
            let renewals = await source.renewals
            XCTAssertEqual(renewals, 0, "a server error is not an expired token")
        }
    }

    func testUserInfoSucceedsOnTheRepeatAfterATransientAnswer() async throws {
        let stub = JoseStubHTTP()
        await stub.enqueue("/userinfo", status: 503)
        await stub.enqueue("/userinfo", headers: json, text: #"{"sub":"user-1","name":"A"}"#)
        let budget = operationBudget()
        let info = try await OperationBudget.$current.withValue(budget) {
            try await self.client(stub).fetch(tokens: JoseTokenSource([bearer]), expectedSubject: "user-1")
        }
        XCTAssertEqual(info.subject, "user-1")
        let count = await stub.requestCount()
        XCTAssertEqual(count, 2)
    }

    func testUserInfoIsNotRepeatedOnA501OrARefusal() async {
        for status in [501, 403, 404] {
            let stub = JoseStubHTTP()
            for _ in 0..<3 { await stub.enqueue("/userinfo", status: status) }
            let budget = operationBudget()
            _ = await joseThrown {
                _ = try await OperationBudget.$current.withValue(budget) {
                    try await self.client(stub).fetch(tokens: JoseTokenSource([bearer]), expectedSubject: "user-1")
                }
            }
            let count = await stub.requestCount()
            XCTAssertEqual(count, 1, "HTTP \(status)")
        }
    }

    func testARetryAfterOnUserInfoBeyondTheBudgetIsReturnedWithoutAnotherRequest() async {
        let stub = JoseStubHTTP()
        await stub.enqueue("/userinfo", status: 429, headers: ["Retry-After": "90"])
        await stub.enqueue("/userinfo", status: 429, headers: ["Retry-After": "90"])
        let budget = operationBudget()
        let error = await joseThrown {
            _ = try await OperationBudget.$current.withValue(budget) {
                try await self.client(stub).fetch(tokens: JoseTokenSource([bearer]), expectedSubject: "user-1")
            }
        }
        let count = await stub.requestCount()
        XCTAssertEqual(count, 1)
        XCTAssertEqual(error as? OAuthError, .recoverable(.server(status: 429, retryAfterMillis: 90_000, attempts: 1, elapsedMillis: 0)))
    }

    // MARK: DPoP

    private let bound = AccessToken(value: "access-dpop", tokenType: "DPoP")
    private let challenge = ["WWW-Authenticate": #"DPoP error="use_dpop_nonce", error_description="Resource server requires nonce in DPoP proof""#, "DPoP-Nonce": "server-nonce-1"]

    func testDpopBoundTokenIsSentAsDpopWithAProofForGetOnTheEndpointWithoutQueryAndBoundToTheToken() async throws {
        let stub = JoseStubHTTP()
        await stub.enqueue("/userinfo", headers: json, text: #"{"sub":"user-1"}"#)
        let dpop = DpopProofFactory(key: SoftwareDpopKey(), clock: Clock(now: { Date(timeIntervalSince1970: 1_900_000_000) }))

        _ = try await client(stub, dpop: dpop).fetch(tokens: JoseTokenSource([bound]), expectedSubject: "user-1")

        let request = await stub.requests[0]
        XCTAssertEqual(request.headers["Authorization"], "DPoP access-dpop")
        let proof = try XCTUnwrap(request.headers["DPoP"])
        let decoded = JoseTestTokens.decode(proof)
        XCTAssertEqual(decoded.claims["htm"] as? String, "GET")
        XCTAssertEqual(decoded.claims["htu"] as? String, "https://issuer.example.com/userinfo")
        XCTAssertEqual(decoded.claims["ath"] as? String, JoseBase64Url.encode(Data(SHA256.hash(data: Data("access-dpop".utf8)))))
        XCTAssertNil(decoded.claims["nonce"])
    }

    func testUseDpopNonceChallengeIsAnsweredOnceWithTheNonceInAFreshProof() async throws {
        let stub = JoseStubHTTP()
        await stub.enqueue("/userinfo", status: 401, headers: challenge)
        await stub.enqueue("/userinfo", headers: json, text: #"{"sub":"user-1"}"#)
        let dpop = DpopProofFactory(key: SoftwareDpopKey())
        let source = JoseTokenSource([bound])

        let info = try await client(stub, dpop: dpop).fetch(tokens: source, expectedSubject: "user-1")

        XCTAssertEqual(info.subject, "user-1")
        let requests = await stub.requests
        XCTAssertEqual(requests.count, 2)
        let first = JoseTestTokens.decode(try XCTUnwrap(requests[0].headers["DPoP"]))
        let second = JoseTestTokens.decode(try XCTUnwrap(requests[1].headers["DPoP"]))
        XCTAssertNil(first.claims["nonce"])
        XCTAssertEqual(second.claims["nonce"] as? String, "server-nonce-1")
        XCTAssertNotEqual(first.claims["jti"] as? String, second.claims["jti"] as? String)
        let renewals = await source.renewals
        XCTAssertEqual(renewals, 0, "a nonce challenge is not an expired token")
        let remembered = await dpop.nonce(for: "https://issuer.example.com")
        XCTAssertEqual(remembered, "server-nonce-1")
    }

    /// A repeated request carries a proof of its own: a `jti` is single-use, and replaying the proof
    /// of the request that failed is what a resource server would refuse.
    func testARepeatedDpopBoundUserInfoRequestCarriesAFreshProof() async throws {
        let stub = JoseStubHTTP()
        await stub.enqueue("/userinfo", status: 503)
        await stub.enqueue("/userinfo", headers: json, text: #"{"sub":"user-1"}"#)
        let dpop = DpopProofFactory(key: SoftwareDpopKey())
        let budget = operationBudget()

        _ = try await OperationBudget.$current.withValue(budget) {
            try await self.client(stub, dpop: dpop).fetch(tokens: JoseTokenSource([self.bound]), expectedSubject: "user-1")
        }

        let requests = await stub.requests
        XCTAssertEqual(requests.count, 2)
        let first = JoseTestTokens.decode(try XCTUnwrap(requests[0].headers["DPoP"]))
        let second = JoseTestTokens.decode(try XCTUnwrap(requests[1].headers["DPoP"]))
        XCTAssertNotNil(first.claims["jti"] as? String)
        XCTAssertNotEqual(first.claims["jti"] as? String, second.claims["jti"] as? String, "two attempts, two proofs")
        XCTAssertEqual(second.claims["ath"] as? String, first.claims["ath"] as? String, "both bound to the same token")
    }

    func testSecondUseDpopNonceChallengeIsNonceLoopAndEndsTheExchange() async {
        let stub = JoseStubHTTP()
        await stub.enqueue("/userinfo", status: 401, headers: challenge)
        await stub.enqueue("/userinfo", status: 401, headers: challenge.merging(["DPoP-Nonce": "server-nonce-2"]) { $1 })
        await stub.enqueue("/userinfo", headers: json, text: #"{"sub":"user-1"}"#)  // a third attempt would be seen
        let dpop = DpopProofFactory(key: SoftwareDpopKey())

        let error = await joseThrown { _ = try await client(stub, dpop: dpop).fetch(tokens: JoseTokenSource([bound]), expectedSubject: "user-1") }

        XCTAssertEqual(error as? OAuthError, .recoverable(.nonceLoop(origin: "https://issuer.example.com")))
        let count = await stub.requestCount()
        XCTAssertEqual(count, 2)
    }

    func testChallengeWithoutANonceHeaderCannotBeAnsweredAndIsNonceLoop() async {
        let stub = JoseStubHTTP()
        await stub.enqueue("/userinfo", status: 401, headers: ["WWW-Authenticate": #"DPoP error="use_dpop_nonce""#])
        let dpop = DpopProofFactory(key: SoftwareDpopKey())
        let error = await joseThrown { _ = try await client(stub, dpop: dpop).fetch(tokens: JoseTokenSource([bound]), expectedSubject: "user-1") }
        XCTAssertEqual(error as? OAuthError, .recoverable(.nonceLoop(origin: "https://issuer.example.com")))
        let count = await stub.requestCount()
        XCTAssertEqual(count, 1)
    }

    func testBound401WithAnotherErrorSpendsTheRenewalNotTheNonceRetry() async throws {
        let stub = JoseStubHTTP()
        await stub.enqueue("/userinfo", status: 401, headers: ["WWW-Authenticate": #"DPoP error="invalid_token""#])
        await stub.enqueue("/userinfo", headers: json, text: #"{"sub":"user-1"}"#)
        let source = JoseTokenSource([bound, AccessToken(value: "access-dpop-2", tokenType: "DPoP")])
        _ = try await client(stub, dpop: DpopProofFactory(key: SoftwareDpopKey())).fetch(tokens: source, expectedSubject: "user-1")
        let renewals = await source.renewals
        XCTAssertEqual(renewals, 1)
    }

    func testDpopBoundTokenWithoutAProofSourceIsInvalidConfigurationAndNothingIsSent() async {
        let stub = JoseStubHTTP()
        let error = await joseThrown { _ = try await client(stub).fetch(tokens: JoseTokenSource([bound]), expectedSubject: "user-1") }
        let count = await stub.requestCount()
        guard case .configuration(.invalidConfiguration)? = error as? OAuthError else { return XCTFail("\(String(describing: error))") }
        XCTAssertEqual(count, 0)
    }

    // MARK: the challenge parser

    func testWwwAuthenticateErrorIsReadFromTheParameterAndNotFromQuotedText() {
        XCTAssertEqual(WwwAuthenticate.error(#"DPoP error="use_dpop_nonce""#), "use_dpop_nonce")
        XCTAssertEqual(WwwAuthenticate.error(#"Bearer realm="x", error=invalid_token, error_description="a b""#), "invalid_token")
        XCTAssertEqual(WwwAuthenticate.error(#"Bearer error_description="error=use_dpop_nonce""#), nil)
        XCTAssertEqual(WwwAuthenticate.error(#"Bearer realm="a, error=use_dpop_nonce""#), nil)
        XCTAssertEqual(WwwAuthenticate.error(#"Basic realm="x", DPoP algs="ES256", error="use_dpop_nonce""#), "use_dpop_nonce")
        XCTAssertNil(WwwAuthenticate.error(nil))
        XCTAssertNil(WwwAuthenticate.error("Bearer"))
        for hostile in [#"="#, #"==="#, #"error"#, #"error="unterminated"#, "\"", ",,,", "a=\"\\"] {
            _ = WwwAuthenticate.error(hostile)   // terminates without crashing
        }
    }
}
