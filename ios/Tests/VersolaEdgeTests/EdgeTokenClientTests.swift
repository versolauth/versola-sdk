import Foundation
import XCTest
@testable import OAuthCore
@testable import VersolaEdge

/// The token endpoint through edge (`spec/versola-sdk-api.md` sections 7, 8 and 11): what `/native/complete`,
/// `/native/token` and `/native/revoke` are sent, what each proof is signed for, whose nonce is cached
/// where, and that nothing is inferred when the remembered endpoints are gone. The Android
/// `EdgeNativeTokenClientTest`'s twin.
final class EdgeTokenClientTests: XCTestCase {
    private typealias F = EdgeFixture

    private let cell1Blob = "v1.kz-1.aB-c_D.e~f"
    private let cell2Code = "v1.kz-2.Zz+/="
    private let refreshToken = "v1.kz-2.Zz+/="

    private func client(
        _ http: ScriptedHTTP, endpoints: EdgeNativeEndpoints? = EdgeNativeEndpoints(tokenEndpoint: F.tokenEndpoint, revocationEndpoint: F.revocationEndpoint),
        dpop: DpopProofFactory = F.proofSource(), store: InMemoryEdgeEndpointsStore? = nil
    ) throws -> (EdgeNativeTokenClient, InMemoryEdgeEndpointsStore) {
        let store = store ?? InMemoryEdgeEndpointsStore(endpoints)
        return (try EdgeNativeTokenClient(clientId: F.clientId, issuer: F.issuer, edgeUrl: F.edgeUrl, httpClient: http, dpop: dpop, endpoints: store, clock: Clock(now: { F.now })), store)
    }

    private func grant(
        code: String = "v1.kz-2.Zz+/=", state: String = "edge-state-1", iss: String? = F.issuer,
        extensions: [String: String]? = nil
    ) -> AuthorizationGrant {
        AuthorizationGrant(
            code: code, codeVerifier: "", redirectUri: F.redirect,
            extensions: extensions ?? [
                EdgeExtension.blob: "v1.kz-1.aB-c_D.e~f", EdgeExtension.tokenEndpoint: F.tokenEndpoint, EdgeExtension.revocationEndpoint: F.revocationEndpoint,
            ],
            nonce: "n", scopes: ["openid"], state: state, iss: iss
        )
    }

    private func nonceChallenge400(_ nonce: String = "auth-nonce-1") -> HTTPResponse {
        F.answer(400, ["DPoP-Nonce": nonce], #"{"error":"use_dpop_nonce","error_description":"Authorization server requires nonce in DPoP proof"}"#)
    }

    // MARK: exchange (/native/complete)

    func testExchangePostsExactlyTheCodeTheStateTheIssAndTheBlobToComplete() async throws {
        let http = ScriptedHTTP([F.answer(200, [:], F.tokenAnswer())])
        let (client, _) = try client(http)

        let issued = try await client.exchange(grant())

        XCTAssertEqual(issued.accessToken, "at-1")
        let request = try await http.firstRequest()
        XCTAssertEqual(request.method, .post)
        XCTAssertEqual(request.url.absoluteString, F.completeUrl)
        let form = F.decodeForm(request)
        XCTAssertEqual(form.map(\.0), ["code", "state", "iss", "blob"], "no client_id, no verifier, no redirect_uri, no resource")
        XCTAssertEqual(form.map(\.1), [cell2Code, "edge-state-1", F.issuer, cell1Blob])
        XCTAssertNil(request.headers["Idempotency-Key"])
    }

    func testOpaqueValuesAreSentByteForByteAndFormEncodedOnce() async throws {
        let http = ScriptedHTTP([F.answer(200, [:], F.tokenAnswer())])
        let (client, _) = try client(http)
        let blob = "v1.kz-1.aB-c_D.e~f"

        _ = try await client.exchange(grant(code: cell2Code, extensions: [
            EdgeExtension.blob: blob, EdgeExtension.tokenEndpoint: F.tokenEndpoint, EdgeExtension.revocationEndpoint: F.revocationEndpoint,
        ]))

        let request = try await http.firstRequest()
        let body = String(decoding: request.body ?? Data(), as: UTF8.self)
        // `+`, `/` and `=` are escaped once: a second encoding would show `%252B`, and a `+` left bare would read as a space.
        XCTAssertTrue(body.hasPrefix("code=v1.kz-2.Zz%2B%2F%3D&"), body)
        XCTAssertFalse(body.contains("%25"))
        XCTAssertTrue(body.hasSuffix("blob=v1.kz-1.aB-c_D.e~f"), body)
        let decoded = F.decodeForm(request)
        XCTAssertEqual(decoded.first { $0.0 == "code" }?.1, cell2Code)
        XCTAssertEqual(decoded.first { $0.0 == "blob" }?.1, blob)
    }

    func testProofHtuIsTheStoredTokenEndpointAndNotEdgesUrl() async throws {
        let http = ScriptedHTTP([F.answer(200, [:], F.tokenAnswer())])
        let (client, _) = try client(http)

        _ = try await client.exchange(grant())

        let claims = F.proofClaims(try await http.firstRequest())
        XCTAssertEqual(claims["htu"] as? String, F.tokenEndpoint)
        XCTAssertEqual(claims["htm"] as? String, "POST")
        XCTAssertNil(claims["ath"])
    }

    func testExchangeIsOneAttemptOnEveryTransientStatus() async throws {
        for status in [408, 429, 500, 502, 503, 504] {
            let http = ScriptedHTTP([F.answer(status, ["Retry-After": "7"])])
            let (client, store) = try client(http, endpoints: nil)
            let world = RetryWorld()
            let error = await thrown { try await world.within(world.budget()) { try await client.exchange(self.grant()) } }
            let count = await http.requests.count
            XCTAssertEqual(count, 1, "HTTP \(status): a spent code is not replayed")
            guard case .recoverable(.server(status, _, 1, _))? = error else { XCTFail("HTTP \(status): \(String(describing: error))"); continue }
            let saved = try await store.load()
            XCTAssertNil(saved, "nothing is remembered from an exchange that failed")
            XCTAssertEqual(world.delays, [], "and it did not wait")
        }
    }

    func testInvalidGrantWithoutADescriptionIsGrantRejected() async throws {
        let http = ScriptedHTTP([F.answer(400, [:], #"{"error":"invalid_grant"}"#)])
        let (client, _) = try client(http)
        let error = await thrown { try await client.exchange(self.grant()) }
        XCTAssertEqual(error, .reauthenticate(.grantRejected))
    }

    func testOtherTokenErrorsKeepTheirCodeAndDescription() async throws {
        let http = ScriptedHTTP([F.answer(400, [:], #"{"error":"invalid_request","error_description":"iss does not match"}"#)])
        let (client, _) = try client(http)
        let error = await thrown { try await client.exchange(self.grant()) }
        XCTAssertEqual(error, .configuration(.tokenRequestRejected(code: "invalid_request", description: "iss does not match")))
    }

    func testA404IsTheClientEdgeDoesNotFront() async throws {
        let http = ScriptedHTTP([F.answer(404)])
        let (client, _) = try client(http)
        let error = await thrown { try await client.exchange(self.grant()) }
        XCTAssertEqual(error, .configuration(.facade(name: "edge_client_unknown", detail: F.clientId)))
    }

    func testExchangeSavesTheTwoEndpointsBeforeItReturnsTheTokens() async throws {
        let http = ScriptedHTTP([F.answer(200, [:], F.tokenAnswer())])
        let (client, store) = try client(http, endpoints: nil)

        _ = try await client.exchange(grant())

        let saved = try await store.load()
        XCTAssertEqual(saved, EdgeNativeEndpoints(tokenEndpoint: F.tokenEndpoint, revocationEndpoint: F.revocationEndpoint))
    }

    func testEachSignInReplacesTheEndpointsWithThoseItsOwnStartAnswered() async throws {
        let http = ScriptedHTTP([F.answer(200, [:], F.tokenAnswer())])
        let old = EdgeNativeEndpoints(tokenEndpoint: "https://old.example.com/token", revocationEndpoint: "https://old.example.com/revoke")
        let (client, store) = try client(http, endpoints: old)

        _ = try await client.exchange(grant())

        let saved = try await store.load()
        XCTAssertEqual(saved?.tokenEndpoint, F.tokenEndpoint)
    }

    func testABearerTokenForAKeyBoundRequestIsRefusedAndNothingIsRemembered() async throws {
        let http = ScriptedHTTP([F.answer(200, [:], F.tokenAnswer(tokenType: "Bearer"))])
        let (client, store) = try client(http, endpoints: nil)

        let error = await thrown { try await client.exchange(self.grant()) }

        guard case .configuration(.hardwareBindingUnavailable)? = error else { return XCTFail("\(String(describing: error))") }
        let saved = try await store.load()
        XCTAssertNil(saved)
    }

    func testGrantWithoutTheBlobOrEitherEndpointIsRefusedBeforeTheCodeIsSpent() async throws {
        let complete: [String: String] = [
            EdgeExtension.blob: "b", EdgeExtension.tokenEndpoint: F.tokenEndpoint, EdgeExtension.revocationEndpoint: F.revocationEndpoint,
        ]
        for missing in [EdgeExtension.blob, EdgeExtension.tokenEndpoint, EdgeExtension.revocationEndpoint] {
            var extensions = complete
            extensions[missing] = nil
            let http = ScriptedHTTP([F.answer(200, [:], F.tokenAnswer())])
            let (client, store) = try client(http, endpoints: nil)
            let error = await thrown { try await client.exchange(self.grant(extensions: extensions)) }
            guard case .configuration(.invalidConfiguration)? = error else { XCTFail("without \(missing): \(String(describing: error))"); continue }
            let count = await http.requests.count
            let saved = try await store.load()
            XCTAssertEqual(count, 0, "without \(missing)")
            XCTAssertNil(saved)
        }
        // A grant a direct back channel made carries no extension at all.
        let http = ScriptedHTTP([F.answer(200, [:], F.tokenAnswer())])
        let (client, _) = try client(http)
        let direct = await thrown { try await client.exchange(self.grant(extensions: [:])) }
        guard case .configuration(.invalidConfiguration)? = direct else { return XCTFail("\(String(describing: direct))") }
        let count = await http.requests.count
        XCTAssertEqual(count, 0)
    }

    func testGrantWhoseEndpointsAreNotHttpsIsRefusedBeforeTheCodeIsSpentAndNothingIsInferred() async throws {
        for (token, revocation) in [
            ("http://auth.example.com/token", F.revocationEndpoint), (F.tokenEndpoint, "http://auth.example.com/revoke"),
            ("http://10.0.2.2/token", "http://10.0.2.2/revoke"), ("not a url", F.revocationEndpoint),
        ] {
            let http = ScriptedHTTP([F.answer(200, [:], F.tokenAnswer())])
            let (client, _) = try client(http, endpoints: nil)
            let error = await thrown {
                try await client.exchange(self.grant(extensions: [
                    EdgeExtension.blob: "b", EdgeExtension.tokenEndpoint: token, EdgeExtension.revocationEndpoint: revocation,
                ]))
            }
            guard case .configuration(.invalidConfiguration(let detail))? = error else { XCTFail("\(token) \(revocation): \(String(describing: error))"); continue }
            XCTAssertFalse(detail.contains("auth.example.com"), "the address is not in the message")
            let count = await http.requests.count
            XCTAssertEqual(count, 0)
        }
    }

    func testGrantWithoutIssIsRefusedBeforeTheCodeIsSpent() async throws {
        let http = ScriptedHTTP([F.answer(200, [:], F.tokenAnswer())])
        let (client, _) = try client(http)
        let error = await thrown { try await client.exchange(self.grant(iss: nil)) }
        XCTAssertEqual(error, .configuration(.issuerMismatch(expected: F.issuer, received: nil)))
        let count = await http.requests.count
        XCTAssertEqual(count, 0)
    }

    func testNonceOfTheRelayedChallengeIsCachedUnderTheEndpointsOriginAndNotEdges() async throws {
        let dpop = F.proofSource()
        let http = ScriptedHTTP([nonceChallenge400(), F.answer(200, [:], F.tokenAnswer())])
        let (client, _) = try client(http, dpop: dpop)

        _ = try await client.exchange(grant())

        let requests = await http.requests
        XCTAssertEqual(requests.count, 2, "the challenge is answered once")
        XCTAssertNil(F.proofClaims(requests[0])["nonce"])
        XCTAssertEqual(F.proofClaims(requests[1])["nonce"] as? String, "auth-nonce-1")
        XCTAssertEqual(requests[1].url.absoluteString, F.completeUrl)
        XCTAssertNotEqual(F.proofClaims(requests[0])["jti"] as? String, F.proofClaims(requests[1])["jti"] as? String)
        let underAuth = await dpop.nonce(for: F.authOrigin)
        let underEdge = await dpop.nonce(for: F.edgeOrigin)
        XCTAssertEqual(underAuth, "auth-nonce-1")
        XCTAssertNil(underEdge, "edge's own nonce is a different cache entry")
    }

    func testEdgesOwn401ChallengeShapeIsReadToo() async throws {
        let http = ScriptedHTTP([F.answer(401, ["WWW-Authenticate": #"DPoP error="use_dpop_nonce""#, "DPoP-Nonce": "n-2"]), F.answer(200, [:], F.tokenAnswer())])
        let (client, _) = try client(http)
        _ = try await client.exchange(grant())
        let requests = await http.requests
        XCTAssertEqual(F.proofClaims(requests[1])["nonce"] as? String, "n-2")
    }

    func testASecondNonceChallengeIsANonceLoopNamingTheEndpointsOrigin() async throws {
        let http = ScriptedHTTP([nonceChallenge400()])
        let (client, _) = try client(http)
        let error = await thrown { try await client.exchange(self.grant()) }
        XCTAssertEqual(error, .recoverable(.nonceLoop(origin: F.authOrigin)))
        let count = await http.requests.count
        XCTAssertEqual(count, 2)
    }

    // MARK: refresh (/native/token)

    func testRefreshPostsTheGrantTypeAndTheRefreshTokenWithTheIdempotencyKeyAndSignsForTheTokenEndpoint() async throws {
        let http = ScriptedHTTP([F.answer(200, [:], F.tokenAnswer())])
        let (client, _) = try client(http)

        _ = try await client.refresh(refreshToken: refreshToken, idempotencyKey: "idem-1")

        let request = try await http.firstRequest()
        XCTAssertEqual(request.url.absoluteString, F.tokenUrl)
        XCTAssertEqual(request.headers["Idempotency-Key"], "idem-1")
        let form = F.decodeForm(request)
        XCTAssertEqual(form.map(\.0), ["grant_type", "refresh_token"])
        XCTAssertEqual(form.map(\.1), ["refresh_token", refreshToken], "byte for byte")
        XCTAssertTrue(String(decoding: request.body ?? Data(), as: UTF8.self).contains("refresh_token=v1.kz-2.Zz%2B%2F%3D"))
        let claims = F.proofClaims(request)
        XCTAssertEqual(claims["htu"] as? String, F.tokenEndpoint)
        XCTAssertNil(claims["ath"])
    }

    func testRefreshWithNoStoredEndpointsIsCredentialsInvalidatedAndSendsNothing() async throws {
        let http = ScriptedHTTP([F.answer(200, [:], F.tokenAnswer())])
        let (client, _) = try client(http, endpoints: nil)

        let error = await thrown { try await client.refresh(refreshToken: self.refreshToken, idempotencyKey: "k") }

        XCTAssertEqual(error, .reauthenticate(.credentialsInvalidated))
        let count = await http.requests.count
        XCTAssertEqual(count, 0, "no discovery fallback, and nothing inferred from anything else")
    }

    func testRefreshWithStoredEndpointsThatAreNotHttpsIsCredentialsInvalidatedAndSendsNothing() async throws {
        for stored in [
            EdgeNativeEndpoints(tokenEndpoint: "http://auth.example.com/token", revocationEndpoint: F.revocationEndpoint),
            EdgeNativeEndpoints(tokenEndpoint: F.tokenEndpoint, revocationEndpoint: "http://auth.example.com/revoke"),
            EdgeNativeEndpoints(tokenEndpoint: "", revocationEndpoint: ""),
        ] {
            let http = ScriptedHTTP([F.answer(200, [:], F.tokenAnswer())])
            let (client, _) = try client(http, endpoints: stored)
            let error = await thrown { try await client.refresh(refreshToken: self.refreshToken, idempotencyKey: "k") }
            XCTAssertEqual(error, .reauthenticate(.credentialsInvalidated), "\(stored)")
            let count = await http.requests.count
            XCTAssertEqual(count, 0)
        }
    }

    func testRefreshNonceFromTheRelayedChallengeIsCachedUnderTheEndpointsOrigin() async throws {
        let dpop = F.proofSource()
        let http = ScriptedHTTP([nonceChallenge400("auth-nonce-9"), F.answer(200, [:], F.tokenAnswer())])
        let (client, _) = try client(http, dpop: dpop)

        _ = try await client.refresh(refreshToken: refreshToken, idempotencyKey: "k")

        let requests = await http.requests
        XCTAssertEqual(F.proofClaims(requests[1])["nonce"] as? String, "auth-nonce-9")
        let underAuth = await dpop.nonce(for: F.authOrigin)
        let underEdge = await dpop.nonce(for: F.edgeOrigin)
        XCTAssertEqual(underAuth, "auth-nonce-9")
        XCTAssertNil(underEdge)
    }

    func testRefreshInvalidGrantIsGrantRejected() async throws {
        let http = ScriptedHTTP([F.answer(400, [:], #"{"error":"invalid_grant"}"#)])
        let (client, _) = try client(http)
        let error = await thrown { try await client.refresh(refreshToken: self.refreshToken, idempotencyKey: "k") }
        XCTAssertEqual(error, .reauthenticate(.grantRejected))
    }

    func testRefreshIsRepeatedUnderTheOperationsBudgetWithAFreshProofEachTime() async throws {
        let world = RetryWorld()
        let http = ScriptedHTTP([F.answer(503), F.answer(200, [:], F.tokenAnswer())])
        let (client, _) = try client(http)

        let token = refreshToken
        _ = try await world.within(world.budget()) {
            try await OperationBudget.run(origin: F.edgeOrigin) { try await client.refresh(refreshToken: token, idempotencyKey: "k") }
        }

        let requests = await http.requests
        XCTAssertEqual(requests.count, 2)
        XCTAssertNotEqual(F.proofClaims(requests[0])["jti"] as? String, F.proofClaims(requests[1])["jti"] as? String)
    }

    // MARK: revoke (/native/revoke)

    func testRevokePostsTheTokenAndTheHintAndSignsForTheRevocationEndpoint() async throws {
        let http = ScriptedHTTP([F.answer(200)])
        let (client, _) = try client(http)

        try await client.revoke(refreshToken: refreshToken)

        let request = try await http.firstRequest()
        XCTAssertEqual(request.url.absoluteString, F.revokeUrl)
        let form = F.decodeForm(request)
        XCTAssertEqual(form.map(\.0), ["token_type_hint", "token"])
        XCTAssertEqual(form.map(\.1), ["refresh_token", refreshToken])
        XCTAssertEqual(F.proofClaims(request)["htu"] as? String, F.revocationEndpoint)
    }

    func testRevokeWithNoStoredEndpointsIsCredentialsInvalidatedAndSendsNothing() async throws {
        let http = ScriptedHTTP([F.answer(200)])
        let (client, _) = try client(http, endpoints: nil)
        let error = await thrown { try await client.revoke(refreshToken: self.refreshToken) }
        XCTAssertEqual(error, .reauthenticate(.credentialsInvalidated))
        let count = await http.requests.count
        XCTAssertEqual(count, 0)
    }

    func testRevokeWithStoredEndpointsThatAreNotHttpsSendsNothing() async throws {
        let http = ScriptedHTTP([F.answer(200)])
        let (client, _) = try client(http, endpoints: EdgeNativeEndpoints(tokenEndpoint: F.tokenEndpoint, revocationEndpoint: "http://auth.example.com/revoke"))
        let error = await thrown { try await client.revoke(refreshToken: self.refreshToken) }
        XCTAssertEqual(error, .reauthenticate(.credentialsInvalidated))
        let count = await http.requests.count
        XCTAssertEqual(count, 0)
    }

    func testRevokeAnswersARelayedNonceChallengeOnceAndCachesTheNonceUnderTheEndpointsOrigin() async throws {
        let dpop = F.proofSource()
        let http = ScriptedHTTP([nonceChallenge400("auth-nonce-r"), F.answer(200)])
        let (client, _) = try client(http, dpop: dpop)

        try await client.revoke(refreshToken: refreshToken)

        let requests = await http.requests
        XCTAssertEqual(requests.count, 2)
        XCTAssertEqual(F.proofClaims(requests[1])["nonce"] as? String, "auth-nonce-r")
        XCTAssertEqual(F.proofClaims(requests[1])["htu"] as? String, F.revocationEndpoint)
        let underAuth = await dpop.nonce(for: F.authOrigin)
        XCTAssertEqual(underAuth, "auth-nonce-r")
    }

    func testRevokeNonceLoopIsReportedForTheEndpointsOrigin() async throws {
        let http = ScriptedHTTP([nonceChallenge400()])
        let (client, _) = try client(http)
        let error = await thrown { try await client.revoke(refreshToken: self.refreshToken) }
        XCTAssertEqual(error, .recoverable(.nonceLoop(origin: F.authOrigin)))
    }

    func testRevokeOf404IsTheClientEdgeDoesNotFront() async throws {
        let http = ScriptedHTTP([F.answer(404)])
        let (client, _) = try client(http)
        let error = await thrown { try await client.revoke(refreshToken: self.refreshToken) }
        XCTAssertEqual(error, .configuration(.facade(name: "edge_client_unknown", detail: F.clientId)))
    }

    func testRevokeIsRepeatedOnATransientStatusUnderTheBudget() async throws {
        let world = RetryWorld()
        let http = ScriptedHTTP([F.answer(503, ["Retry-After": "1"]), F.answer(200)])
        let (client, _) = try client(http)

        try await world.within(world.budget()) { try await client.revoke(refreshToken: self.refreshToken) }

        let requests = await http.requests
        XCTAssertEqual(requests.count, 2)
        XCTAssertNotEqual(F.proofClaims(requests[0])["jti"] as? String, F.proofClaims(requests[1])["jti"] as? String)
    }

    // MARK: no value is parsed, and the only requests are edge's

    func testNoRequestOfAnyCallGoesToTheAddressesTheProofsAreSignedFor() async throws {
        let http = ScriptedHTTP([F.answer(200, [:], F.tokenAnswer())])
        let (client, _) = try client(http)
        _ = try await client.exchange(grant())
        _ = try await client.refresh(refreshToken: refreshToken, idempotencyKey: "k")
        try await client.revoke(refreshToken: refreshToken)

        let urls = await http.requests.map(\.url.absoluteString)
        XCTAssertEqual(urls, [F.completeUrl, F.tokenUrl, F.revokeUrl])
    }

    // MARK: the endpoint store

    func testFileStoreRoundTripsAndAnUnreadableFileIsDeletedAndReadAsAbsent() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("versola-edge-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let file = directory.appendingPathComponent("native-endpoints.json")
        let store = FileEdgeEndpointsStore(file: file)
        let none = try await store.load()
        XCTAssertNil(none)

        let endpoints = EdgeNativeEndpoints(tokenEndpoint: F.tokenEndpoint, revocationEndpoint: F.revocationEndpoint)
        try await store.save(endpoints)
        let loaded = try await store.load()
        XCTAssertEqual(loaded, endpoints)

        try Data("not json".utf8).write(to: file)
        let damaged = try await store.load()
        XCTAssertNil(damaged)
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path), "a damaged file costs a sign-in, never a guessed address")
    }

    func testStoredEndpointsAreNotCredentialsAndCarryNoTokens() throws {
        let data = try JSONEncoder().encode(EdgeNativeEndpoints(tokenEndpoint: F.tokenEndpoint, revocationEndpoint: F.revocationEndpoint))
        let text = String(decoding: data, as: UTF8.self)
        XCTAssertTrue(text.contains("token_endpoint") && text.contains("revocation_endpoint"))
        XCTAssertFalse(text.contains("rt-1"))
    }
}
