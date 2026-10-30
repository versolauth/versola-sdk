import Foundation
import XCTest
@testable import OAuthCore

/// `HTTPTokenClient` against a scripted HTTP client: the wire shape of every request, the
/// mapping of every answer, and the two fixed challenge retries (`spec/retry-policy.md`).
final class TokenClientTests: XCTestCase {
    private let configuration = CoreConfiguration(
        issuer: "https://id.example.com", clientId: "mobile", redirectUri: URL(string: "https://app.example.com/oauth")!
    )

    private func metadata(dpop: Bool = false, revocation: Bool = true) -> ProviderMetadata {
        ProviderMetadata(
            issuer: "https://id.example.com",
            authorizationEndpoint: "https://id.example.com/authorize",
            tokenEndpoint: "https://id.example.com/token",
            revocationEndpoint: revocation ? "https://id.example.com/revoke" : nil,
            dpopSigningAlgValuesSupported: dpop ? ["ES256"] : []
        )
    }

    private func client(_ http: HTTPClient, dpop: DpopProofSource? = nil, binding: TokenBinding = .bearer, metadata: ProviderMetadata? = nil, idempotency: Bool = false) throws -> HTTPTokenClient {
        let document = metadata ?? self.metadata(dpop: dpop != nil)
        return try HTTPTokenClient(configuration: configuration, metadata: { document }, httpClient: http, dpop: dpop, tokenBinding: binding, sendIdempotencyKey: idempotency)
    }

    private func grant(extensions: [String: String] = [:], resources: [String] = []) -> AuthorizationGrant {
        AuthorizationGrant(code: "the-code", codeVerifier: String(repeating: "v", count: 43), redirectUri: "https://app.example.com/oauth", resources: resources, extensions: extensions, nonce: "n")
    }

    private static let issued = #"{"access_token":"at","token_type":"Bearer","expires_in":300,"refresh_token":"rt","id_token":"idt","scope":"openid"}"#

    private func form(_ request: HTTPRequest) -> [String: [String]] {
        var fields: [String: [String]] = [:]
        for pair in String(data: request.body ?? Data(), encoding: .utf8)!.split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1).map { String($0).removingPercentEncoding ?? "" }
            fields[parts[0], default: []].append(parts.count > 1 ? parts[1] : "")
        }
        return fields
    }

    func testExchangeSendsThePublicClientFormAndNothingElse() async throws {
        let http = RecordingHTTP.json(200, Self.issued)
        let response = try await client(http).exchange(grant(resources: ["https://api.example.com", "https://files.example.com"]))

        XCTAssertEqual(response.accessToken, "at")
        XCTAssertEqual(response.expiresIn, 300)
        XCTAssertEqual(response.refreshToken, "rt")
        let request = await http.requests.first!
        XCTAssertEqual(request.method, .post)
        XCTAssertEqual(request.url.absoluteString, "https://id.example.com/token")
        XCTAssertEqual(request.headers["Content-Type"], "application/x-www-form-urlencoded")
        XCTAssertEqual(request.headers["Accept"], "application/json")
        XCTAssertNil(request.headers["Idempotency-Key"])
        XCTAssertNil(request.headers["DPoP"])
        let fields = form(request)
        XCTAssertEqual(fields["grant_type"], ["authorization_code"])
        XCTAssertEqual(fields["code"], ["the-code"])
        XCTAssertEqual(fields["redirect_uri"], ["https://app.example.com/oauth"])
        XCTAssertEqual(fields["code_verifier"], [String(repeating: "v", count: 43)])
        XCTAssertEqual(fields["client_id"], ["mobile"])
        XCTAssertEqual(fields["resource"], ["https://api.example.com", "https://files.example.com"])
        XCTAssertNil(fields["client_secret"])
    }

    func testRefreshSendsTheTokenAndCarriesTheIdempotencyKeyOnlyWhenAsked() async throws {
        let http = RecordingHTTP.json(200, Self.issued)
        _ = try await client(http).refresh(refreshToken: "rt-1", idempotencyKey: "key-1")
        _ = try await client(http, idempotency: true).refresh(refreshToken: "rt-1", idempotencyKey: "key-1")

        let requests = await http.requests
        XCTAssertEqual(form(requests[0])["grant_type"], ["refresh_token"])
        XCTAssertEqual(form(requests[0])["refresh_token"], ["rt-1"])
        XCTAssertEqual(form(requests[0])["client_id"], ["mobile"])
        XCTAssertNil(form(requests[0])["resource"])
        XCTAssertNil(requests[0].headers["Idempotency-Key"])
        XCTAssertEqual(requests[1].headers["Idempotency-Key"], "key-1")
    }

    func testTheServerDateAndAStringExpiresInAreRead() async throws {
        let http = RecordingHTTP { _ in
            HTTPResponse(statusCode: 200, headers: ["Date": "Sun, 06 Nov 1994 08:49:37 GMT"], body: Data(#"{"access_token":"at","token_type":"Bearer","expires_in":"60"}"#.utf8))
        }
        let response = try await client(http).exchange(grant())
        XCTAssertEqual(response.expiresIn, 60)
        XCTAssertEqual(response.serverDate, Date(timeIntervalSince1970: 784_111_777))
        XCTAssertNil(response.refreshToken)
    }

    func testAnUnreadableDateIsOnlyAnAbsentClockAndAMissingExpiresInIsUnknown() async throws {
        let http = RecordingHTTP { _ in
            HTTPResponse(statusCode: 200, headers: ["Date": "yesterday"], body: Data(#"{"access_token":"at","token_type":"Bearer"}"#.utf8))
        }
        let response = try await client(http).exchange(grant())
        XCTAssertNil(response.serverDate)
        XCTAssertEqual(response.expiresIn, 0)
    }

    func testAMalformedTokenResponseIsTokenResponseMalformed() async throws {
        for body in ["not json", "[]", #"{"token_type":"Bearer"}"#, #"{"access_token":"at"}"#] {
            let http = RecordingHTTP.json(200, body)
            do {
                _ = try await client(http).exchange(grant())
                XCTFail("accepted \(body)")
            } catch let error as OAuthError {
                guard case .configuration(.tokenResponseMalformed) = error else { return XCTFail("\(error) for \(body)") }
            }
        }
    }

    func testErrorMapping() async throws {
        let cases: [(Int, [String: String], String, (OAuthError) -> Bool)] = [
            (400, [:], #"{"error":"invalid_grant"}"#, { if case .reauthenticate(.grantRejected) = $0 { return true }; return false }),
            (400, [:], #"{"error":"invalid_client","error_description":"unknown"}"#, { if case .configuration(.tokenRequestRejected(code: "invalid_client", description: "unknown")) = $0 { return true }; return false }),
            (400, [:], "<html>", { if case .configuration(.tokenRequestRejected(let code, _)) = $0 { return code.contains("no OAuth error") }; return false }),
            (302, ["Location": "https://elsewhere.example.com"], "", { if case .configuration(.tokenRequestRejected(let code, _)) = $0 { return code.contains("redirects are not followed") }; return false }),
            (500, [:], "<html>", { if case .recoverable(.server(500, nil, 1, _)) = $0 { return true }; return false }),
            (429, [:], "", { if case .recoverable(.server(429, nil, 1, _)) = $0 { return true }; return false }),
            (408, [:], "", { if case .recoverable(.server(408, nil, 1, _)) = $0 { return true }; return false }),
        ]
        for (status, headers, body, matches) in cases {
            let http = RecordingHTTP { _ in HTTPResponse(statusCode: status, headers: headers, body: Data(body.utf8)) }
            do {
                _ = try await client(http).exchange(grant())
                XCTFail("accepted HTTP \(status)")
            } catch let error as OAuthError {
                XCTAssertTrue(matches(error), "HTTP \(status) \(body) -> \(error)")
            }
        }
    }

    func testATransportFailureIsRecoverableNetwork() async throws {
        let http = RecordingHTTP { _ in throw TransportFailure() }
        do {
            _ = try await client(http).exchange(grant())
            XCTFail("no error")
        } catch let error as OAuthError {
            guard case .recoverable(.network) = error else { return XCTFail("\(error)") }
        }
    }

    func testAGrantStartedThroughABackChannelIsRefusedBeforeAnyRequest() async throws {
        let http = RecordingHTTP.json(200, Self.issued)
        do {
            _ = try await client(http).exchange(grant(extensions: ["blob": "x"]))
            XCTFail("no error")
        } catch let error as OAuthError {
            guard case .configuration(.invalidConfiguration) = error else { return XCTFail("\(error)") }
        }
        let count = await http.requests.count
        XCTAssertEqual(count, 0)
    }

    // MARK: - DPoP

    /// Records the nonce each proof was minted with; the nonce store is the real contract.
    actor NonceSource: DpopProofSource {
        var nonces: [String: String] = [:]
        var minted: [String?] = []
        func thumbprint() async throws -> String { "jkt" }
        func proof(method: String, url: URL, nonce: String?, accessToken: String?) async throws -> String {
            minted.append(nonce)
            return "proof-\(minted.count)"
        }
        func observe(nonce: String, origin: String) async { nonces[origin] = nonce }
        func observe(serverDate: String?) async {}
        func nonce(for origin: String) async -> String? { nonces[origin] }
        func clearNonces() async { nonces.removeAll() }
    }

    func testDpopNeedsAProofSourceAtConstruction() {
        let document = metadata()
        XCTAssertThrowsError(try HTTPTokenClient(configuration: configuration, metadata: { document }, httpClient: RecordingHTTP.json(200, ""), dpop: nil, tokenBinding: .dpop()))
    }

    func testAProofIsSentOnlyWhenTheProviderAdvertisesDpop() async throws {
        let http = RecordingHTTP.json(200, #"{"access_token":"at","token_type":"DPoP","expires_in":300}"#)
        let source = NonceSource()
        _ = try await client(http, dpop: source, binding: .dpop(), metadata: metadata(dpop: false)).exchange(grant())
        _ = try await client(http, dpop: source, binding: .dpop(), metadata: metadata(dpop: true)).exchange(grant())
        let requests = await http.requests
        XCTAssertNil(requests[0].headers["DPoP"])
        XCTAssertEqual(requests[1].headers["DPoP"], "proof-1")
    }

    func testRequiredDpopAgainstAProviderWithoutItFailsBeforeTheCodeIsSpent() async throws {
        let http = RecordingHTTP.json(200, Self.issued)
        do {
            _ = try await client(http, dpop: NonceSource(), binding: .dpop(required: true), metadata: metadata(dpop: false)).exchange(grant())
            XCTFail("no error")
        } catch let error as OAuthError {
            guard case .configuration(.hardwareBindingUnavailable) = error else { return XCTFail("\(error)") }
        }
        let count = await http.requests.count
        XCTAssertEqual(count, 0)
    }

    func testRequiredDpopRefusesABearerTokenIssuedForABoundRequest() async throws {
        let http = RecordingHTTP.json(200, Self.issued)
        do {
            _ = try await client(http, dpop: NonceSource(), binding: .dpop(required: true), metadata: metadata(dpop: true)).exchange(grant())
            XCTFail("no error")
        } catch let error as OAuthError {
            guard case .configuration(.hardwareBindingUnavailable) = error else { return XCTFail("\(error)") }
        }
    }

    func testUseDpopNonceIsRetriedOnceWithTheNonceAndASecondDemandIsANonceLoop() async throws {
        let http = RecordingHTTP { request in
            if request.headers["DPoP"] == "proof-1" {
                return HTTPResponse(statusCode: 400, headers: ["DPoP-Nonce": "n1"], body: Data(#"{"error":"use_dpop_nonce"}"#.utf8))
            }
            return HTTPResponse(statusCode: 200, body: Data(#"{"access_token":"at","token_type":"DPoP","expires_in":300}"#.utf8))
        }
        let source = NonceSource()
        _ = try await client(http, dpop: source, binding: .dpop(), metadata: metadata(dpop: true)).exchange(grant())
        let minted = await source.minted
        XCTAssertEqual(minted, [nil, "n1"])

        let looping = RecordingHTTP { _ in HTTPResponse(statusCode: 401, headers: ["WWW-Authenticate": #"DPoP error="use_dpop_nonce""#, "DPoP-Nonce": "n2"], body: Data()) }
        do {
            _ = try await client(looping, dpop: NonceSource(), binding: .dpop(), metadata: metadata(dpop: true)).exchange(grant())
            XCTFail("no error")
        } catch let error as OAuthError {
            XCTAssertEqual(error, .recoverable(.nonceLoop(origin: "https://id.example.com")))
        }
        let attempts = await looping.requests.count
        XCTAssertEqual(attempts, 2)
    }

    func testAChallengeWithoutANonceIsANonceLoopAtOnce() async throws {
        let http = RecordingHTTP { _ in HTTPResponse(statusCode: 400, body: Data(#"{"error":"use_dpop_nonce"}"#.utf8)) }
        do {
            _ = try await client(http, dpop: NonceSource(), binding: .dpop(), metadata: metadata(dpop: true)).exchange(grant())
            XCTFail("no error")
        } catch let error as OAuthError {
            guard case .recoverable(.nonceLoop) = error else { return XCTFail("\(error)") }
        }
        let attempts = await http.requests.count
        XCTAssertEqual(attempts, 1)
    }

    func testAnInvalidProofIsRetriedOnceThenCredentialsInvalidated() async throws {
        let http = RecordingHTTP { _ in HTTPResponse(statusCode: 400, body: Data(#"{"error":"invalid_dpop_proof"}"#.utf8)) }
        do {
            _ = try await client(http, dpop: NonceSource(), binding: .dpop(), metadata: metadata(dpop: true)).exchange(grant())
            XCTFail("no error")
        } catch let error as OAuthError {
            XCTAssertEqual(error, .reauthenticate(.credentialsInvalidated))
        }
        let attempts = await http.requests.count
        XCTAssertEqual(attempts, 2)
    }

    /// A server that verifies `iat` within `leeway` of its own clock and says what time it is.
    private func skewCheckingServer(serverTime: Date, leeway: TimeInterval = 60) -> RecordingHTTP {
        RecordingHTTP { request in
            let dateHeader = ["Date": HTTPDate.format(serverTime)]
            guard let proof = request.headers["DPoP"], let iat = JoseTestTokens.decode(proof).claims["iat"] as? Int,
                  abs(TimeInterval(iat) - serverTime.timeIntervalSince1970) <= leeway
            else {
                return HTTPResponse(statusCode: 400, headers: dateHeader, body: Data(#"{"error":"invalid_dpop_proof"}"#.utf8))
            }
            return HTTPResponse(statusCode: 200, headers: dateHeader, body: Data(#"{"access_token":"at","token_type":"DPoP","expires_in":300,"refresh_token":"rt"}"#.utf8))
        }
    }

    func testAnInvalidProofFromAFastDeviceClockIsRetriedOnceWithTheServersTimeAndSucceeds() async throws {
        let server = Date(timeIntervalSince1970: 1_700_000_000)
        let device = server.addingTimeInterval(600)
        let http = skewCheckingServer(serverTime: server)
        let factory = DpopProofFactory(key: SoftwareDpopKey(), clock: Clock(now: { device }))

        let response = try await client(http, dpop: factory, binding: .dpop(), metadata: metadata(dpop: true)).exchange(grant())

        XCTAssertEqual(response.accessToken, "at")
        let requests = await http.requests
        XCTAssertEqual(requests.count, 2, "one refusal, one corrected retry")
        let iats = requests.map { JoseTestTokens.decode($0.headers["DPoP"]!).claims["iat"] as? Int }
        XCTAssertEqual(iats, [1_700_000_600, 1_700_000_000])
    }

    func testAnInvalidProofFromASlowDeviceClockIsCorrectedForwards() async throws {
        let server = Date(timeIntervalSince1970: 1_700_000_000)
        let device = server.addingTimeInterval(-600)
        let http = skewCheckingServer(serverTime: server)
        let factory = DpopProofFactory(key: SoftwareDpopKey(), clock: Clock(now: { device }))

        _ = try await client(http, dpop: factory, binding: .dpop(), metadata: metadata(dpop: true)).refresh(refreshToken: "rt-1", idempotencyKey: "k")

        let attempts = await http.requests.count
        XCTAssertEqual(attempts, 2)
    }

    func testAnInvalidProofThatTheCorrectedClockDoesNotFixIsStillOneRetryThenCredentialsInvalidated() async throws {
        // A key that does not match the grant: the server refuses at the right time as well. The
        // corrected retry is the only one, and the outcome is the one the spec gives.
        let server = Date(timeIntervalSince1970: 1_700_000_000)
        let http = RecordingHTTP { _ in
            HTTPResponse(statusCode: 400, headers: ["Date": HTTPDate.format(server)], body: Data(#"{"error":"invalid_dpop_proof"}"#.utf8))
        }
        let factory = DpopProofFactory(key: SoftwareDpopKey(), clock: Clock(now: { server.addingTimeInterval(600) }))
        do {
            _ = try await client(http, dpop: factory, binding: .dpop(), metadata: metadata(dpop: true)).exchange(grant())
            XCTFail("no error")
        } catch let error as OAuthError {
            XCTAssertEqual(error, .reauthenticate(.credentialsInvalidated))
        }
        let attempts = await http.requests.count
        XCTAssertEqual(attempts, 2)
    }

    // MARK: - Revocation

    func testRevokeSendsTokenHintAndClientIdAndNoProof() async throws {
        let http = RecordingHTTP.json(200, "")
        try await client(http, dpop: NonceSource(), binding: .dpop(), metadata: metadata(dpop: true)).revoke(refreshToken: "rt-1")
        let request = await http.requests.first!
        XCTAssertEqual(request.url.absoluteString, "https://id.example.com/revoke")
        XCTAssertNil(request.headers["DPoP"])
        let fields = form(request)
        XCTAssertEqual(fields["token"], ["rt-1"])
        XCTAssertEqual(fields["token_type_hint"], ["refresh_token"])
        XCTAssertEqual(fields["client_id"], ["mobile"])
        XCTAssertNil(fields["client_secret"])
    }

    func testRevokeWithoutAnAdvertisedEndpointMakesNoRequest() async throws {
        let http = RecordingHTTP.json(200, "")
        try await client(http, metadata: metadata(revocation: false)).revoke(refreshToken: "rt-1")
        let count = await http.requests.count
        XCTAssertEqual(count, 0)
    }

    func testRevokeMapsATransientAndARefusal() async throws {
        do {
            try await client(RecordingHTTP.json(503, "")).revoke(refreshToken: "rt")
            XCTFail("no error")
        } catch let error as OAuthError {
            guard case .recoverable(.server(503, nil, _, _)) = error else { return XCTFail("\(error)") }
        }
        do {
            try await client(RecordingHTTP.json(401, #"{"error":"invalid_client"}"#)).revoke(refreshToken: "rt")
            XCTFail("no error")
        } catch let error as OAuthError {
            XCTAssertEqual(error, .configuration(.tokenRequestRejected(code: "invalid_client", description: nil)))
        }
    }

    func testWwwAuthenticateErrorReadsQuotedAndBareValues() {
        XCTAssertEqual(wwwAuthenticateError(#"DPoP error="use_dpop_nonce", error_description="x""#), "use_dpop_nonce")
        XCTAssertEqual(wwwAuthenticateError("Bearer realm=x, error=invalid_token"), "invalid_token")
        XCTAssertNil(wwwAuthenticateError("Bearer realm=\"api\""))
    }
}
