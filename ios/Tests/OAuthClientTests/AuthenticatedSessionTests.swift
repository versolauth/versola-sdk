import Network
import os
import XCTest
@testable import OAuthClient

private actor FakeTokens: AccessTokenSource {
    private var current: AccessToken
    private let renewed: [AccessToken]
    private(set) var renewCount = 0
    private(set) var accessCount = 0

    init(current: AccessToken, renewed: [AccessToken] = []) {
        self.current = current
        self.renewed = renewed
    }

    func accessToken() async throws -> AccessToken {
        accessCount += 1
        return current
    }

    func renewAccessToken() async throws -> AccessToken {
        renewCount += 1
        let next = renewed.isEmpty ? current : renewed[min(renewCount - 1, renewed.count - 1)]
        current = next
        return next
    }
}

private actor FakeDpop: DpopProofSource {
    struct Proof: Sendable, Equatable {
        var method: String
        var url: URL
        var nonce: String?
        var accessToken: String?
    }

    private(set) var proofs: [Proof] = []
    private(set) var observed: [(nonce: String, origin: String)] = []
    private(set) var observedDates: [String?] = []
    private var nonces: [String: String] = [:]

    func thumbprint() async throws -> String { "jkt" }

    func proof(method: String, url: URL, nonce: String?, accessToken: String?) async throws -> String {
        proofs.append(Proof(method: method, url: url, nonce: nonce, accessToken: accessToken))
        return "proof-\(proofs.count)"
    }

    func observe(nonce: String, origin: String) async {
        observed.append((nonce, origin))
        nonces[origin] = nonce
    }

    func observe(serverDate: String?, age: String?) async { observedDates.append(serverDate) }

    func nonce(for origin: String) async -> String? { nonces[origin] }
    func clearNonces() async { nonces = [:] }
}

private func authHeader(_ request: URLRequest) -> String? { request.value(forHTTPHeaderField: "Authorization") }

final class AuthenticatedSessionTests: XCTestCase {
    private let api = URL(string: "https://api.example.com/v1/items?page=2#top")!
    private let bearer = AccessToken(value: "tok-1", tokenType: "Bearer")
    private let dpopToken = AccessToken(value: "tok-1", tokenType: "DPoP")

    override func tearDown() {
        StubURLProtocol.reset()
        super.tearDown()
    }

    private func scope(_ origins: Set<String> = ["https://api.example.com"]) throws -> RequestScope {
        try RequestScope(origins: origins)
    }

    private func session(tokens: any AccessTokenSource, origins: Set<String> = ["https://api.example.com"], dpop: (any DpopProofSource)? = nil) throws -> AuthenticatedSession {
        AuthenticatedSession(tokens: tokens, scope: try scope(origins), dpop: dpop, session: StubURLProtocol.session())
    }


    // MARK: scope

    func testScopeMatchesTheOriginWhateverThePathQueryOrDefaultPort() throws {
        let scope = try scope(["https://api.example.com", "http://localhost:9000"])
        XCTAssertTrue(scope.includes(URL(string: "https://api.example.com")!))
        XCTAssertTrue(scope.includes(URL(string: "https://api.example.com/a/b?c=d#e")!))
        XCTAssertTrue(scope.includes(URL(string: "https://api.example.com/x")!), "the default port is applied")
        XCTAssertTrue(scope.includes(URL(string: "https://API.example.com/x")!), "hosts compare case-insensitively")
        XCTAssertTrue(scope.includes(URL(string: "http://localhost:9000/x")!))
    }

    func testScopeExcludesAnotherHostPortSchemeAndLookalike() throws {
        let scope = try scope(["https://api.example.com", "http://localhost:9000"])
        XCTAssertFalse(scope.includes(URL(string: "https://api.example.com:8443/x")!))
        XCTAssertFalse(scope.includes(URL(string: "https://other.example.com/x")!))
        XCTAssertFalse(scope.includes(URL(string: "http://api.example.com/x")!))
        XCTAssertFalse(scope.includes(URL(string: "https://api.example.com.evil.example.org/x")!))
        XCTAssertFalse(scope.includes(URL(string: "https://sub.api.example.com/x")!))
        XCTAssertFalse(scope.includes(URL(string: "https://evil.example.org/?u=https://api.example.com")!))
        XCTAssertFalse(scope.includes(URL(string: "http://localhost:9001/x")!))
        XCTAssertFalse(scope.includes(URL(string: "file:///etc/hosts")!))
    }

    func testScopeConstructionRefusals() {
        XCTAssertNoThrow(try RequestScope(origins: ["https://api.example.com"]))
        XCTAssertNoThrow(try RequestScope(origins: ["http://127.0.0.1:3000"]))
        for bad: Set<String> in [
            [], ["http://api.example.com"], ["https://api.example.com/v1"], ["https://api.example.com?x=1"], ["api.example.com"],
            ["https://api.example.com", "http://api.example.com"],
        ] {
            XCTAssertThrowsError(try RequestScope(origins: bad)) {
                guard case OAuthError.configuration(.invalidConfiguration) = $0 else { return XCTFail("\($0)") }
            }
        }
    }

    // MARK: attaching the token

    func testTokenIsAttachedInsideTheScopeAndTheQueryIsKept() async throws {
        StubURLProtocol.install { _ in .response(status: 200, body: Data("ok".utf8)) }
        let tokens = FakeTokens(current: bearer)
        let (data, response) = try await session(tokens: tokens).data(for: URLRequest(url: api))
        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(data, Data("ok".utf8))
        let sent = try XCTUnwrap(StubURLProtocol.requests.first)
        XCTAssertEqual(authHeader(sent), "Bearer tok-1")
        XCTAssertEqual(sent.url?.query, "page=2")
        XCTAssertNil(sent.value(forHTTPHeaderField: "DPoP"))
    }

    func testCallerSuppliedAuthorizationIsReplacedNotAppended() async throws {
        StubURLProtocol.install { _ in .response(status: 200) }
        var request = URLRequest(url: api)
        request.setValue("Bearer attacker", forHTTPHeaderField: "authorization")
        request.setValue("forged", forHTTPHeaderField: "DPoP")
        _ = try await session(tokens: FakeTokens(current: bearer)).data(for: request)
        let sent = try XCTUnwrap(StubURLProtocol.requests.first)
        XCTAssertEqual(authHeader(sent), "Bearer tok-1")
        XCTAssertNil(sent.value(forHTTPHeaderField: "DPoP"))
    }

    func testOtherPortAndHostGetNoTokenAndTheirUnauthorizedIsReturnedUntouched() async throws {
        StubURLProtocol.install { _ in .response(status: 401, headers: ["WWW-Authenticate": "Bearer"]) }
        let tokens = FakeTokens(current: bearer, renewed: [AccessToken(value: "tok-2", tokenType: "Bearer")])
        let session = try session(tokens: tokens)
        for other in ["https://api.example.com:8443/x", "https://other.example.com/x", "http://api.example.com/x"] {
            let (_, response) = try await session.data(for: URLRequest(url: URL(string: other)!))
            XCTAssertEqual(response.statusCode, 401)
        }
        XCTAssertEqual(StubURLProtocol.requests.count, 3, "no replay for a request outside the scope")
        for sent in StubURLProtocol.requests { XCTAssertNil(authHeader(sent)) }
        let renewals = await tokens.renewCount
        let accesses = await tokens.accessCount
        XCTAssertEqual(renewals, 0)
        XCTAssertEqual(accesses, 0, "no token is even fetched for an out-of-scope request")
    }

    func testRedirectIsReturnedNotFollowedAndTheTokenNeverReachesTheTarget() async throws {
        StubURLProtocol.install { _ in .redirect(location: "https://evil.example.org/collect") }
        let (_, response) = try await session(tokens: FakeTokens(current: bearer)).data(for: URLRequest(url: api))
        XCTAssertEqual(response.statusCode, 302)
        XCTAssertEqual(response.value(forHTTPHeaderField: "Location"), "https://evil.example.org/collect")
        XCTAssertEqual(StubURLProtocol.requests.count, 1)
        XCTAssertEqual(StubURLProtocol.requests.first?.url?.host, "api.example.com")
    }

    func testOtherStatusesAreTheAppsAndReturnedAsTheyAre() async throws {
        for status in [403, 404, 429, 500] {
            StubURLProtocol.install { _ in .response(status: status) }
            let tokens = FakeTokens(current: bearer)
            let (_, response) = try await session(tokens: tokens).data(for: URLRequest(url: api))
            XCTAssertEqual(response.statusCode, status)
            let renewals = await tokens.renewCount
            XCTAssertEqual(renewals, 0)
        }
    }

    // MARK: 401 handling

    func testUnauthorizedRenewsOnceAndReplaysWithTheNewToken() async throws {
        StubURLProtocol.install { request in
            authHeader(request) == "Bearer tok-2" ? .response(status: 200) : .response(status: 401, headers: ["WWW-Authenticate": "Bearer error=\"invalid_token\""])
        }
        let tokens = FakeTokens(current: bearer, renewed: [AccessToken(value: "tok-2", tokenType: "Bearer")])
        let (_, response) = try await session(tokens: tokens).data(for: URLRequest(url: api))
        XCTAssertEqual(response.statusCode, 200)
        let renewals = await tokens.renewCount
        XCTAssertEqual(renewals, 1)
        XCTAssertEqual(StubURLProtocol.requests.map { authHeader($0) }, ["Bearer tok-1", "Bearer tok-2"])
    }

    func testABareUnauthorizedWithNoChallengeAlsoRenews() async throws {
        StubURLProtocol.install { request in
            authHeader(request) == "Bearer tok-2" ? .response(status: 200) : .response(status: 401)
        }
        let tokens = FakeTokens(current: bearer, renewed: [AccessToken(value: "tok-2", tokenType: "Bearer")])
        let (_, response) = try await session(tokens: tokens).data(for: URLRequest(url: api))
        XCTAssertEqual(response.statusCode, 200)
    }

    func testTwoUnauthorizedAnswersEndInSessionRejected() async throws {
        StubURLProtocol.install { _ in .response(status: 401, headers: ["WWW-Authenticate": "Bearer"]) }
        let tokens = FakeTokens(current: bearer, renewed: [AccessToken(value: "tok-2", tokenType: "Bearer")])
        do {
            _ = try await session(tokens: tokens).data(for: URLRequest(url: api))
            XCTFail("expected sessionRejected")
        } catch {
            XCTAssertEqual(error as? OAuthError, .reauthenticate(.sessionRejected))
        }
        let renewals = await tokens.renewCount
        XCTAssertEqual(renewals, 1, "one renewal, never a second")
        XCTAssertEqual(StubURLProtocol.requests.count, 2, "one request and one replay")
    }

    func testAConcurrentRefreshIsReusedInsteadOfRotatingAgain() async throws {
        // The source already holds a newer token by the time the 401 arrives.
        let tokens = FakeTokens(current: bearer)
        StubURLProtocol.install { request in
            authHeader(request) == "Bearer tok-1" ? .response(status: 401) : .response(status: 200)
        }
        // The first accessToken() call hands out tok-1; swap in a newer one for the next.
        let newer = AccessToken(value: "tok-9", tokenType: "Bearer")
        let source = SwappingTokens(first: bearer, then: newer)
        let session = try session(tokens: source)
        let (_, response) = try await session.data(for: URLRequest(url: api))
        XCTAssertEqual(response.statusCode, 200)
        let renewals = await source.renewCount
        XCTAssertEqual(renewals, 0)
        XCTAssertEqual(StubURLProtocol.requests.map { authHeader($0) }, ["Bearer tok-1", "Bearer tok-9"])
        _ = tokens
    }

    func testAStreamedBodyIsNotReplayedAfterTheRenewal() async throws {
        StubURLProtocol.install { _ in .response(status: 401) }
        let tokens = FakeTokens(current: bearer, renewed: [AccessToken(value: "tok-2", tokenType: "Bearer")])
        var request = URLRequest(url: api)
        request.httpMethod = "POST"
        request.httpBodyStream = InputStream(data: Data("body".utf8))
        let (_, response) = try await session(tokens: tokens).data(for: request)
        XCTAssertEqual(response.statusCode, 401)
        let renewals = await tokens.renewCount
        XCTAssertEqual(renewals, 1)
        XCTAssertEqual(StubURLProtocol.requests.count, 1)
    }

    // MARK: step-up (RFC 9470)

    func testInsufficientUserAuthenticationRaisesStepUpWithAcrValuesAndMaxAgeAndDoesNotRenew() async throws {
        StubURLProtocol.install { _ in
            .response(status: 401, headers: ["WWW-Authenticate": "Bearer error=\"insufficient_user_authentication\", error_description=\"a stronger authentication is needed\", acr_values=\"urn:example:mfa urn:example:hw\", max_age=300"])
        }
        let tokens = FakeTokens(current: bearer)
        do {
            _ = try await session(tokens: tokens).data(for: URLRequest(url: api))
            XCTFail("expected stepUp")
        } catch {
            XCTAssertEqual(error as? OAuthError, .stepUp(acrValues: ["urn:example:mfa", "urn:example:hw"], maxAge: 300))
        }
        let renewals = await tokens.renewCount
        XCTAssertEqual(renewals, 0, "a refresh yields the same acr: it is the loop this branch avoids")
        XCTAssertEqual(StubURLProtocol.requests.count, 1)
    }

    func testStepUpIsReadByParameterNameEvenUnderADPoPScheme() async throws {
        StubURLProtocol.install { _ in
            .response(status: 401, headers: ["WWW-Authenticate": "DPoP error=\"insufficient_user_authentication\", acr_values=\"mfa\""])
        }
        do {
            _ = try await session(tokens: FakeTokens(current: bearer)).data(for: URLRequest(url: api))
            XCTFail("expected stepUp")
        } catch {
            XCTAssertEqual(error as? OAuthError, .stepUp(acrValues: ["mfa"], maxAge: nil))
        }
    }

    func testAnUnparseableMaxAgeIsDroppedNotFatal() async throws {
        StubURLProtocol.install { _ in
            .response(status: 401, headers: ["WWW-Authenticate": "Bearer error=\"insufficient_user_authentication\", acr_values=\"mfa\", max_age=soon"])
        }
        do {
            _ = try await session(tokens: FakeTokens(current: bearer)).data(for: URLRequest(url: api))
            XCTFail("expected stepUp")
        } catch {
            XCTAssertEqual(error as? OAuthError, .stepUp(acrValues: ["mfa"], maxAge: nil))
        }
    }

    // MARK: DPoP

    func testDPoPTokenIsSentUnderTheDPoPSchemeWithAProofOverTheUrlWithoutQueryOrFragment() async throws {
        StubURLProtocol.install { _ in .response(status: 200) }
        let dpop = FakeDpop()
        var request = URLRequest(url: api)
        request.httpMethod = "POST"
        _ = try await session(tokens: FakeTokens(current: dpopToken), dpop: dpop).data(for: request)
        let sent = try XCTUnwrap(StubURLProtocol.requests.first)
        XCTAssertEqual(authHeader(sent), "DPoP tok-1")
        XCTAssertEqual(sent.value(forHTTPHeaderField: "DPoP"), "proof-1")
        let proofs = await dpop.proofs
        XCTAssertEqual(proofs, [FakeDpop.Proof(method: "POST", url: URL(string: "https://api.example.com/v1/items")!, nonce: nil, accessToken: "tok-1")])
    }

    func testABearerTokenGetsNoProofEvenWithAProofSource() async throws {
        StubURLProtocol.install { _ in .response(status: 200) }
        let dpop = FakeDpop()
        _ = try await session(tokens: FakeTokens(current: bearer), dpop: dpop).data(for: URLRequest(url: api))
        let sent = try XCTUnwrap(StubURLProtocol.requests.first)
        XCTAssertEqual(authHeader(sent), "Bearer tok-1")
        XCTAssertNil(sent.value(forHTTPHeaderField: "DPoP"))
        let proofs = await dpop.proofs
        XCTAssertTrue(proofs.isEmpty)
    }

    func testADPoPBoundTokenWithoutAProofSourceFailsClosed() async throws {
        StubURLProtocol.install { _ in .response(status: 200) }
        do {
            _ = try await session(tokens: FakeTokens(current: dpopToken), dpop: nil).data(for: URLRequest(url: api))
            XCTFail("expected invalidConfiguration")
        } catch OAuthError.configuration(.invalidConfiguration) {
        }
        XCTAssertTrue(StubURLProtocol.requests.isEmpty, "nothing was sent")
    }

    func testUseDpopNonceRetriesOnceWithTheNonce() async throws {
        StubURLProtocol.install { request in
            request.value(forHTTPHeaderField: "DPoP") == "proof-2"
                ? .response(status: 200)
                : .response(status: 401, headers: ["WWW-Authenticate": "DPoP error=\"use_dpop_nonce\"", "DPoP-Nonce": "nonce-A"])
        }
        let dpop = FakeDpop()
        let (_, response) = try await session(tokens: FakeTokens(current: dpopToken), dpop: dpop).data(for: URLRequest(url: api))
        XCTAssertEqual(response.statusCode, 200)
        let proofs = await dpop.proofs
        XCTAssertEqual(proofs.map { $0.nonce }, [nil, "nonce-A"])
        let observed = await dpop.observed
        XCTAssertEqual(observed.map { $0.origin }, ["https://api.example.com"])
        XCTAssertEqual(StubURLProtocol.requests.count, 2)
    }

    func testASecondNonceDemandIsANonceLoopNotAThirdAttempt() async throws {
        StubURLProtocol.install { _ in
            .response(status: 401, headers: ["WWW-Authenticate": "DPoP error=\"use_dpop_nonce\"", "DPoP-Nonce": "nonce-B"])
        }
        let tokens = FakeTokens(current: dpopToken)
        do {
            _ = try await session(tokens: tokens, dpop: FakeDpop()).data(for: URLRequest(url: api))
            XCTFail("expected nonceLoop")
        } catch {
            XCTAssertEqual(error as? OAuthError, .recoverable(.nonceLoop(origin: "https://api.example.com")))
        }
        XCTAssertEqual(StubURLProtocol.requests.count, 2)
        let renewals = await tokens.renewCount
        XCTAssertEqual(renewals, 0)
    }

    func testANonceChallengeWithoutANonceHeaderIsNotRetried() async throws {
        StubURLProtocol.install { _ in .response(status: 401, headers: ["WWW-Authenticate": "DPoP error=\"use_dpop_nonce\""]) }
        do {
            _ = try await session(tokens: FakeTokens(current: dpopToken), dpop: FakeDpop()).data(for: URLRequest(url: api))
            XCTFail("expected nonceLoop")
        } catch {
            XCTAssertEqual(error as? OAuthError, .recoverable(.nonceLoop(origin: "https://api.example.com")))
        }
        XCTAssertEqual(StubURLProtocol.requests.count, 1)
    }

    func testInvalidDpopProofFromASkewedDeviceClockIsRetriedOnceWithTheServersTimeAndSucceeds() async throws {
        let serverTime = Date(timeIntervalSince1970: 1_700_000_000)
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        let dateHeader = formatter.string(from: serverTime)
        StubURLProtocol.install { request in
            let iat = request.value(forHTTPHeaderField: "DPoP").flatMap { Self.iat(of: $0) }
            if let iat, abs(iat - Int(serverTime.timeIntervalSince1970)) <= 60 {
                return .response(status: 200, headers: ["Date": dateHeader], body: Data("ok".utf8))
            }
            return .response(status: 401, headers: ["Date": dateHeader, "WWW-Authenticate": "DPoP error=\"invalid_dpop_proof\""])
        }
        let tokens = FakeTokens(current: dpopToken)
        let factory = DpopProofFactory(key: SoftwareDpopKey(), clock: Clock(now: { serverTime.addingTimeInterval(-900) }))

        let (data, response) = try await session(tokens: tokens, dpop: factory).data(for: URLRequest(url: api))

        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(String(decoding: data, as: UTF8.self), "ok")
        let requests = StubURLProtocol.requests
        XCTAssertEqual(requests.count, 2, "one refusal, one corrected retry")
        XCTAssertEqual(requests.compactMap { $0.value(forHTTPHeaderField: "DPoP").flatMap { Self.iat(of: $0) } }, [1_699_999_100, 1_700_000_000])
        let renewals = await tokens.renewCount
        XCTAssertEqual(renewals, 0)
    }

    /// A loopback HTTP server that answers every request with a response a cache may keep. The
    /// built-in HTTP protocol is the only thing that consults `URLCache` and reports a local-cache
    /// fetch in the task's metrics, so this one test uses a real socket rather than the stub.
    private final class CacheableServer: Sendable {
        private let listener: NWListener
        private let served = OSAllocatedUnfairLock(initialState: 0)
        var requests: Int { served.withLock { $0 } }
        let port: UInt16

        init() async throws {
            listener = try NWListener(using: .tcp, on: .any)
            let served = self.served
            listener.newConnectionHandler = { connection in
                connection.start(queue: .global())
                connection.receive(minimumIncompleteLength: 1, maximumLength: 65_536) { _, _, _, _ in
                    served.withLock { $0 += 1 }
                    let head = "HTTP/1.1 200 OK\r\nDate: Tue, 14 Nov 2023 21:53:20 GMT\r\nCache-Control: public, max-age=31536000\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                    connection.send(content: Data(head.utf8), completion: .contentProcessed { _ in connection.cancel() })
                }
            }
            let listener = self.listener
            port = try await withCheckedThrowingContinuation { continuation in
                listener.stateUpdateHandler = { state in
                    switch state {
                    case .ready: continuation.resume(returning: listener.port!.rawValue)
                    case .failed(let error): continuation.resume(throwing: error)
                    default: break
                    }
                }
                listener.start(queue: .global())
            }
        }

        func stop() { listener.cancel() }
    }

    func testAResponseTheUrlCacheServedIsNotTakenForTheServersClock() async throws {
        let server = try await CacheableServer()
        defer { server.stop() }
        let origin = "http://127.0.0.1:\(server.port)"
        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = URLCache(memoryCapacity: 1_000_000, diskCapacity: 0)
        let dpop = FakeDpop()
        let session = AuthenticatedSession(tokens: FakeTokens(current: dpopToken), scope: try scope([origin]), dpop: dpop, session: URLSession(configuration: configuration))
        var request = URLRequest(url: URL(string: "\(origin)/v1/items")!)
        request.cachePolicy = .returnCacheDataElseLoad

        let (first, _) = try await session.data(for: request)
        let (second, _) = try await session.data(for: request)

        XCTAssertEqual(String(decoding: first, as: UTF8.self), "ok")
        XCTAssertEqual(String(decoding: second, as: UTF8.self), "ok")
        XCTAssertEqual(server.requests, 1, "the second answer came out of the URL cache")
        let observed = await dpop.observedDates
        XCTAssertEqual(observed, ["Tue, 14 Nov 2023 21:53:20 GMT", nil], "the network answer taught the clock; the cached one, stored earlier, did not")
    }

    private static func iat(of proof: String) -> Int? {
        guard let payload = proof.split(separator: ".").dropFirst().first,
              let data = Data(base64Encoded: String(payload).replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
                  + String(repeating: "=", count: (4 - payload.count % 4) % 4)),
              let claims = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        else { return nil }
        return claims["iat"] as? Int
    }

    func testInvalidDpopProofIsRetriedOnceThenCredentialsInvalidated() async throws {
        StubURLProtocol.install { _ in .response(status: 401, headers: ["WWW-Authenticate": "DPoP error=\"invalid_dpop_proof\""]) }
        let tokens = FakeTokens(current: dpopToken)
        do {
            _ = try await session(tokens: tokens, dpop: FakeDpop()).data(for: URLRequest(url: api))
            XCTFail("expected credentialsInvalidated")
        } catch {
            XCTAssertEqual(error as? OAuthError, .reauthenticate(.credentialsInvalidated))
        }
        XCTAssertEqual(StubURLProtocol.requests.count, 2)
        let renewals = await tokens.renewCount
        XCTAssertEqual(renewals, 0, "a refresh reuses the same key and cannot repair a key mismatch")
    }

    func testTokenSourceErrorsPropagateAndNothingIsSent() async throws {
        struct Failing: AccessTokenSource {
            func accessToken() async throws -> AccessToken { throw OAuthError.reauthenticate(.sessionExpired) }
            func renewAccessToken() async throws -> AccessToken { throw OAuthError.reauthenticate(.grantRejected) }
        }
        StubURLProtocol.install { _ in .response(status: 200) }
        do {
            _ = try await session(tokens: Failing()).data(for: URLRequest(url: api))
            XCTFail("expected sessionExpired")
        } catch {
            XCTAssertEqual(error as? OAuthError, .reauthenticate(.sessionExpired))
        }
        XCTAssertTrue(StubURLProtocol.requests.isEmpty)
    }

    // MARK: challenge parser

    func testParserReadsQuotedAndUnquotedParametersAndMultipleChallenges() {
        let challenges = AuthenticateChallenge.parse(
            #"Bearer realm="api", error=invalid_token, error_description="the \"token\" expired", DPoP algs="ES256 RS256", Basic"#
        )
        XCTAssertEqual(challenges.map { $0.scheme }, ["Bearer", "DPoP", "Basic"])
        XCTAssertEqual(challenges[0].parameters["realm"], "api")
        XCTAssertEqual(challenges[0].parameters["error"], "invalid_token")
        XCTAssertEqual(challenges[0].parameters["error_description"], #"the "token" expired"#)
        XCTAssertEqual(challenges[1].parameters["algs"], "ES256 RS256")
        XCTAssertTrue(challenges[2].parameters.isEmpty)
    }

    func testParserLowerCasesNamesAndKeepsTheFirstOccurrence() {
        let merged = AuthenticateChallenge.merged(AuthenticateChallenge.parse(#"Bearer ERROR="first", Error="second", DPoP error="third""#))
        XCTAssertEqual(merged["error"], "first")
    }

    func testParserReadsParametersWithNoScheme() {
        let merged = AuthenticateChallenge.merged(AuthenticateChallenge.parse(#"error="use_dpop_nonce""#))
        XCTAssertEqual(merged["error"], "use_dpop_nonce")
    }

    func testParserReadsAToken68() {
        let challenges = AuthenticateChallenge.parse("Negotiate YII3aGVsbG8=")
        XCTAssertEqual(challenges.first?.scheme, "Negotiate")
        XCTAssertEqual(challenges.first?.token68, "YII3aGVsbG8=")
        XCTAssertTrue(challenges.first?.parameters.isEmpty ?? false)
    }

    func testParserSurvivesMalformedInput() {
        let malformed = [
            "", " ", ",", ",,,", "=", "==", "\"", "\"\"", "\\", "Bearer error=", "Bearer error=\"", "Bearer error=\"unterminated",
            "Bearer =x", "Bearer \"quoted\"", "Bearer error==", "Bearer , , error = \"x\" ,", "error", "Bearer error=,acr_values=",
            "Bearer error=\"a\\", "\u{0}\u{1}\u{2}", "Bearer \u{FFFD}=\u{FFFD}", "Bearer é=ü", "𝄞=𝄞", "DPoP ===", "a=b=c=d",
            String(repeating: "Bearer a=b, ", count: 5_000), String(repeating: "\"", count: 10_001), String(repeating: "a=", count: 10_000),
        ]
        for header in malformed {
            let challenges = AuthenticateChallenge.parse(header)
            _ = AuthenticateChallenge.merged(challenges)
        }
        // And what could be read of a half-broken header is still read.
        let merged = AuthenticateChallenge.merged(AuthenticateChallenge.parse(#"Bearer error="insufficient_user_authentication", acr_values="#))
        XCTAssertEqual(merged["error"], "insufficient_user_authentication")
        XCTAssertEqual(AuthenticateChallenge.merged(AuthenticateChallenge.parse(#"Bearer error="a\"#))["error"], "a")
        XCTAssertTrue(AuthenticateChallenge.merged(AuthenticateChallenge.parse("Bearer =x"))["error"] == nil)
    }

    func testParserNeverTurnsGarbageIntoAnErrorParameter() {
        for header in ["Bearer realm=\"error=insufficient_user_authentication\"", "Bearer error_description=\"error=use_dpop_nonce\""] {
            XCTAssertNil(AuthenticateChallenge.merged(AuthenticateChallenge.parse(header))["error"], header)
        }
    }
}

/// Hands out `first` once and `then` afterwards, so the 401 handler finds a newer token already cached.
private actor SwappingTokens: AccessTokenSource {
    private let first: AccessToken
    private let next: AccessToken
    private var calls = 0
    private(set) var renewCount = 0

    init(first: AccessToken, then next: AccessToken) {
        self.first = first
        self.next = next
    }

    func accessToken() async throws -> AccessToken {
        calls += 1
        return calls == 1 ? first : next
    }

    func renewAccessToken() async throws -> AccessToken {
        renewCount += 1
        return next
    }
}
