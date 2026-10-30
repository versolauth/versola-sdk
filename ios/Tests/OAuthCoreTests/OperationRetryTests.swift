import Foundation
import XCTest
@testable import OAuthCore

/// The operation table of `spec/retry-policy.md`, one row at a time (scenario 34): every request
/// the SDK originates is repeated under the running operation's budget except the
/// `authorization_code` exchange, a 501 or a 4xx is never repeated, and outside an operation a
/// request is made once, as it always was. Time is injected; nothing here sleeps.
final class OperationRetryTests: XCTestCase {
    private let world = RetryBudgetServerErrorTests.World()
    private let issuer = "https://id.example.com"

    private func operationBudget(cooldown: RetryCooldown? = nil, policy: RetryPolicy = .default) -> RetryBudget {
        policy.newBudget(clock: world.clock, random: RetryBudgetServerErrorTests.FixedRandom(fraction: 0), cooldown: cooldown, sleep: world.sleep)
    }

    private func within<T>(_ budget: RetryBudget, _ body: () async throws -> T) async throws -> T {
        try await OperationBudget.$current.withValue(budget) { try await body() }
    }

    private func failure(_ body: () async throws -> some Any) async -> OAuthError? {
        do { _ = try await body(); return nil } catch { return error as? OAuthError }
    }

    /// Answers `answers` in order, then repeats the last.
    private func http(_ answers: [HTTPResponse]) -> RecordingHTTP {
        let index = Box(0)
        return RecordingHTTP { _ in
            let i = await index.value
            await index.set(i + 1)
            return answers[min(i, answers.count - 1)]
        }
    }

    private func answer(_ status: Int, _ headers: [String: String] = [:], _ body: String = "") -> HTTPResponse {
        HTTPResponse(statusCode: status, headers: headers, body: Data(body.utf8))
    }

    private static let transient = [500, 502, 503, 504, 408, 429]

    // MARK: Discovery

    private let metadataDocument = #"{"issuer":"https://id.example.com","authorization_endpoint":"https://id.example.com/a","token_endpoint":"https://id.example.com/t","jwks_uri":"https://id.example.com/jwks"}"#

    private func discover(_ http: RecordingHTTP) async throws -> ProviderMetadata {
        try await HTTPDiscoveryClient(httpClient: http).fetch(issuer: issuer)
    }

    func testDiscoveryIsRepeatedOnEveryTransientStatusAndSurfacesServerWithTheRequestCount() async throws {
        for status in Self.transient {
            let http = http([answer(status)])
            let error = await failure { try await self.within(self.operationBudget()) { try await self.discover(http) } }
            let count = await http.requests.count
            XCTAssertEqual(count, 3, "HTTP \(status): maxAttemptsPerOrigin requests, original included")
            guard case .recoverable(.server(status, nil, 3, _))? = error else { XCTFail("HTTP \(status): \(String(describing: error))"); continue }
        }
    }

    func testDiscoverySucceedsOnTheRepeatAfterATransientAnswer() async throws {
        let http = http([answer(503), answer(200, [:], metadataDocument)])
        let metadata = try await within(operationBudget()) { try await self.discover(http) }
        XCTAssertEqual(metadata.issuer, issuer)
        let count = await http.requests.count
        XCTAssertEqual(count, 2)
    }

    func testDiscoveryWaitsTheRetryAfterOfA429() async throws {
        let http = http([answer(429, ["Retry-After": "3"]), answer(200, [:], metadataDocument)])
        _ = try await within(operationBudget()) { try await self.discover(http) }
        XCTAssertEqual(world.delays, [3.0])
    }

    func testDiscoveryIgnoresARetryAfterOnA500() async throws {
        let http = http([answer(500, ["Retry-After": "3"]), answer(200, [:], metadataDocument)])
        _ = try await within(operationBudget()) { try await self.discover(http) }
        XCTAssertEqual(world.delays, [0.0], "the backoff at zero jitter, not three seconds")
    }

    func testDiscoveryIsNotRepeatedOnA501OrA4xxOrAMalformedDocument() async {
        for (status, body) in [(501, ""), (505, ""), (404, ""), (403, ""), (200, "<html>")] {
            let http = http([answer(status, [:], body)])
            _ = await failure { try await self.within(self.operationBudget()) { try await self.discover(http) } }
            let count = await http.requests.count
            XCTAssertEqual(count, 1, "HTTP \(status)")
        }
    }

    func testAStatusDiscoveryHasNoUseForIsServerAndNeverRepeated() async {
        let http = http([answer(100)])
        let error = await failure { try await self.within(self.operationBudget()) { try await self.discover(http) } }
        let count = await http.requests.count
        XCTAssertEqual(count, 1)
        XCTAssertEqual(error, .recoverable(.server(status: 100, retryAfterMillis: nil, attempts: 1, elapsedMillis: 0)))
    }

    func testARedirectFromDiscoveryIsConfigurationAndNeverRepeated() async {
        for status in [301, 302, 307] {
            let http = http([answer(status, ["Location": "https://elsewhere.example.com/"])])
            let error = await failure { try await self.within(self.operationBudget()) { try await self.discover(http) } }
            let count = await http.requests.count
            XCTAssertEqual(count, 1, "HTTP \(status)")
            guard case .configuration(.discoveryMalformed)? = error else { XCTFail("HTTP \(status): \(String(describing: error))"); continue }
        }
    }

    func testATransportFailureOfDiscoveryIsRepeatedAsNetwork() async {
        let http = RecordingHTTP { _ in throw TransportFailure() }
        let error = await failure { try await self.within(self.operationBudget()) { try await self.discover(http) } }
        let count = await http.requests.count
        XCTAssertEqual(count, 3)
        guard case .recoverable(.network(_, 3, _))? = error else { return XCTFail("\(String(describing: error))") }
    }

    func testOutsideAnOperationAFailedDiscoveryIsMadeOnce() async {
        let http = http([answer(503)])
        let error = await failure { try await self.discover(http) }
        let count = await http.requests.count
        XCTAssertEqual(count, 1)
        guard case .recoverable(.server(503, nil, 1, _))? = error else { return XCTFail("\(String(describing: error))") }
    }

    // MARK: The key set

    private let jwksDocument = #"{"keys":[]}"#

    func testTheKeySetIsRepeatedOnTransientStatusesAndNotOnA4xxOr501() async {
        for status in Self.transient {
            let http = http([answer(status)])
            let error = await failure { try await self.within(self.operationBudget()) { try await JwksClient(httpClient: http).keys(uri: "https://id.example.com/jwks", forceRefresh: true) } }
            let count = await http.requests.count
            XCTAssertEqual(count, 3, "HTTP \(status)")
            guard case .recoverable(.server(status, nil, 3, _))? = error else { XCTFail("HTTP \(status): \(String(describing: error))"); continue }
        }
        for status in [501, 404] {
            let http = http([answer(status)])
            _ = await failure { try await self.within(self.operationBudget()) { try await JwksClient(httpClient: http).keys(uri: "https://id.example.com/jwks", forceRefresh: true) } }
            let count = await http.requests.count
            XCTAssertEqual(count, 1, "HTTP \(status)")
        }
    }

    func testAStatusTheKeySetHasNoUseForIsServerWithItsStatusAndNeverRepeated() async {
        for status in [204, 401, 404] {
            let http = http([answer(status)])
            let error = await failure { try await self.within(self.operationBudget()) { try await JwksClient(httpClient: http).keys(uri: "https://id.example.com/jwks", forceRefresh: true) } }
            let count = await http.requests.count
            XCTAssertEqual(count, 1, "HTTP \(status)")
            XCTAssertEqual(error, .recoverable(.server(status: status, retryAfterMillis: nil, attempts: 1, elapsedMillis: 0)))
        }
        XCTAssertEqual(world.delays, [])
    }

    func testTheKeySetRecoversOnTheRepeat() async throws {
        let http = http([answer(502), answer(200, [:], jwksDocument)])
        let loaded = try await within(operationBudget()) { try await JwksClient(httpClient: http).keys(uri: "https://id.example.com/jwks", forceRefresh: true) }
        XCTAssertTrue(loaded.fetched)
        let count = await http.requests.count
        XCTAssertEqual(count, 2)
    }

    // MARK: Pushed authorization request

    private let parEndpoint = "https://id.example.com/par"
    private let created = #"{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":60}"#

    private func push(_ http: RecordingHTTP) async throws -> StartedAuthorization {
        let configuration = AuthzKit.configuration
        let starter = PushedAuthorizationStarter(configuration: configuration, httpClient: http, policy: .required)
        let request = AuthorizationRequest.create(configuration: configuration, scopes: ["openid"], dpopJkt: "jkt-1")
        return try await starter.start(request: request, metadata: AuthzKit.metadata(parEndpoint: parEndpoint), now: AuthzKit.now)
    }

    func testThePushIsRepeatedOnTransientStatusesAndSucceedsOnTheRepeat() async throws {
        for status in Self.transient {
            let http = http([answer(status)])
            let error = await failure { try await self.within(self.operationBudget()) { try await self.push(http) } }
            let count = await http.requests.count
            XCTAssertEqual(count, 3, "HTTP \(status)")
            guard case .recoverable(.server(status, nil, 3, _))? = error else { XCTFail("HTTP \(status): \(String(describing: error))"); continue }
        }
        let http = http([answer(503), answer(201, [:], created)])
        _ = try await within(operationBudget()) { try await self.push(http) }
        let count = await http.requests.count
        XCTAssertEqual(count, 2)
    }

    func testThePushIsNotRepeatedOnA501OrARejection() async {
        for (status, body) in [(501, ""), (400, #"{"error":"invalid_request"}"#), (401, #"{"error":"invalid_client"}"#)] {
            let http = http([answer(status, [:], body)])
            _ = await failure { try await self.within(self.operationBudget()) { try await self.push(http) } }
            let count = await http.requests.count
            XCTAssertEqual(count, 1, "HTTP \(status)")
        }
    }

    // MARK: Token endpoint: revocation repeated, the code exchange not

    private let tokenMetadata = ProviderMetadata(
        issuer: "https://id.example.com", authorizationEndpoint: "https://id.example.com/authorize",
        tokenEndpoint: "https://id.example.com/token", revocationEndpoint: "https://id.example.com/revoke"
    )

    private func tokenClient(_ http: RecordingHTTP) throws -> HTTPTokenClient {
        let document = tokenMetadata
        return try HTTPTokenClient(
            configuration: CoreConfiguration(issuer: issuer, clientId: "mobile", redirectUri: URL(string: "https://app.example.com/oauth")!),
            metadata: { document }, httpClient: http
        )
    }

    private func grant() -> AuthorizationGrant {
        AuthorizationGrant(code: "the-code", codeVerifier: String(repeating: "v", count: 43), redirectUri: "https://app.example.com/oauth", resources: [], extensions: [:], nonce: "n")
    }

    func testRevocationIsRepeatedOnTransientStatusesUnderTheBudget() async throws {
        for status in Self.transient {
            let http = http([answer(status)])
            let client = try tokenClient(http)
            let error = await failure { try await self.within(self.operationBudget()) { try await client.revoke(refreshToken: "rt") } }
            let count = await http.requests.count
            XCTAssertEqual(count, 3, "HTTP \(status): exactly maxAttemptsPerOrigin revocation requests")
            guard case .recoverable(.server(status, nil, 3, _))? = error else { XCTFail("HTTP \(status): \(String(describing: error))"); continue }
        }
        let http = http([answer(503), answer(200)])
        try await within(operationBudget()) { try await self.tokenClient(http).revoke(refreshToken: "rt") }
        let count = await http.requests.count
        XCTAssertEqual(count, 2)
    }

    func testRevocationIsNotRepeatedOnA501OrARefusal() async throws {
        for (status, body) in [(501, ""), (400, #"{"error":"invalid_request"}"#), (401, #"{"error":"invalid_client"}"#)] {
            let http = http([answer(status, [:], body)])
            let client = try tokenClient(http)
            _ = await failure { try await self.within(self.operationBudget()) { try await client.revoke(refreshToken: "rt") } }
            let count = await http.requests.count
            XCTAssertEqual(count, 1, "HTTP \(status)")
        }
    }

    func testTheCodeExchangeIsMadeOnceOnEveryTransientStatus() async throws {
        for status in Self.transient {
            let http = http([answer(status)])
            let client = try tokenClient(http)
            let error = await failure { try await self.within(self.operationBudget()) { try await client.exchange(self.grant()) } }
            let count = await http.requests.count
            XCTAssertEqual(count, 1, "HTTP \(status): a spent code is not replayed")
            guard case .recoverable(.server(status, _, 1, _))? = error else { XCTFail("HTTP \(status): \(String(describing: error))"); continue }
        }
        XCTAssertEqual(world.delays, [], "and it did not wait")
    }

    func testARetryAfterOnTheCodeExchangeIsRememberedAndQuietsTheNextRequestToThatOrigin() async throws {
        let cooldown = RetryCooldown(clock: world.clock)
        let http = http([answer(429, ["Retry-After": "30"])])
        let client = try tokenClient(http)
        let first = await failure { try await self.within(self.operationBudget(cooldown: cooldown)) { try await client.exchange(self.grant()) } }
        guard case .recoverable(.server(429, 30_000, 1, _))? = first else { return XCTFail("\(String(describing: first))") }

        // A revocation in another operation, ten seconds on: refused before it is sent.
        world.advance(10)
        let second = await failure { try await self.within(self.operationBudget(cooldown: cooldown)) { try await client.revoke(refreshToken: "rt") } }
        let count = await http.requests.count
        XCTAssertEqual(count, 1, "the revocation was never sent")
        XCTAssertEqual(second, .recoverable(.server(status: 429, retryAfterMillis: 20_000, attempts: 0, elapsedMillis: 0)))
    }

    /// The exchange is not refused by a cooldown: `login()` checks that before the browser opens (a
    /// refusal there costs the user nothing), and a code that has got this far is sent and answered.
    func testACodeExchangeIsSentWhileTheOriginIsCoolingDown() async throws {
        let cooldown = RetryCooldown(clock: world.clock)
        await cooldown.record(origin: DpopOrigin.of(URL(string: "https://id.example.com/token")!), status: 503, retryAfterMillis: 10_000)
        let http = http([answer(200, [:], #"{"access_token":"at","token_type":"Bearer","expires_in":300}"#)])
        let client = try tokenClient(http)
        let issued = try await within(operationBudget(cooldown: cooldown)) { try await client.exchange(self.grant()) }
        XCTAssertEqual(issued.accessToken, "at")
        let count = await http.requests.count
        XCTAssertEqual(count, 1)
    }

    // MARK: One budget for the whole operation

    /// "A discovery that failed twice leaves less for the push" (`spec/retry-policy.md`): the
    /// allowance is the operation's, whichever client makes the request.
    func testAnOperationsClientsDrawOnOneAllowance() async throws {
        let budget = operationBudget()
        let discovery = http([answer(500), answer(500), answer(200, [:], metadataDocument)])
        let keys = http([answer(500)])
        let (metadata, error): (ProviderMetadata, OAuthError?) = try await within(budget) {
            let metadata = try await self.discover(discovery)
            let error = await self.failure { try await JwksClient(httpClient: keys).keys(uri: "https://id.example.com/jwks", forceRefresh: true) }
            return (metadata, error)
        }
        XCTAssertEqual(metadata.issuer, issuer)
        let discoveryRequests = await discovery.requests.count
        XCTAssertEqual(discoveryRequests, 3)
        let keyRequests = await keys.requests.count
        XCTAssertEqual(keyRequests, 1, "two failures were already spent at this origin; one is left, and one failure ends it")
        guard case .recoverable(.server(500, nil, 1, _))? = error else { return XCTFail("\(String(describing: error))") }
    }
}
