import XCTest
@testable import OAuthClient
@testable import OAuthCore

final class URLSessionHTTPClientTests: XCTestCase {
    private let url = URL(string: "https://auth.example.com/token?code=abc")!

    override func tearDown() {
        StubURLProtocol.reset()
        super.tearDown()
    }

    func testResponseCarriesStatusBodyAndLowerCasedHeaders() async throws {
        StubURLProtocol.install { _ in
            .response(status: 200, headers: ["Content-Type": "application/json", "DPoP-Nonce": "n1"], body: Data("{}".utf8))
        }
        let client = URLSessionHTTPClient(session: StubURLProtocol.session())
        let response = try await client.send(HTTPRequest(method: .get, url: url))
        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(response.body, Data("{}".utf8))
        XCTAssertEqual(response.headers["content-type"], "application/json")
        XCTAssertEqual(response.header("DPoP-Nonce"), "n1")
    }

    func testRequestCarriesMethodHeadersAndBody() async throws {
        StubURLProtocol.install { _ in .response(status: 204) }
        let client = URLSessionHTTPClient(session: StubURLProtocol.session())
        let body = Data("grant_type=refresh_token".utf8)
        _ = try await client.send(HTTPRequest(
            method: .post, url: url, headers: ["Content-Type": "application/x-www-form-urlencoded"], body: body
        ))
        let sent = try XCTUnwrap(StubURLProtocol.requests.first)
        XCTAssertEqual(sent.httpMethod, "POST")
        XCTAssertEqual(sent.value(forHTTPHeaderField: "content-type"), "application/x-www-form-urlencoded")
        XCTAssertEqual(sent.bodyData, body)
    }

    func testRedirectIsReturnedNotFollowed() async throws {
        StubURLProtocol.install { _ in .redirect(location: "https://evil.example.org/steal") }
        let client = URLSessionHTTPClient(session: StubURLProtocol.session())
        let response = try await client.send(HTTPRequest(method: .post, url: url, body: Data("secret=1".utf8)))
        XCTAssertEqual(response.statusCode, 302)
        XCTAssertEqual(response.header("location"), "https://evil.example.org/steal")
        // The negative half: nothing was sent to the redirect target.
        XCTAssertEqual(StubURLProtocol.requests.count, 1)
        XCTAssertEqual(StubURLProtocol.requests.first?.url, url)
    }

    func testTransportErrorMapsToRecoverableNetworkWithoutTheURL() async throws {
        StubURLProtocol.install { _ in .failure(.notConnectedToInternet) }
        let client = URLSessionHTTPClient(session: StubURLProtocol.session())
        do {
            _ = try await client.send(HTTPRequest(method: .get, url: url))
            XCTFail("expected a network error")
        } catch let OAuthError.recoverable(.network(detail, attempts, elapsedMillis)) {
            XCTAssertEqual(attempts, 1)
            XCTAssertGreaterThanOrEqual(elapsedMillis, 0)
            XCTAssertFalse(detail.contains("auth.example.com"))
            XCTAssertFalse(detail.contains("code=abc"))
            XCTAssertTrue(detail.contains("URLError"))
        }
    }

    /// Whether the request ever connected is a typed fact recorded where the `URLError` is in hand
    /// (`ConnectionFlag`, read by `RefreshReplay`), not something read back out of the text.
    func testTheClientRecordsWhetherTheRequestEverConnected() {
        let never: [URLError.Code] = [
            .cannotFindHost, .cannotConnectToHost, .dnsLookupFailed, .notConnectedToInternet,
            .secureConnectionFailed, .serverCertificateHasBadDate, .serverCertificateUntrusted,
            .serverCertificateHasUnknownRoot, .serverCertificateNotYetValid, .clientCertificateRejected,
            .clientCertificateRequired,
        ]
        let maybe: [URLError.Code] = [.timedOut, .networkConnectionLost, .badServerResponse, .cannotParseResponse, .resourceUnavailable, .unknown]
        func recorded(_ code: URLError.Code) -> Bool {
            let flag = ConnectionFlag()
            ConnectionFlag.$current.withValue(flag) {
                _ = URLSessionHTTPClient.networkError(URLError(code, userInfo: [NSURLErrorFailingURLStringErrorKey: "https://auth.example.com/cb?code=abc"]), elapsed: .zero)
            }
            return flag.neverConnected
        }
        for code in never { XCTAssertTrue(recorded(code), "\(code.rawValue)") }
        for code in maybe { XCTAssertFalse(recorded(code), "\(code.rawValue)") }
        // Outside a refresh nothing is listening, and nothing fails.
        _ = URLSessionHTTPClient.networkError(URLError(.cannotFindHost), elapsed: .zero)
        // A failure that is not a URLError says nothing.
        let flag = ConnectionFlag()
        ConnectionFlag.$current.withValue(flag) { _ = URLSessionHTTPClient.networkError(nil, detail: "x", elapsed: .zero) }
        XCTAssertFalse(flag.neverConnected)
    }

    func testURLsInAnErrorTextAreStripped() {
        let stripped = URLSessionHTTPClient.stripURLs("could not connect to https://auth.example.com/cb?code=abc now")
        XCTAssertEqual(stripped, "could not connect to <url> now")
    }

    func testCancelledCallerGetsCancellationNotNetworkError() async {
        StubURLProtocol.install { _ in .failure(.cancelled) }
        let client = URLSessionHTTPClient(session: StubURLProtocol.session())
        do {
            _ = try await client.send(HTTPRequest(method: .get, url: url))
            XCTFail("expected cancellation")
        } catch is CancellationError {
        } catch {
            XCTFail("expected CancellationError, got \(error)")
        }
    }

    // MARK: - Cache

    /// A key set or a discovery document refetched on purpose (a `kid` it lacks, a rotated endpoint)
    /// must come from the provider, not from the `URLCache` of the app's session.
    func testRequestsIgnoreTheLocalCache() async throws {
        StubURLProtocol.install { _ in .response(status: 200, body: Data("{}".utf8)) }
        let client = URLSessionHTTPClient(session: StubURLProtocol.session())

        _ = try await client.send(HTTPRequest(method: .get, url: url))

        let sent = try XCTUnwrap(StubURLProtocol.requests.first)
        XCTAssertEqual(sent.cachePolicy, .reloadIgnoringLocalCacheData)
    }

    // MARK: - Size

    func testABodyAtTheLimitIsReturnedAndOneByteOverIsRefusedAsConfiguration() async throws {
        let limit = HTTPRequest.defaultMaxResponseBytes
        StubURLProtocol.install { _ in .response(status: 200, body: Data(repeating: 0x20, count: limit)) }
        let client = URLSessionHTTPClient(session: StubURLProtocol.session())
        let ok = try await client.send(HTTPRequest(method: .get, url: url))
        XCTAssertEqual(ok.body.count, limit)

        StubURLProtocol.install { _ in .response(status: 200, body: Data(repeating: 0x20, count: limit + 1)) }
        do {
            _ = try await client.send(HTTPRequest(method: .get, url: url))
            XCTFail("a body over the limit was returned")
        } catch let error as OAuthError {
            guard case .configuration(.invalidConfiguration(let detail)) = error else { return XCTFail("\(error)") }
            XCTAssertTrue(detail.contains("larger than"))
            XCTAssertFalse(detail.contains("code=abc"), "no URL in the detail")
        }
    }

    func testADeclaredLengthOverTheLimitIsRefusedBeforeTheBodyIsRead() async throws {
        StubURLProtocol.install { _ in .response(status: 200, headers: ["Content-Length": "\(50 << 20)"], body: Data("{}".utf8)) }
        let client = URLSessionHTTPClient(session: StubURLProtocol.session())
        do {
            _ = try await client.send(HTTPRequest(method: .get, url: url))
            XCTFail("returned")
        } catch let error as OAuthError {
            guard case .configuration(.invalidConfiguration) = error else { return XCTFail("\(error)") }
        }
    }

    func testARequestMayAskForMoreRoomThanTheDefault() async throws {
        StubURLProtocol.install { _ in .response(status: 200, body: Data(repeating: 0x20, count: 2048)) }
        let client = URLSessionHTTPClient(session: StubURLProtocol.session())
        do {
            _ = try await client.send(HTTPRequest(method: .get, url: url, maxResponseBytes: 1024))
            XCTFail("returned")
        } catch let error as OAuthError {
            guard case .configuration = error else { return XCTFail("\(error)") }
        }
    }

    // MARK: - Timeout

    private func hungClient(sessionTimeout: TimeInterval = 60, floor: TimeInterval = 0.05) -> URLSessionHTTPClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        configuration.timeoutIntervalForRequest = sessionTimeout
        return URLSessionHTTPClient(session: URLSession(configuration: configuration), minimumAttemptTimeout: floor)
    }

    private func assertTimesOut(_ client: URLSessionHTTPClient, file: StaticString = #filePath, line: UInt = #line) async {
        let started = ContinuousClock.now
        do {
            _ = try await client.send(HTTPRequest(method: .get, url: url))
            XCTFail("a request to a hung provider returned", file: file, line: line)
        } catch let OAuthError.recoverable(.network(detail, _, _)) {
            XCTAssertTrue(detail.contains("URLError"), file: file, line: line)
        } catch {
            XCTFail("expected recoverable network, got \(error)", file: file, line: line)
        }
        XCTAssertLessThan(ContinuousClock.now - started, .seconds(10), "bounded by the deadline, not by the session's default", file: file, line: line)
    }

    /// `spec/retry-policy.md`: `totalBudget` is the ceiling for one operation. A request to a
    /// provider that has stopped answering may not sit on the session's own 60 s (or, for a
    /// resource-style stall, longer) inside a 20 s budget.
    func testAnAttemptInsideAnOperationIsBoundedByWhatIsLeftOfItsBudget() async throws {
        StubURLProtocol.install { _ in .hang }
        let budget = try RetryPolicy(maxAttemptsPerOrigin: 1, maxTotalAttempts: 1, initialBackoff: 0, backoffMultiplier: 1, maxBackoff: 0, totalBudget: 0.1).newBudget()

        await OperationBudget.$current.withValue(budget) {
            await assertTimesOut(hungClient(sessionTimeout: 60))
        }
    }

    func testAnAttemptOutsideAnOperationStillEndsAtTheSessionsOwnTimeout() async throws {
        StubURLProtocol.install { _ in .hang }
        await assertTimesOut(hungClient(sessionTimeout: 0.1))
    }

    func testTheBudgetNeverStarvesAnAttemptBelowTheFloor() async throws {
        // A budget nearly spent still gives a request that has not been tried a real chance:
        // the code exchange cannot be repeated and the user's time in the browser is already gone.
        let budget = try RetryPolicy(maxAttemptsPerOrigin: 1, maxTotalAttempts: 1, initialBackoff: 0, backoffMultiplier: 1, maxBackoff: 0, totalBudget: 0.001).newBudget()
        StubURLProtocol.install { _ in .response(status: 200, body: Data("{}".utf8)) }
        let client = URLSessionHTTPClient(session: StubURLProtocol.session(), minimumAttemptTimeout: 5)

        let response = try await OperationBudget.$current.withValue(budget) {
            try await client.send(HTTPRequest(method: .get, url: url))
        }
        XCTAssertEqual(response.statusCode, 200)
    }
}
