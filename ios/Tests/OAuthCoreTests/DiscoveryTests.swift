import XCTest
@testable import OAuthCore

final class DiscoveryTests: XCTestCase {
    private let document = """
    {"issuer":"https://id.example.com","authorization_endpoint":"https://id.example.com/authorize",
     "token_endpoint":"https://id.example.com/token","jwks_uri":"https://id.example.com/jwks"}
    """

    private func service(_ http: RecordingHTTP, cache: ProviderMetadataCache = MemoryMetadataCache(),
                         issuer: String = AuthzKit.issuer) -> DiscoveryService {
        DiscoveryService(issuer: issuer, client: HTTPDiscoveryClient(httpClient: http), cache: cache)
    }

    private func assertThrows(
        _ expected: OAuthError, _ body: () async throws -> some Any,
        file: StaticString = #filePath, line: UInt = #line
    ) async {
        do {
            _ = try await body()
            XCTFail("expected \(expected)", file: file, line: line)
        } catch {
            XCTAssertEqual(error as? OAuthError, expected, file: file, line: line)
        }
    }

    func testFetchesTheWellKnownDocumentAndCachesIt() async throws {
        let http = RecordingHTTP.json(200, document)
        let cache = MemoryMetadataCache()
        let metadata = try await service(http, cache: cache).metadata()
        XCTAssertEqual(metadata.tokenEndpoint, "https://id.example.com/token")
        let requests = await http.requests
        XCTAssertEqual(requests.count, 1)
        XCTAssertEqual(requests[0].method, .get)
        XCTAssertEqual(requests[0].url.absoluteString, "https://id.example.com/.well-known/openid-configuration")
        XCTAssertEqual(requests[0].headers["Accept"], "application/json")
        let cached = try await cache.load()
        XCTAssertEqual(cached, metadata)
    }

    func testAnIssuerWithATrailingSlashDoesNotDoubleTheSlash() async throws {
        let http = RecordingHTTP.json(200, document)
        _ = try await service(http, issuer: "https://id.example.com/").metadata()
        let url = await http.requests[0].url.absoluteString
        XCTAssertEqual(url, "https://id.example.com/.well-known/openid-configuration")
    }

    func testAnIssuerPathIsKeptBeforeTheWellKnownSuffix() async throws {
        let doc = document.replacingOccurrences(of: "https://id.example.com\"", with: "https://id.example.com/tenant\"")
        let http = RecordingHTTP.json(200, doc)
        _ = try await service(http, issuer: "https://id.example.com/tenant").metadata()
        let url = await http.requests[0].url.absoluteString
        XCTAssertEqual(url, "https://id.example.com/tenant/.well-known/openid-configuration")
    }

    func testACachedDocumentSkipsTheNetwork() async throws {
        let http = RecordingHTTP.json(500, "")
        let cached = AuthzKit.metadata()
        let metadata = try await service(http, cache: MemoryMetadataCache(cached)).metadata()
        XCTAssertEqual(metadata, cached)
        let count = await http.requests.count
        XCTAssertEqual(count, 0)
    }

    func testASecondCallIsServedFromMemory() async throws {
        let http = RecordingHTTP.json(200, document)
        let service = service(http)
        _ = try await service.metadata()
        _ = try await service.metadata()
        let count = await http.requests.count
        XCTAssertEqual(count, 1)
    }

    func testADocumentCachedForAnotherIssuerIsIgnored() async throws {
        let http = RecordingHTTP.json(200, document)
        var foreign = AuthzKit.metadata()
        foreign.issuer = "https://other.example.org"
        let metadata = try await service(http, cache: MemoryMetadataCache(foreign)).metadata()
        XCTAssertEqual(metadata.issuer, AuthzKit.issuer)
        let count = await http.requests.count
        XCTAssertEqual(count, 1)
    }

    func testADocumentNamingAnotherIssuerIsRefusedAndNotCached() async throws {
        let http = RecordingHTTP.json(200, document.replacingOccurrences(
            of: "\"issuer\":\"https://id.example.com\"", with: "\"issuer\":\"https://evil.example.org\""))
        let cache = MemoryMetadataCache()
        await assertThrows(.configuration(.discoveryIssuerMismatch(
            configured: AuthzKit.issuer, advertised: "https://evil.example.org"))) {
            try await self.service(http, cache: cache).metadata()
        }
        let cached = try await cache.load()
        XCTAssertNil(cached)
    }

    func testADocumentWithoutATokenEndpointNamesTheMissingField() async {
        let http = RecordingHTTP.json(200, #"{"issuer":"https://id.example.com","authorization_endpoint":"https://id.example.com/a"}"#)
        await assertThrows(.configuration(.discoveryFieldMissing(field: "token_endpoint"))) {
            try await self.service(http).metadata()
        }
    }

    func testAServerErrorIsRecoverableServerWithItsStatus() async {
        let http = RecordingHTTP.json(500, "oops")
        await assertThrows(.recoverable(.server(status: 500, retryAfterMillis: nil, attempts: 1, elapsedMillis: 0))) {
            try await self.service(http).metadata()
        }
    }

    func testAMissingDocumentIsAConfigurationFaultNotARetry() async {
        let http = RecordingHTTP.json(404, "")
        do {
            _ = try await service(http).metadata()
            XCTFail("expected a failure")
        } catch let OAuthError.configuration(.invalidConfiguration(detail)) {
            XCTAssertTrue(detail.contains("HTTP 404"))
        } catch {
            XCTFail("unexpected \(error)")
        }
    }

    func testUndecodableJsonIsDiscoveryMalformed() async {
        let http = RecordingHTTP.json(200, "<html>not json</html>")
        do {
            _ = try await service(http).metadata()
            XCTFail("expected a failure")
        } catch OAuthError.configuration(.discoveryMalformed) {
        } catch {
            XCTFail("unexpected \(error)")
        }
    }

    func testATransportFailureIsRecoverableNetwork() async {
        let http = RecordingHTTP { _ in throw TransportFailure() }
        do {
            _ = try await service(http).metadata()
            XCTFail("expected a failure")
        } catch OAuthError.recoverable(.network(_, let attempts, _)) {
            XCTAssertEqual(attempts, 1)
        } catch {
            XCTFail("unexpected \(error)")
        }
    }

    func testAStatusDiscoveryHasNoUseForIsServerWithItsStatus() async {
        for status in [100, 302, 304] {
            let http = RecordingHTTP.json(status, "")
            await assertThrows(.recoverable(.server(status: status, retryAfterMillis: nil, attempts: 1, elapsedMillis: 0))) {
                try await self.service(http).metadata()
            }
        }
    }

    func testAFailedFetchIsNotRememberedSoTheNextCallRetries() async throws {
        let calls = Box(0)
        let body = document
        let http = RecordingHTTP { _ in
            let n = await calls.value + 1
            await calls.set(n)
            return n == 1 ? HTTPResponse(statusCode: 503) : HTTPResponse(statusCode: 200, body: Data(body.utf8))
        }
        let service = service(http)
        do {
            _ = try await service.metadata()
            XCTFail("expected a failure")
        } catch OAuthError.recoverable(.server(503, _, _, _)) {}
        let metadata = try await service.metadata()
        XCTAssertEqual(metadata.issuer, AuthzKit.issuer)
        let count = await http.requests.count
        XCTAssertEqual(count, 2)
    }

    func testConcurrentCallersShareOneFetch() async throws {
        let gate = Gate()
        let body = document
        let http = RecordingHTTP { _ in
            await gate.wait()
            return HTTPResponse(statusCode: 200, body: Data(body.utf8))
        }
        let service = service(http)
        let callers = (0..<8).map { _ in Task { try await service.metadata() } }
        await AuthzKit.waitUntil("the first fetch reaches the network") { await http.requests.count >= 1 }
        for _ in 0..<50 { await Task.yield() }
        await gate.open()
        for caller in callers {
            let metadata = try await caller.value
            XCTAssertEqual(metadata.issuer, AuthzKit.issuer)
        }
        let count = await http.requests.count
        XCTAssertEqual(count, 1)
    }

    func testACancelledCallerDoesNotStrandTheOthers() async throws {
        let gate = Gate()
        let body = document
        let http = RecordingHTTP { _ in
            await gate.wait()
            return HTTPResponse(statusCode: 200, body: Data(body.utf8))
        }
        let service = service(http)
        let cancelled = Task { try await service.metadata() }
        let survivor = Task { try await service.metadata() }
        await AuthzKit.waitUntil("the fetch starts") { await http.requests.count >= 1 }
        cancelled.cancel()
        await gate.open()
        let metadata = try await survivor.value
        XCTAssertEqual(metadata.issuer, AuthzKit.issuer)
    }

    func testStaticDiscoveryServesItsDocument() async throws {
        let fixed = AuthzKit.metadata()
        let service = DiscoveryService(
            issuer: AuthzKit.issuer, client: StaticDiscoveryClient(metadata: fixed), cache: MemoryMetadataCache())
        let metadata = try await service.metadata()
        XCTAssertEqual(metadata, fixed)
    }
}
