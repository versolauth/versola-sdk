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
        let http = RecordingHTTP.json(100, "")
        await assertThrows(.recoverable(.server(status: 100, retryAfterMillis: nil, attempts: 1, elapsedMillis: 0))) {
            try await self.service(http).metadata()
        }
    }

    /// A redirect is not followed and is a deployment fault (`errors.md`), never a busy provider.
    func testARedirectFromDiscoveryIsConfigurationNotServer() async {
        for status in [301, 302, 304, 307, 308] {
            let http = RecordingHTTP.json(status, "")
            await assertThrows(.configuration(.discoveryMalformed(detail: "discovery answered HTTP \(status); redirects are not followed"))) {
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

    // MARK: - Endpoints must be https

    private func metadata(_ overrides: (inout ProviderMetadata) -> Void) -> ProviderMetadata {
        var value = AuthzKit.metadata()
        value.jwksUri = "https://id.example.com/jwks"
        overrides(&value)
        return value
    }

    private func assertRefused(_ name: String, _ document: ProviderMetadata, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try document.validate(configuredIssuer: AuthzKit.issuer), name, file: file, line: line) { error in
            guard case .configuration(.discoveryMalformed(let detail)) = error as? OAuthError else {
                return XCTFail("\(name): \(error)", file: file, line: line)
            }
            XCTAssertTrue(detail.contains(name), "the detail names the member: \(detail)", file: file, line: line)
        }
    }

    /// A document whose `token_endpoint` is `http://` would have the refresh token POSTed in the
    /// clear: the three endpoints every session needs are refused where the document is read.
    func testTheEndpointsEverySessionNeedsMustBeHttpsWhenTheDocumentIsRead() {
        assertRefused("token_endpoint", metadata { $0.tokenEndpoint = "http://id.example.com/token" })
        assertRefused("authorization_endpoint", metadata { $0.authorizationEndpoint = "http://id.example.com/authorize" })
        assertRefused("jwks_uri", metadata { $0.jwksUri = "http://id.example.com/jwks" })
    }

    /// An `http://` sign-out or revocation endpoint this app never uses must not make the whole
    /// provider unusable: those are refused where they are used (and logout is best effort).
    func testAnInsecureEndpointThatIsOnlyUsedLaterDoesNotSpoilTheDocument() throws {
        let document = metadata {
            $0.userinfoEndpoint = "http://id.example.com/userinfo"
            $0.revocationEndpoint = "http://id.example.com/revoke"
            $0.endSessionEndpoint = "http://id.example.com/logout"
            $0.pushedAuthorizationRequestEndpoint = "http://id.example.com/par"
        }
        XCTAssertNoThrow(try document.validate(configuredIssuer: AuthzKit.issuer))
    }

    func testTheInsecureOptionalEndpointsAreRefusedAtTheirPlaceOfUse() async throws {
        let insecure = metadata {
            $0.userinfoEndpoint = "http://id.example.com/userinfo"
            $0.revocationEndpoint = "http://id.example.com/revoke"
            $0.endSessionEndpoint = "http://id.example.com/logout"
            $0.pushedAuthorizationRequestEndpoint = "http://id.example.com/par"
        }
        let http = RecordingHTTP.json(200, "{}")
        func malformed(_ name: String, file: StaticString = #filePath, line: UInt = #line, _ body: () async throws -> Void) async {
            do {
                try await body()
                XCTFail("\(name) was used", file: file, line: line)
            } catch let OAuthError.configuration(.discoveryMalformed(detail)) {
                XCTAssertTrue(detail.contains(name), detail, file: file, line: line)
            } catch {
                XCTFail("\(name): \(error)", file: file, line: line)
            }
        }

        let tokens = try HTTPTokenClient(configuration: AuthzKit.configuration, metadata: { insecure }, httpClient: http)
        await malformed("revocation_endpoint") { try await tokens.revoke(refreshToken: "rt") }

        let par = PushedAuthorizationStarter(configuration: AuthzKit.configuration, httpClient: http, policy: .whenAdvertised)
        let request = AuthorizationRequest.create(configuration: AuthzKit.configuration, scopes: ["openid"])
        await malformed("pushed_authorization_request_endpoint") { _ = try await par.start(request: request, metadata: insecure, now: AuthzKit.now) }

        let userinfo = HTTPUserInfoClient(
            userinfoEndpoint: { insecure.userinfoEndpoint }, httpClient: http, dpop: nil,
            verifier: JwsVerifier(jwksUri: { nil }, allowedAlgorithms: { [] }, jwks: JwksClient(httpClient: http))
        )
        await malformed("userinfo_endpoint") { _ = try await userinfo.fetch(tokens: FixedTokenSource(), expectedSubject: "alice") }

        let flow = AuthorizationFlow(
            configuration: AuthzKit.configuration, discovery: DiscoveryService(issuer: AuthzKit.issuer, client: StaticDiscoveryClient(metadata: insecure), cache: MemoryMetadataCache()),
            pendingStore: MemoryPendingStore(), browser: ScriptedBrowser.answering(), states: SessionStateHub()
        )
        await malformed("end_session_endpoint") { _ = try await flow.endSession(idTokenHint: "hint") }
        let sent = await http.requests
        XCTAssertTrue(sent.isEmpty, "nothing was sent to an insecure endpoint")
    }

    private struct FixedTokenSource: AccessTokenSource {
        func accessToken() async throws -> AccessToken { AccessToken(value: "at", tokenType: "Bearer") }
        func renewAccessToken() async throws -> AccessToken { AccessToken(value: "at", tokenType: "Bearer") }
    }

    func testAnEndpointThatIsNotAnAbsoluteUrlWithAHostIsRefused() {
        assertRefused("token_endpoint", metadata { $0.tokenEndpoint = "/token" })
        assertRefused("token_endpoint", metadata { $0.tokenEndpoint = "https:token" })
        assertRefused("jwks_uri", metadata { $0.jwksUri = "ftp://id.example.com/jwks" })
        assertRefused("token_endpoint", metadata { $0.tokenEndpoint = "javascript:alert(1)" })
    }

    func testCleartextIsAcceptedOnLoopbackOnlyAsTheIssuerIs() throws {
        for host in ["localhost:8080", "127.0.0.1:8080", "[::1]:8080"] {
            let local = metadata {
                $0.issuer = "https://id.example.com"
                $0.tokenEndpoint = "http://\(host)/token"
                $0.jwksUri = "http://\(host)/jwks"
            }
            XCTAssertNoThrow(try local.validate(configuredIssuer: AuthzKit.issuer), host)
        }
        assertRefused("token_endpoint", metadata { $0.tokenEndpoint = "http://localhost.example.com/token" })
        assertRefused("token_endpoint", metadata { $0.tokenEndpoint = "http://10.0.2.2:8080/token" })
    }

    /// Cross-origin endpoints are legitimate (a provider whose JWKS or logout is on a CDN or
    /// another host); the rule is the scheme, not the origin.
    func testEndpointsOnOtherHttpsOriginsAreAccepted() throws {
        let document = metadata {
            $0.tokenEndpoint = "https://token.other.example.net/oauth/token"
            $0.jwksUri = "https://keys.cdn.example.org/jwks"
            $0.endSessionEndpoint = "https://sso.example.com/logout"
        }
        XCTAssertNoThrow(try document.validate(configuredIssuer: AuthzKit.issuer))
    }

    func testAnEmptyOptionalEndpointIsAbsentNotInvalid() throws {
        let document = metadata { $0.endSessionEndpoint = ""; $0.revocationEndpoint = "" }
        XCTAssertNoThrow(try document.validate(configuredIssuer: AuthzKit.issuer))
    }

    func testADocumentWithAnInsecureEndpointIsNotServedFromTheCacheEither() async throws {
        let poisoned = metadata { $0.tokenEndpoint = "http://id.example.com/token" }
        let http = RecordingHTTP.json(200, document)
        let served = try await service(http, cache: MemoryMetadataCache(poisoned)).metadata()
        XCTAssertEqual(served.tokenEndpoint, "https://id.example.com/token", "treated as absent, refetched")
    }
}
