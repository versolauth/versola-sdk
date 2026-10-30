import Foundation
import XCTest
@testable import OAuthCore

final class JwksTests: XCTestCase {
    private let uri = "https://issuer.example.com/jwks.json"
    private let rsa = JoseTestKeys.rsa.jwk(kid: "rsa")
    private let ec = JoseTestKeys.p256.jwk(kid: "ec")

    func testClientGetsJwksUriWithAcceptJsonAndThenAnswersFromMemory() async throws {
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(rsa, ec))
        let client = JwksClient(httpClient: stub)

        let first = try await client.keys(uri: uri, forceRefresh: false)
        let second = try await client.keys(uri: uri, forceRefresh: false)

        XCTAssertTrue(first.fetched)
        XCTAssertFalse(second.fetched)
        XCTAssertEqual(first.keys.keys.map(\.kid), ["rsa", "ec"])
        XCTAssertEqual(second.keys, first.keys)
        let requests = await stub.requests
        XCTAssertEqual(requests.count, 1)
        XCTAssertEqual(requests[0].method, .get)
        XCTAssertEqual(requests[0].url.absoluteString, uri)
        XCTAssertEqual(requests[0].headers["Accept"], "application/json")
    }

    func testCacheIsReadBeforeTheNetworkAndNothingIsRequested() async throws {
        let stub = JoseStubHTTP()
        let cache = MemoryJwksCache()
        try await cache.save(JsonWebKeySet(keys: [rsa]))

        let loaded = try await JwksClient(httpClient: stub, cache: cache).keys(uri: uri, forceRefresh: false)

        XCTAssertFalse(loaded.fetched)
        XCTAssertEqual(loaded.keys.keys, [rsa])
        let count = await stub.requestCount()
        XCTAssertEqual(count, 0)
    }

    func testForcedRefreshFetchesAgainReplacesTheKeysAndUpdatesTheCache() async throws {
        let stub = JoseStubHTTP()
        let cache = MemoryJwksCache()
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(rsa))
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(ec))
        let client = JwksClient(httpClient: stub, cache: cache)

        _ = try await client.keys(uri: uri, forceRefresh: false)
        let refreshed = try await client.keys(uri: uri, forceRefresh: true)
        let afterwards = try await client.keys(uri: uri, forceRefresh: false)

        XCTAssertTrue(refreshed.fetched)
        XCTAssertEqual(refreshed.keys.keys.map(\.kid), ["ec"])
        XCTAssertFalse(afterwards.fetched)
        XCTAssertEqual(afterwards.keys.keys.map(\.kid), ["ec"])
        let cached = try await cache.load()
        XCTAssertEqual(cached?.keys.map(\.kid), ["ec"])
        let count = await stub.requestCount()
        XCTAssertEqual(count, 2)
    }

    func testAColdClientFetchesWhenTheCacheIsEmptyAndFillsTheCache() async throws {
        let stub = JoseStubHTTP()
        let cache = MemoryJwksCache()
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(rsa))

        _ = try await JwksClient(httpClient: stub, cache: cache).keys(uri: uri, forceRefresh: false)

        let cached = try await cache.load()
        XCTAssertEqual(cached?.keys, [rsa])
    }

    func testKeysTheSdkCannotUseAreSkippedAndTheUsableOnesKept() async throws {
        let document = """
        {"keys":[
          {"kty":"OKP","crv":"Ed25519","x":"abc","kid":"okp"},
          {"kty":"oct","k":"abc","kid":"oct"},
          {"kty":"RSA","n":5,"e":"AQAB","kid":"numeric-n"},
          {"kty":"RSA","kid":"no-material"},
          {"kty":"EC","crv":"P-256","kid":"no-coordinates"},
          "not an object",
          {"kid":"no-kty"},
          {"kty":"EC","crv":"P-256","x":"\(ec.x!)","y":"\(ec.y!)","kid":"ec","use":"sig","alg":"ES256"}
        ]}
        """
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", text: document)

        let loaded = try await JwksClient(httpClient: stub).keys(uri: uri, forceRefresh: false)

        XCTAssertEqual(loaded.keys.keys.map(\.kid), ["ec"])
        XCTAssertEqual(loaded.keys.keys.first?.use, "sig")
        XCTAssertEqual(loaded.keys.keys.first?.alg, "ES256")
    }

    func testDocumentThatIsNotAJwkSetIsDiscoveryMalformedAndDoesNotReplaceCachedKeys() async throws {
        let stub = JoseStubHTTP()
        let cache = MemoryJwksCache()
        try await cache.save(JsonWebKeySet(keys: [rsa]))
        let client = JwksClient(httpClient: stub, cache: cache)
        for body in ["not json", #"{"keys":"nope"}"#, "[]", #"{"nokeys":[]}"#] {
            await stub.enqueue("/jwks.json", text: body)
            let error = await joseThrown { _ = try await client.keys(uri: uri, forceRefresh: true) }
            guard case .configuration(.discoveryMalformed)? = error as? OAuthError else {
                return XCTFail("not discoveryMalformed for \(body): \(String(describing: error))")
            }
        }
        let cached = try await cache.load()
        XCTAssertEqual(cached?.keys, [rsa])
        // And the keys that worked are still served without a request.
        let served = try await client.keys(uri: uri, forceRefresh: false)
        XCTAssertEqual(served.keys.keys, [rsa])
    }

    func testHttp500IsARecoverableServerFailure() async {
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", status: 500)
        let error = await joseThrown { _ = try await JwksClient(httpClient: stub).keys(uri: uri, forceRefresh: false) }
        XCTAssertEqual(error as? OAuthError, .recoverable(.server(status: 500, retryAfterMillis: nil, attempts: 1, elapsedMillis: 0)))
    }

    func testNon200StatusesAreNotKeys() async {
        for status in [204, 401, 404, 503] {
            let stub = JoseStubHTTP()
            await stub.enqueue("/jwks.json", status: status, body: JoseTestTokens.jwks(rsa))
            let error = await joseThrown { _ = try await JwksClient(httpClient: stub).keys(uri: uri, forceRefresh: false) }
            // Every one is `server` with its status: a 503 because the provider is busy, the rest
            // because the key set has no use for them (`spec/retry-policy.md`, "unexpected").
            // Never a key, and never a transport failure.
            guard case .recoverable(.server(let seen, nil, 1, _))? = error as? OAuthError, seen == status else {
                return XCTFail("status \(status): \(String(describing: error))")
            }
        }
    }

    func testRedirectIsNotFollowedAndIsADeploymentFault() async {
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", status: 302, headers: ["Location": "https://evil.example.com/jwks.json"])
        let error = await joseThrown { _ = try await JwksClient(httpClient: stub).keys(uri: uri, forceRefresh: false) }
        guard case .configuration(.discoveryMalformed)? = error as? OAuthError else { return XCTFail("\(String(describing: error))") }
        let count = await stub.requestCount()
        XCTAssertEqual(count, 1)
    }

    func testTransportFailureIsARecoverableNetworkFailure() async {
        let stub = JoseStubHTTP()
        await stub.enqueueFailure("/jwks.json")
        let error = await joseThrown { _ = try await JwksClient(httpClient: stub).keys(uri: uri, forceRefresh: false) }
        guard case .recoverable(.network)? = error as? OAuthError else { return XCTFail("\(String(describing: error))") }
    }

    func testAFailedFetchLeavesTheClientAbleToFetchAgain() async throws {
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", status: 500)
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(rsa))
        let client = JwksClient(httpClient: stub)

        _ = await joseThrown { _ = try await client.keys(uri: uri, forceRefresh: false) }
        let loaded = try await client.keys(uri: uri, forceRefresh: false)

        XCTAssertTrue(loaded.fetched)
        XCTAssertEqual(loaded.keys.keys, [rsa])
    }

    func testUriThatIsNotAUrlIsDiscoveryMalformed() async {
        let error = await joseThrown { _ = try await JwksClient(httpClient: JoseStubHTTP()).keys(uri: "not a url", forceRefresh: false) }
        guard case .configuration(.discoveryMalformed)? = error as? OAuthError else { return XCTFail("\(String(describing: error))") }
    }

    func testRacingCallersShareOneRequest() async throws {
        let stub = JoseStubHTTP(hold: true)
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(rsa))
        let client = JwksClient(httpClient: stub)
        let uri = self.uri

        let callers = (0..<20).map { _ in Task { try await client.keys(uri: uri, forceRefresh: false) } }
        // Await the effect, bounded, rather than a delay: the first caller's request is in flight.
        var spins = 0
        while await stub.requestCount() == 0, spins < 100_000 {
            await Task.yield()
            spins += 1
        }
        for _ in 0..<100 { await Task.yield() }
        await stub.release()

        for caller in callers {
            let loaded = try await caller.value
            XCTAssertEqual(loaded.keys.keys, [rsa])
        }
        let count = await stub.requestCount()
        XCTAssertEqual(count, 1)
    }

    func testMemoryCacheSavesAndLoads() async throws {
        let cache = MemoryJwksCache()
        let empty = try await cache.load()
        XCTAssertNil(empty)
        try await cache.save(JsonWebKeySet(keys: [rsa]))
        let loaded = try await cache.load()
        XCTAssertEqual(loaded?.keys, [rsa])
    }

    // MARK: - Expiry

    /// A key set whose save time and lifetime the test chooses, standing in for the file on disk.
    private actor AgedKeys: JwksCache {
        var stored: JsonWebKeySet?
        var at: Date?
        var life: TimeInterval?
        init(_ stored: JsonWebKeySet?, at: Date?, lifetime: TimeInterval? = nil) {
            self.stored = stored
            self.at = at
            self.life = lifetime
        }
        func load() async throws -> JsonWebKeySet? { stored }
        func save(_ set: JsonWebKeySet) async throws { stored = set }
        func save(_ set: JsonWebKeySet, lifetime: TimeInterval?) async throws {
            stored = set
            life = lifetime
            at = Date(timeIntervalSince1970: 1_800_000_000)
        }
        func savedAt() async throws -> Date? { at }
        func lifetime() async throws -> TimeInterval? { life }
    }

    func testAKeySetIsFetchedAgainOnceItsMaxAgeHasElapsed() async throws {
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", headers: ["Cache-Control": "public, max-age=600"], body: JoseTestTokens.jwks(rsa))
        await stub.enqueue("/jwks.json", headers: ["Cache-Control": "max-age=600"], body: JoseTestTokens.jwks(ec))
        let time = ManualClock()
        let client = JwksClient(httpClient: stub, clock: time.clock)

        let first = try await client.keys(uri: uri, forceRefresh: false)
        time.advance(599)
        let within = try await client.keys(uri: uri, forceRefresh: false)
        time.advance(2)
        let after = try await client.keys(uri: uri, forceRefresh: false)

        XCTAssertTrue(first.fetched)
        XCTAssertFalse(within.fetched, "still inside the provider's max-age")
        XCTAssertTrue(after.fetched, "a withdrawn key does not stay trusted for the life of the process")
        XCTAssertEqual(after.keys.keys.map(\.kid), ["ec"])
        let count = await stub.requestCount()
        XCTAssertEqual(count, 2)
    }

    func testWithoutACacheControlHeaderTheKeysLastADay() async throws {
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(rsa))
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(rsa))
        let time = ManualClock()
        let client = JwksClient(httpClient: stub, clock: time.clock)

        _ = try await client.keys(uri: uri, forceRefresh: false)
        time.advance(24 * 3600 - 1)
        let within = try await client.keys(uri: uri, forceRefresh: false)
        time.advance(2)
        let after = try await client.keys(uri: uri, forceRefresh: false)

        XCTAssertFalse(within.fetched)
        XCTAssertTrue(after.fetched)
    }

    func testAnExpiredSetIsNotServedWhenTheRefetchFails() async throws {
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", headers: ["Cache-Control": "max-age=300"], body: JoseTestTokens.jwks(rsa))
        await stub.enqueueFailure("/jwks.json")
        let time = ManualClock()
        let client = JwksClient(httpClient: stub, clock: time.clock)
        _ = try await client.keys(uri: uri, forceRefresh: false)
        time.advance(301)

        let error = await joseThrown { _ = try await client.keys(uri: uri, forceRefresh: false) }

        guard case .recoverable? = error as? OAuthError else { return XCTFail("\(String(describing: error))") }
    }

    // MARK: - Stale if error (the ID token of a refresh only)

    /// The provider has already rotated the refresh token when the ID token is judged, so a key
    /// set that cannot be refetched must not cost the refresh its access token for the length of
    /// the outage: the expired set is used, bounded, and only for this check.
    func testAnExpiredSetIsServedStaleToARefreshValidationWhenTheRefetchFails() async throws {
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", headers: ["Cache-Control": "max-age=300"], body: JoseTestTokens.jwks(rsa))
        await stub.enqueueFailure("/jwks.json")
        let time = ManualClock()
        let client = JwksClient(httpClient: stub, clock: time.clock)
        _ = try await client.keys(uri: uri, forceRefresh: false)
        time.advance(301)

        let uri = self.uri
        let loaded = try await staleAllowed { try await client.keys(uri: uri, forceRefresh: false) }

        XCTAssertEqual(loaded.keys.keys, [rsa])
        XCTAssertTrue(loaded.stale, "the caller can tell the set is past its lifetime")
        XCTAssertTrue(loaded.fetched, "a refetch was just tried: the verifier must not try another for an unknown kid")
    }

    func testStaleIsNeverServedToAnyoneElse() async throws {
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", headers: ["Cache-Control": "max-age=300"], body: JoseTestTokens.jwks(rsa))
        await stub.enqueueFailure("/jwks.json")
        let time = ManualClock()
        let client = JwksClient(httpClient: stub, clock: time.clock)
        _ = try await client.keys(uri: uri, forceRefresh: false)
        time.advance(301)

        let error = await joseThrown { _ = try await client.keys(uri: uri, forceRefresh: false) }

        guard case .recoverable? = error as? OAuthError else { return XCTFail("\(String(describing: error))") }
    }

    func testStaleIsBoundedToAWeekPastTheLifetime() async throws {
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", headers: ["Cache-Control": "max-age=300"], body: JoseTestTokens.jwks(rsa))
        await stub.enqueueFailure("/jwks.json")
        await stub.enqueueFailure("/jwks.json")
        let time = ManualClock()
        let client = JwksClient(httpClient: stub, clock: time.clock)
        let uri = self.uri
        _ = try await client.keys(uri: uri, forceRefresh: false)

        time.advance(300 + CacheLifetime.maximumStale - 1)
        let inside = try await staleAllowed { try await client.keys(uri: uri, forceRefresh: false) }
        time.advance(2)
        let error = await joseThrown { _ = try await staleAllowed { try await client.keys(uri: uri, forceRefresh: false) } }

        XCTAssertTrue(inside.stale)
        guard case .recoverable? = error as? OAuthError else { return XCTFail("a key set older than the bound was served: \(String(describing: error))") }
    }

    func testAnAnswerThatIsNotAKeySetIsNotMaskedByTheStaleCopy() async throws {
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", headers: ["Cache-Control": "max-age=300"], body: JoseTestTokens.jwks(rsa))
        await stub.enqueue("/jwks.json", text: "<html>captive portal</html>")
        let time = ManualClock()
        let client = JwksClient(httpClient: stub, clock: time.clock)
        _ = try await client.keys(uri: uri, forceRefresh: false)
        time.advance(301)

        let uri = self.uri
        let error = await joseThrown { _ = try await staleAllowed { try await client.keys(uri: uri, forceRefresh: false) } }

        guard case .configuration(.discoveryMalformed)? = error as? OAuthError else { return XCTFail("\(String(describing: error))") }
    }

    func testAnExpiredSetOnDiskIsServedStaleToAColdClientWhenTheRefetchFails() async throws {
        let time = ManualClock()
        let stub = JoseStubHTTP()
        await stub.enqueueFailure("/jwks.json")
        let disk = AgedKeys(JsonWebKeySet(keys: [rsa]), at: time.clock.now() - 3 * 24 * 3600, lifetime: 3600)

        let uri = self.uri
        let loaded = try await staleAllowed { try await JwksClient(httpClient: stub, cache: disk, clock: time.clock).keys(uri: uri, forceRefresh: false) }

        XCTAssertEqual(loaded.keys.keys, [rsa])
        XCTAssertTrue(loaded.stale)
    }

    /// A stale set that lacks the token's `kid` is an outage, not evidence of a forgery.
    func testAStaleSetWithoutTheKidIsRecoverableNotASignatureRejection() async throws {
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", headers: ["Cache-Control": "max-age=300"], body: JoseTestTokens.jwks(ec))
        await stub.enqueueFailure("/jwks.json")
        let time = ManualClock()
        let client = JwksClient(httpClient: stub, clock: time.clock)
        let uri = self.uri
        let verifier = JwsVerifier(jwksUri: { uri }, allowedAlgorithms: { [] }, jwks: client)
        _ = try await client.keys(uri: uri, forceRefresh: false)
        time.advance(301)
        let token = JoseTestTokens.rsa("RS256", payload: JoseTestTokens.json(["sub": "alice"]), kid: "rsa")

        let error = await joseThrown { _ = try await staleAllowed { try await verifier.verify(token) } }

        guard case .recoverable? = error as? OAuthError else { return XCTFail("\(String(describing: error))") }
    }

    func testAKeySetOnDiskOlderThanItsLifetimeIsNotUsedByAColdClient() async throws {
        let time = ManualClock()
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(ec))
        let stale = AgedKeys(JsonWebKeySet(keys: [rsa]), at: time.clock.now() - 3 * 3600, lifetime: 3600)

        let loaded = try await JwksClient(httpClient: stub, cache: stale, clock: time.clock).keys(uri: uri, forceRefresh: false)

        XCTAssertTrue(loaded.fetched)
        XCTAssertEqual(loaded.keys.keys.map(\.kid), ["ec"])
    }

    func testAKeySetOnDiskInsideItsLifetimeIsUsedByAColdClient() async throws {
        let time = ManualClock()
        let stub = JoseStubHTTP()
        let fresh = AgedKeys(JsonWebKeySet(keys: [rsa]), at: time.clock.now() - 1800, lifetime: 3600)

        let loaded = try await JwksClient(httpClient: stub, cache: fresh, clock: time.clock).keys(uri: uri, forceRefresh: false)

        XCTAssertFalse(loaded.fetched)
        let count = await stub.requestCount()
        XCTAssertEqual(count, 0)
    }

    func testAnUnknownKidStillCostsOneRefetchAfterTheExpiryWork() async throws {
        // The rotation path is unchanged: a fresh set that lacks the `kid` is refetched once.
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(rsa))
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(rsa, ec))
        let client = JwksClient(httpClient: stub, clock: ManualClock().clock)
        _ = try await client.keys(uri: uri, forceRefresh: false)

        let forced = try await client.keys(uri: uri, forceRefresh: true)

        XCTAssertTrue(forced.fetched)
        XCTAssertEqual(forced.keys.keys.map(\.kid), ["rsa", "ec"])
    }
}

/// Runs `body` as the check of a refresh's ID token does: a key set past its lifetime is allowed.
private func staleAllowed<T: Sendable>(_ body: @Sendable () async throws -> T) async rethrows -> T {
    try await JwksStaleness.$allowed.withValue(true) { try await body() }
}
