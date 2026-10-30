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
            // A 503 is the provider being busy (`server`); the rest were never classified and stay
            // a failure to read the keys (`network`). Neither is a key.
            switch error as? OAuthError {
            case .recoverable(.server(let seen, _, _, _))? where status == 503: XCTAssertEqual(seen, 503)
            case .recoverable(.network)? where status != 503: break
            default: XCTFail("status \(status): \(String(describing: error))")
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
}
