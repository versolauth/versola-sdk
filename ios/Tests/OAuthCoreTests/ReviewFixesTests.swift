import Foundation
import XCTest
@testable import OAuthCore

/// The behaviours the review of the first iOS commit asked for, each pinned here: the
/// discovery cache's age, the reserved authorization parameters, and the JWKS refetch rule.
final class ReviewFixesTests: XCTestCase {
    private static let issuer = "https://id.example.com"
    private static let document = ProviderMetadata(issuer: issuer, authorizationEndpoint: "\(issuer)/authorize", tokenEndpoint: "\(issuer)/token")
    private static let rotated = ProviderMetadata(issuer: issuer, authorizationEndpoint: "\(issuer)/authorize", tokenEndpoint: "\(issuer)/token2")

    /// A cache whose save time the test chooses.
    actor AgedCache: ProviderMetadataCache {
        var stored: ProviderMetadata?
        var at: Date?
        var life: TimeInterval?
        var saves = 0
        init(_ stored: ProviderMetadata?, at: Date?, lifetime: TimeInterval? = nil) {
            self.stored = stored
            self.at = at
            self.life = lifetime
        }
        func load() async throws -> ProviderMetadata? { stored }
        func save(_ metadata: ProviderMetadata) async throws {
            try await save(metadata, lifetime: nil)
        }
        func save(_ metadata: ProviderMetadata, lifetime: TimeInterval?) async throws {
            stored = metadata
            life = lifetime
            saves += 1
        }
        func savedAt() async throws -> Date? { at }
        func lifetime() async throws -> TimeInterval? { life }
    }

    actor CountingDiscovery: DiscoveryClient {
        var fetches = 0
        let answer: Result<ProviderMetadata, OAuthError>
        init(_ answer: Result<ProviderMetadata, OAuthError>) { self.answer = answer }
        func fetch(issuer: String) async throws -> ProviderMetadata {
            fetches += 1
            return try answer.get()
        }
    }

    private static let now = Date(timeIntervalSince1970: 1_700_000_000)
    private var now: Date { Self.now }

    func testAFreshCachedDocumentIsServedWithoutANetworkRequest() async throws {
        let client = CountingDiscovery(.success(Self.rotated))
        let service = DiscoveryService(issuer: Self.issuer, client: client, cache: AgedCache(Self.document, at: now.addingTimeInterval(-3600)), clock: Clock(now: { Self.now }))
        let served = try await service.metadata()
        XCTAssertEqual(served, Self.document)
        let fetches = await client.fetches
        XCTAssertEqual(fetches, 0)
    }

    func testADocumentOlderThanADayIsRefetchedAndTheNewOneCached() async throws {
        let client = CountingDiscovery(.success(Self.rotated))
        let cache = AgedCache(Self.document, at: now.addingTimeInterval(-25 * 3600))
        let service = DiscoveryService(issuer: Self.issuer, client: client, cache: cache, clock: Clock(now: { Self.now }))
        let served = try await service.metadata()
        XCTAssertEqual(served, Self.rotated)
        let fetches = await client.fetches
        XCTAssertEqual(fetches, 1)
        let saves = await cache.saves
        XCTAssertEqual(saves, 1)
    }

    func testAStaleDocumentWhoseRefetchFailsIsStillServed() async throws {
        let client = CountingDiscovery(.failure(.recoverable(.network(detail: "down", attempts: 1, elapsedMillis: 0))))
        let service = DiscoveryService(issuer: Self.issuer, client: client, cache: AgedCache(Self.document, at: nil), clock: Clock(now: { Self.now }))
        let served = try await service.metadata()
        XCTAssertEqual(served, Self.document)
        let fetches = await client.fetches
        XCTAssertEqual(fetches, 1)
    }

    // MARK: - Expiry of the document held in memory, and the provider's own lifetime

    func testADocumentHeldInMemoryIsFetchedAgainAfterADay() async throws {
        let client = CountingDiscovery(.success(Self.rotated))
        let time = ManualClock()
        let cache = AgedCache(Self.document, at: time.clock.now())
        let service = DiscoveryService(issuer: Self.issuer, client: client, cache: cache, clock: time.clock)

        let first = try await service.metadata()
        time.advance(24 * 3600 - 1)
        let within = try await service.metadata()
        time.advance(2)
        let after = try await service.metadata()

        XCTAssertEqual(first, Self.document)
        XCTAssertEqual(within, Self.document)
        XCTAssertEqual(after, Self.rotated, "a rotated token_endpoint is reachable without restarting the app")
        let fetches = await client.fetches
        XCTAssertEqual(fetches, 1)
    }

    func testAnExpiredDocumentWhoseRefetchFailsKeepsServingTheOldOneAndTriesAgainAfterAMinute() async throws {
        let client = CountingDiscovery(.failure(.recoverable(.network(detail: "down", attempts: 1, elapsedMillis: 0))))
        let time = ManualClock()
        let service = DiscoveryService(issuer: Self.issuer, client: client, cache: AgedCache(Self.document, at: time.clock.now()), clock: time.clock)
        _ = try await service.metadata()
        time.advance(25 * 3600)

        let first = try await service.metadata()
        let second = try await service.metadata()
        let duringTheOutage = await client.fetches
        time.advance(DiscoveryService.staleRetryInterval + 1)
        let third = try await service.metadata()

        XCTAssertEqual(first, Self.document)
        XCTAssertEqual(second, Self.document)
        XCTAssertEqual(third, Self.document)
        XCTAssertEqual(duringTheOutage, 1, "an outage costs one attempt a minute, not a retry budget per call")
        let fetches = await client.fetches
        XCTAssertEqual(fetches, 2)
    }

    func testTheProvidersMaxAgeShortensWhatIsTrusted() async throws {
        let time = ManualClock()
        let http = RecordingHTTP { _ in HTTPResponse(statusCode: 200, headers: ["Cache-Control": "max-age=900"], body: Data(#"{"issuer":"\#(Self.issuer)","authorization_endpoint":"\#(Self.issuer)/authorize","token_endpoint":"\#(Self.issuer)/token"}"#.utf8)) }
        let cache = AgedCache(nil, at: nil)
        let service = DiscoveryService(issuer: Self.issuer, client: HTTPDiscoveryClient(httpClient: http), cache: cache, clock: time.clock)

        _ = try await service.metadata()
        time.advance(899)
        _ = try await service.metadata()
        let within = await http.requests.count
        time.advance(2)
        _ = try await service.metadata()
        let after = await http.requests.count

        XCTAssertEqual(within, 1)
        XCTAssertEqual(after, 2)
        let lifetime = try await cache.lifetime()
        XCTAssertEqual(lifetime, 900, "the lifetime is persisted with the document, so a restart honours it")
    }

    func testADocumentOnDiskOlderThanItsOwnLifetimeIsRefetchedEvenInsideADay() async throws {
        let client = CountingDiscovery(.success(Self.rotated))
        let time = ManualClock()
        let cache = AgedCache(Self.document, at: time.clock.now() - 7200, lifetime: 900)
        let service = DiscoveryService(issuer: Self.issuer, client: client, cache: cache, clock: time.clock)

        let served = try await service.metadata()

        XCTAssertEqual(served, Self.rotated)
    }

    func testTheParametersTheSDKKeepsUnrepresentableAreRefused() {
        for name in ["client_secret", "request", "response_mode", "dpop_jkt", "state"] {
            XCTAssertThrowsError(try AuthorizationParameters(extra: [name: "x"]), name) { error in
                guard case .configuration(.invalidConfiguration) = error as? OAuthError else { return XCTFail("\(error)") }
            }
        }
        XCTAssertNoThrow(try AuthorizationParameters(extra: ["audience": "https://api.example.com"]))
    }
}
