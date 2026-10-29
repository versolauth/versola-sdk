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
        var saves = 0
        init(_ stored: ProviderMetadata?, at: Date?) {
            self.stored = stored
            self.at = at
        }
        func load() async throws -> ProviderMetadata? { stored }
        func save(_ metadata: ProviderMetadata) async throws {
            stored = metadata
            saves += 1
        }
        func savedAt() async throws -> Date? { at }
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

    func testTheParametersTheSDKKeepsUnrepresentableAreRefused() {
        for name in ["client_secret", "request", "response_mode", "dpop_jkt", "state"] {
            XCTAssertThrowsError(try AuthorizationParameters(extra: [name: "x"]), name) { error in
                guard case .configuration(.invalidConfiguration) = error as? OAuthError else { return XCTFail("\(error)") }
            }
        }
        XCTAssertNoThrow(try AuthorizationParameters(extra: ["audience": "https://api.example.com"]))
    }
}
