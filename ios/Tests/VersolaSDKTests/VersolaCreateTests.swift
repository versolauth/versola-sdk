import Foundation
import XCTest
@testable import OAuthClient
@testable import OAuthCore
@testable import VersolaEdge
@testable import VersolaSDK

/// `Versola.create` (`spec/versola-sdk-api.md` section 4): one instance per storage key, no network and
/// no key generation, and what a restore finds.
final class VersolaCreateTests: XCTestCase {
    override func setUp() async throws {
        await Versola.forgetAll()
    }

    override func tearDown() async throws {
        await Versola.forgetAll()
    }

    func testCreateDoesNoNetworkIoAndGeneratesNoKey() async throws {
        let world = World()

        let client = try await world.create()

        let requests = await world.edge.requests
        XCTAssertEqual(requests.count, 0, "no discovery, no start")
        XCTAssertTrue(world.keys.isEmpty, "the DPoP key is generated at the first sign-in")
        let state = await client.sessionState
        XCTAssertEqual(state, .unauthenticated)
        let claims = await client.claims
        XCTAssertNil(claims)
        let requestsAfter = await world.edge.requests
        XCTAssertEqual(requestsAfter.count, 0, "reading the state is not a request either")
    }

    func testASecondCreateWithTheSameConfigurationReturnsTheFirstInstance() async throws {
        let world = World()
        let first = try await world.create()
        let second = try await world.create()
        XCTAssertTrue(first === second)
    }

    func testASecondCreateWithADifferentConfigurationForTheSameStorageIsRefused() async throws {
        let world = World()
        _ = try await world.create()

        let error = await thrown { _ = try await world.create(try world.configuration(redirect: "https://other.example.com/callback")) }

        guard case .configuration(.invalidConfiguration(let detail))? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(detail.contains("different configuration"), detail)
        XCTAssertFalse(detail.contains("other.example.com"), "values stay out of the message")
    }

    func testASecondCreateWithAnotherUrlSessionOrLoggerIsRefused() async throws {
        let world = World()
        _ = try await world.create()
        let otherSession = URLSession(configuration: .ephemeral)
        let other = try VersolaConfiguration(
            edgeUrl: Sdk.edgeUrl, clientId: world.clientId, redirectUri: Sdk.redirect, postLogoutRedirectUri: Sdk.postLogout,
            logger: world.logger, urlSession: otherSession
        )

        let error = await thrown { _ = try await world.create(other) }

        guard case .configuration(.invalidConfiguration(let detail))? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(detail.contains("urlSession or logger"), detail)
    }

    func testClientsOfAnotherClientIdOrEdgeAreDistinctInstances() async throws {
        let world = World()
        let first = try await world.create()
        let otherClient = try await world.create(try world.configuration(clientId: world.clientId + "-b"))
        let otherEdge = try await world.create(try world.configuration(edgeUrl: "https://id2.example.com", issuer: "https://id.example.com"))
        XCTAssertFalse(first === otherClient)
        XCTAssertFalse(first === otherEdge)
        XCTAssertFalse(otherClient === otherEdge)
    }

    func testConcurrentCreatesOfOneConfigurationAllGetTheSameInstance() async throws {
        let world = World()
        let clients = try await withThrowingTaskGroup(of: Versola.self) { group in
            for _ in 0..<20 { group.addTask { try await world.create() } }
            var all: [Versola] = []
            for try await client in group { all.append(client) }
            return all
        }
        XCTAssertEqual(Set(clients.map(ObjectIdentifier.init)).count, 1)
    }

    // MARK: restore

    private func edgePending(createdAt: Date, lifetime: TimeInterval, state: String = "edge-state-cold", nonce: String = "cold-nonce") -> PendingAuthorizationRequest {
        PendingAuthorizationRequest(
            state: state, nonce: nonce, codeVerifier: "", scopes: ["openid", "offline_access"], redirectUri: Sdk.redirect, createdAt: createdAt,
            issRequired: true,
            extensions: [
                EdgeExtension.blob: "v1.kz-1.blob-cold", EdgeExtension.tokenEndpoint: Sdk.tokenEndpoint, EdgeExtension.revocationEndpoint: Sdk.revocationEndpoint,
            ],
            lifetime: lifetime
        )
    }

    func testAPendingRequestYoungerThanItsOwnLifetimeIsRestoredAsAuthorizing() async throws {
        let world = World()
        let store = InMemoryPendingAuthorizationStore()
        try await store.save(edgePending(createdAt: Sdk.now.addingTimeInterval(-30), lifetime: 60))
        let cold = ColdBrowser(.userCancelled)

        let client = try await world.create(browser: cold, pending: store)

        let state = await client.sessionState
        XCTAssertEqual(state, .authorizing)
    }

    func testAPendingRequestOlderThanItsOwnLifetimeIsDiscardedThoughTenMinutesHaveNotPassed() async throws {
        let world = World()
        let store = InMemoryPendingAuthorizationStore()
        try await store.save(edgePending(createdAt: Sdk.now.addingTimeInterval(-61), lifetime: 60))

        let client = try await world.create(browser: ColdBrowser(.userCancelled), pending: store)

        let state = await client.sessionState
        let remaining = try await store.load()
        XCTAssertEqual(state, .unauthenticated)
        XCTAssertNil(remaining)
    }

    func testAColdStartedRedirectIsRedeemedThroughEdgeAndSignsIn() async throws {
        let world = World()
        await world.edge.setForcedNonce("cold-nonce")
        let store = InMemoryPendingAuthorizationStore()
        try await store.save(edgePending(createdAt: Sdk.now.addingTimeInterval(-5), lifetime: 90))
        let redirect = URL(string: "\(Sdk.redirect)?code=cold-code&state=edge-state-cold&iss=\(Sdk.issuer)")!
        let cold = ColdBrowser(.redirect(redirect))
        let client = try await world.create(browser: cold, pending: store)

        let states = StateRecorder()
        await states.start(await client.sessionStates())
        cold.release()
        await waitUntil("the resumed sign-in authenticates") { await client.sessionState == .authenticated }
        await states.stop()

        let completes = await world.edge.completes
        XCTAssertEqual(completes.count, 1)
        XCTAssertEqual(completes.first?.map(\.0), ["code", "state", "iss", "blob"])
        XCTAssertEqual(completes.first?.last?.1, "v1.kz-1.blob-cold", "the blob that was persisted before the process died")
        let claims = await client.claims
        XCTAssertEqual(claims?.subject, "alice")
        let remembered = await world.scopes.load()
        XCTAssertTrue(remembered.contains("openid"))
        let saved = try await world.endpoints.load()
        XCTAssertEqual(saved?.tokenEndpoint, Sdk.tokenEndpoint)
    }
}
