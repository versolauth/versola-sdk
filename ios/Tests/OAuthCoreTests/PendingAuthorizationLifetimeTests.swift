import Foundation
import os
import XCTest
@testable import OAuthCore

/// The lifetime a starter gives a pending request (`spec/versola-sdk-api.md` section 5, "Lifetime";
/// the Android `PendingAuthorizationLifetimeTest`'s twin): shorter than ten minutes, persisted with
/// the request so that a cold start honours it, never longer than ten minutes, and the wait that
/// outlives it ends as `recoverable(.pendingRequestExpired)`.
final class PendingAuthorizationLifetimeTests: XCTestCase {
    private let created = AuthzKit.now

    private func request(lifetime: TimeInterval? = nil, extensions: [String: String] = [:]) -> PendingAuthorizationRequest {
        guard let lifetime else {
            return PendingAuthorizationRequest(
                state: "s", nonce: "n", codeVerifier: "v", scopes: ["openid"], redirectUri: AuthzKit.redirect,
                createdAt: created, extensions: extensions
            )
        }
        return PendingAuthorizationRequest(
            state: "s", nonce: "n", codeVerifier: "v", scopes: ["openid"], redirectUri: AuthzKit.redirect,
            createdAt: created, extensions: extensions, lifetime: lifetime
        )
    }

    // MARK: the rule

    func testRequestWithoutALifetimeOfItsOwnLivesTenMinutes() {
        let pending = request()
        XCTAssertEqual(pending.lifetime, PendingAuthorizationRequest.maxAge)
        XCTAssertFalse(pending.isExpired(at: created.addingTimeInterval(599)))
        XCTAssertFalse(pending.isExpired(at: created.addingTimeInterval(600)))
        XCTAssertTrue(pending.isExpired(at: created.addingTimeInterval(601)))
    }

    func testShorterLifetimeExpiresTheRequestAtThatAgeAndNotAtTenMinutes() {
        let pending = request(lifetime: 30)
        XCTAssertFalse(pending.isExpired(at: created.addingTimeInterval(29)))
        XCTAssertTrue(pending.isExpired(at: created.addingTimeInterval(31)))
        XCTAssertTrue(pending.isExpired(at: created.addingTimeInterval(300)))
    }

    func testRemainingTimeCountsDownFromTheShorterLifetimeAndStopsAtZero() {
        let pending = request(lifetime: 30)
        XCTAssertEqual(pending.remaining(at: created), 30)
        XCTAssertEqual(pending.remaining(at: created.addingTimeInterval(10)), 20)
        XCTAssertEqual(pending.remaining(at: created.addingTimeInterval(45)), 0)
        // A clock stepped back never reports more than the lifetime.
        XCTAssertEqual(pending.remaining(at: created.addingTimeInterval(-100)), 30)
    }

    func testLifetimeBeyondTenMinutesIsCappedAtTenMinutes() {
        let pending = request(lifetime: 3600)
        XCTAssertEqual(pending.lifetime, 600)
        XCTAssertTrue(pending.isExpired(at: created.addingTimeInterval(601)))
        XCTAssertEqual(pending.remaining(at: created), 600)
    }

    func testNegativeOrNonFiniteLifetimeIsAnExpiredRequestAndNotALongLivedOne() {
        for lifetime in [-5, Double.nan, Double.infinity, -Double.infinity] {
            let pending = request(lifetime: lifetime)
            XCTAssertEqual(pending.lifetime, 0, "\(lifetime)")
            XCTAssertTrue(pending.isExpired(at: created.addingTimeInterval(1)), "\(lifetime)")
        }
    }

    // MARK: the codec

    func testLifetimeSurvivesTheCodecBesideAStartersExtensions() throws {
        let pending = request(lifetime: 42, extensions: ["blob": "v1.kz-1.aB-c_D.e~f", "token_endpoint": "https://auth.example.com/token"])
        let decoded = try JSONDecoder().decode(PendingAuthorizationRequest.self, from: JSONEncoder().encode(pending))
        XCTAssertEqual(decoded, pending)
        XCTAssertEqual(decoded.lifetime, 42)
        XCTAssertEqual(decoded.extensions["blob"], "v1.kz-1.aB-c_D.e~f")
    }

    func testRecordWrittenWithoutALifetimeDecodesAsTenMinutes() throws {
        let encoded = try JSONEncoder().encode(request(lifetime: 42))
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        XCTAssertNotNil(object.removeValue(forKey: "lifetime"), "the lifetime is a member of the record")
        let legacy = try JSONSerialization.data(withJSONObject: object)

        let decoded = try JSONDecoder().decode(PendingAuthorizationRequest.self, from: legacy)

        XCTAssertEqual(decoded.lifetime, 600)
        XCTAssertFalse(decoded.isExpired(at: created.addingTimeInterval(599)))
    }

    func testDecodedRecordClaimingMoreThanTenMinutesIsStillCapped() throws {
        let encoded = try JSONEncoder().encode(request(lifetime: 42))
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        object["lifetime"] = 86_400
        let tampered = try JSONSerialization.data(withJSONObject: object)

        let decoded = try JSONDecoder().decode(PendingAuthorizationRequest.self, from: tampered)

        XCTAssertEqual(decoded.lifetime, 600)
    }

    // MARK: the flow

    /// A starter that gives the request the lifetime its back channel named, as the edge starter does.
    private struct ShortLivedStarter: AuthorizationStarter {
        let lifetime: TimeInterval
        func start(request: AuthorizationRequest, metadata: ProviderMetadata, now: Date) async throws -> StartedAuthorization {
            let base = request.toPending(createdAt: now, issRequired: true)
            let pending = PendingAuthorizationRequest(
                state: base.state, nonce: base.nonce, codeVerifier: base.codeVerifier, scopes: base.scopes,
                redirectUri: base.redirectUri, createdAt: now, issRequired: true, lifetime: lifetime
            )
            return StartedAuthorization(pending: pending, browserUri: URL(string: "https://id.example.com/authorize?state=\(pending.state)")!)
        }
    }

    /// A clock fixed `offset` seconds after the request was created.
    private func clock(at offset: TimeInterval) -> Clock {
        let instant = created.addingTimeInterval(offset)
        return Clock(now: { instant })
    }

    private func ticking(creation: Date, later: Date) -> Clock {
        let calls = OSAllocatedUnfairLock(initialState: 0)
        return Clock(now: { calls.withLock { n in defer { n += 1 }; return n == 0 ? creation : later } })
    }

    private func flow(
        store: MemoryPendingStore, browser: BrowserAuthorizationSession, clock: Clock, starter: AuthorizationStarter? = nil
    ) -> (AuthorizationFlow, SessionStateHub) {
        let hub = SessionStateHub()
        let discovery = DiscoveryService(issuer: AuthzKit.issuer, client: StaticDiscoveryClient(metadata: AuthzKit.metadata()), cache: MemoryMetadataCache())
        let flow = AuthorizationFlow(
            configuration: AuthzKit.configuration, discovery: discovery, pendingStore: store, browser: browser, states: hub,
            clock: clock, starter: starter
        )
        return (flow, hub)
    }

    func testLoginWhoseSheetOutlivesAShorterLifetimeEndsAsPendingRequestExpiredAtThatLifetime() async {
        // 29.95 s into a 30 s lifetime: with the ten-minute default the wait would be 570 s and this test would hang.
        let sleeping = ScriptedBrowser(onAuthorize: { _, _ in
            try await Task.sleep(nanoseconds: 3_600_000_000_000)
            throw CancellationError()
        })
        let store = MemoryPendingStore()
        let (flow, hub) = flow(
            store: store, browser: sleeping, clock: ticking(creation: created, later: created.addingTimeInterval(29.95)),
            starter: ShortLivedStarter(lifetime: 30)
        )

        do {
            _ = try await flow.authorize(scopes: ["openid"])
            XCTFail("a login with no redirect completed")
        } catch {
            XCTAssertEqual(error as? OAuthError, .recoverable(.pendingRequestExpired))
        }
        let stored = await store.stored
        let state = await hub.current
        XCTAssertNil(stored)
        XCTAssertEqual(state, .unauthenticated)
    }

    func testColdStartRestoreDiscardsARequestOlderThanItsOwnLifetimeWhileTenMinutesHaveNotPassed() async throws {
        let store = MemoryPendingStore(PendingAuthorizationRequest(
            state: "s", nonce: "n", codeVerifier: "v", scopes: ["openid"], redirectUri: AuthzKit.redirect,
            createdAt: created, lifetime: 60
        ))
        let (flow, hub) = flow(store: store, browser: ScriptedBrowser.answering(), clock: clock(at: 100))

        try await flow.ensureRestored()

        let state = await hub.current
        let stored = await store.stored
        XCTAssertEqual(state, .unauthenticated)
        XCTAssertNil(stored)
        do {
            _ = try await flow.resumePendingAuthorization()
            XCTFail("the expiry is reported once")
        } catch {
            XCTAssertEqual(error as? OAuthError, .recoverable(.pendingRequestExpired))
        }
    }

    func testColdStartRestoreKeepsARequestInsideItsOwnLifetime() async throws {
        let store = MemoryPendingStore(PendingAuthorizationRequest(
            state: "s", nonce: "n", codeVerifier: "v", scopes: ["openid"], redirectUri: AuthzKit.redirect,
            createdAt: created, lifetime: 60
        ))
        let (flow, hub) = flow(store: store, browser: ScriptedBrowser.answering(), clock: clock(at: 59))

        try await flow.ensureRestored()

        let state = await hub.current
        XCTAssertEqual(state, .authorizing)
    }

    func testResumeWaitsOnlyForWhatIsLeftOfTheRequestsOwnLifetime() async {
        let store = MemoryPendingStore(PendingAuthorizationRequest(
            state: "s", nonce: "n", codeVerifier: "v", scopes: ["openid"], redirectUri: AuthzKit.redirect,
            createdAt: created, lifetime: 60
        ))
        // 59.95 s old: 0.05 s left of the 60, where the ten-minute default would wait 540 s more.
        let sleeping = ScriptedBrowser(onAuthorize: { _, _ in throw CancellationError() }, onAwait: { _ in
            try await Task.sleep(nanoseconds: 3_600_000_000_000)
            throw CancellationError()
        })
        let (flow, _) = self.flow(store: store, browser: sleeping, clock: clock(at: 59.95))

        do {
            _ = try await flow.resumePendingAuthorization()
            XCTFail("a resume with no redirect completed")
        } catch {
            XCTAssertEqual(error as? OAuthError, .recoverable(.pendingRequestExpired))
        }
        let stored = await store.stored
        XCTAssertNil(stored)
    }
}
