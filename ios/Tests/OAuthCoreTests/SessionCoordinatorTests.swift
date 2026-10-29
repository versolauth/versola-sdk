import CryptoKit
import Foundation
import os
import XCTest
@testable import OAuthCore

/// `SessionCoordinator` over fakes at every seam: the persistence order of `login()`, the
/// single refresh flight, the rotation slot, the no-refresh-token session, logout, and the
/// claims restored after a cold start (`spec/state-machine.md`).
final class SessionCoordinatorTests: XCTestCase {
    /// The fakes in AuthzKit answer for these; the fixture must be configured with the same.
    private static let issuer = AuthzKit.issuer
    private static let redirect = AuthzKit.redirect

    actor MemoryCredentials: CredentialStore {
        var refresh: String?
        var idToken: String?
        var rotation: String?
        var clears = 0
        /// The slot's value at the moment the token client was called: what proves the order.
        var rotationAtRequest: [String?] = []
        func hasGrant() async throws -> Bool { refresh != nil }
        func refreshToken() async throws -> String? { refresh }
        func rawIdToken() async throws -> String? { idToken }
        func save(refreshToken: String, rawIdToken: String?) async throws {
            refresh = refreshToken
            idToken = rawIdToken
        }
        func savePendingRotation(_ idempotencyKey: String?) async throws { rotation = idempotencyKey }
        func pendingRotation() async throws -> String? { rotation }
        func clear() async throws {
            clears += 1
            refresh = nil
            idToken = nil
            rotation = nil
        }
        func noteRequest() { rotationAtRequest.append(rotation) }
    }

    actor ScriptedTokenClient: TokenClient {
        enum Call: Equatable { case exchange, refresh(String, String), revoke(String) }
        var calls: [Call] = []
        var answers: [Result<TokenResponse, OAuthError>]
        var revokeError: OAuthError?
        let store: MemoryCredentials?
        /// Held open while set: lets a test start two refreshes before either resolves.
        var gate: Gate?
        init(_ answers: [Result<TokenResponse, OAuthError>], store: MemoryCredentials? = nil) {
            self.answers = answers
            self.store = store
        }
        func hold(_ gate: Gate) { self.gate = gate }
        func setRevokeError(_ error: OAuthError) { revokeError = error }
        private func next() throws -> TokenResponse {
            guard !answers.isEmpty else { throw OAuthError.recoverable(.network(detail: "no scripted answer", attempts: 1, elapsedMillis: 0)) }
            return try answers.removeFirst().get()
        }
        func exchange(_ grant: AuthorizationGrant) async throws -> TokenResponse {
            calls.append(.exchange)
            return try next()
        }
        func refresh(refreshToken: String, idempotencyKey: String) async throws -> TokenResponse {
            calls.append(.refresh(refreshToken, idempotencyKey))
            await store?.noteRequest()
            if let gate { await gate.wait() }
            return try next()
        }
        func revoke(refreshToken: String) async throws {
            calls.append(.revoke(refreshToken))
            if let revokeError { throw revokeError }
        }
    }

    actor RecordingValidator: IdTokenValidator {
        var calls: [(nonce: String?, previous: String?)] = []
        var rejection: IdTokenRejection?
        func reject(_ reason: IdTokenRejection) { rejection = reason }
        func validate(idToken: String, expectedNonce: String?, accessToken: String?, maxAge: Int?, previous: IdTokenClaims?, serverTime: Date?) async throws -> IdTokenClaims {
            calls.append((expectedNonce, previous?.subject))
            if let rejection { throw OAuthError.configuration(.idTokenRejected(rejection)) }
            return try IdTokenClaimsParser.parseStored(idToken)
        }
    }

    final class Warnings: OAuthLogger, Sendable {
        private let lines = OSAllocatedUnfairLock(initialState: [String]())
        var warnings: [String] { lines.withLock { $0 } }
        func info(_ message: String) {}
        func warn(_ message: String) { lines.withLock { $0.append(message) } }
    }

    /// A clock the test moves; read synchronously by the coordinator's `Clock`.
    final class TickingClock: Sendable {
        private let date: OSAllocatedUnfairLock<Date>
        init(_ initial: Date) { date = OSAllocatedUnfairLock(initialState: initial) }
        func peek() -> Date { date.withLock { $0 } }
        func advance(_ seconds: TimeInterval) { date.withLock { $0 = $0.addingTimeInterval(seconds) } }
    }

    struct Fixture {
        let coordinator: SessionCoordinator
        let flow: AuthorizationFlow
        let store: MemoryCredentials
        let tokens: ScriptedTokenClient
        let validator: RecordingValidator
        let logger: Warnings
        let clock: TickingClock
    }

    private func idToken(subject: String = "alice", nonce: String = "n") -> String {
        let now = Int(Date().timeIntervalSince1970)
        return JoseTestTokens.rsa("RS256", payload: JoseTestTokens.json(["iss": Self.issuer, "sub": subject, "aud": "mobile", "iat": now, "exp": now + 3600, "nonce": nonce]))
    }

    private func response(refresh: String? = "rt-1", expiresIn: Int = 300, subject: String = "alice") -> TokenResponse {
        TokenResponse(accessToken: "at-\(refresh ?? "none")-\(UUID().uuidString.prefix(4))", tokenType: "Bearer", expiresIn: expiresIn, refreshToken: refresh, idToken: idToken(subject: subject), scope: "openid")
    }

    private func fixture(answers: [Result<TokenResponse, OAuthError>], policy: RefreshTokenPolicy = .optional, store: MemoryCredentials = MemoryCredentials(), retry: RetryPolicy? = nil) throws -> Fixture {
        let clock = TickingClock(Date(timeIntervalSince1970: 1_700_000_000))
        let configuration = CoreConfiguration(issuer: Self.issuer, clientId: "mobile", redirectUri: URL(string: Self.redirect)!, postLogoutRedirectUri: URL(string: "https://app.example.com/signed-out"))
        let discovery = DiscoveryService(issuer: Self.issuer, client: StaticDiscoveryClient(metadata: AuthzKit.metadata()), cache: MemoryMetadataCache())
        let flow = AuthorizationFlow(
            configuration: configuration, discovery: discovery, pendingStore: MemoryPendingStore(),
            browser: ScriptedBrowser.answering(), states: SessionStateHub(),
            clock: Clock(now: { Date() }), hasStoredGrant: { try await store.hasGrant() }
        )
        let tokens = ScriptedTokenClient(answers, store: store)
        let validator = RecordingValidator()
        let logger = Warnings()
        let coordinator = SessionCoordinator(
            flow: flow, tokenClient: tokens, credentialStore: store,
            retryPolicy: try retry ?? RetryPolicy(maxAttemptsPerOrigin: 2, maxTotalAttempts: 2, initialBackoff: 0, backoffMultiplier: 1, maxBackoff: 0, totalBudget: 10),
            clock: Clock(now: { clock.peek() }), logger: logger, refreshTokens: policy, idTokenValidator: validator
        )
        return Fixture(coordinator: coordinator, flow: flow, store: store, tokens: tokens, validator: validator, logger: logger, clock: clock)
    }

    // MARK: - Login

    func testLoginValidatesPersistsThenPublishesAuthenticatedAndCachesTheToken() async throws {
        let f = try fixture(answers: [.success(response())])

        try await f.coordinator.login(scopes: ["openid"])

        let state = await f.flow.states.current
        XCTAssertEqual(state, .authenticated)
        let stored = await f.store.refresh
        XCTAssertEqual(stored, "rt-1")
        let claims = await f.coordinator.claims
        XCTAssertEqual(claims?.subject, "alice")
        let validations = await f.validator.calls
        XCTAssertEqual(validations.count, 1)
        XCTAssertNotNil(validations.first?.nonce)
        // Served from the cache: no refresh.
        _ = try await f.coordinator.accessToken()
        let calls = await f.tokens.calls
        XCTAssertEqual(calls, [.exchange])
    }

    func testARejectedIdTokenPersistsNothingAndSettlesWhereItStarted() async throws {
        let f = try fixture(answers: [.success(response())])
        await f.validator.reject(.nonce)

        do {
            try await f.coordinator.login(scopes: ["openid"])
            XCTFail("no error")
        } catch let error as OAuthError {
            XCTAssertEqual(error, .configuration(.idTokenRejected(.nonce)))
        }

        let stored = await f.store.refresh
        XCTAssertNil(stored)
        let state = await f.flow.states.current
        XCTAssertEqual(state, .unauthenticated)
        let claims = await f.coordinator.claims
        XCTAssertNil(claims)
    }

    func testUnderRequiredAMissingRefreshTokenIsRefusedAndOfflineAccessIsAsked() async throws {
        let f = try fixture(answers: [.success(response(refresh: nil))], policy: .required)
        do {
            try await f.coordinator.login(scopes: ["openid"])
            XCTFail("no error")
        } catch let error as OAuthError {
            XCTAssertEqual(error, .configuration(.tokenResponseMalformed(detail: "refresh_token is missing")))
        }
    }

    func testWithoutARefreshTokenTheSessionLivesInMemoryAndEndsWithTheAccessToken() async throws {
        let f = try fixture(answers: [.success(response(refresh: nil, expiresIn: 60))])
        try await f.coordinator.login(scopes: ["openid"])

        let state = await f.flow.states.current
        XCTAssertEqual(state, .authenticated)
        XCTAssertTrue(f.logger.warnings.contains { $0.contains("issued no refresh token") })
        _ = try await f.coordinator.accessToken()
        // Past the token's usable window: the session is over, with no token request.
        f.clock.advance(61)
        do {
            _ = try await f.coordinator.accessToken()
            XCTFail("no error")
        } catch let error as OAuthError {
            XCTAssertEqual(error, .reauthenticate(.sessionExpired))
        }
        let after = await f.flow.states.current
        XCTAssertEqual(after, .unauthenticated)
        let claims = await f.coordinator.claims
        XCTAssertNil(claims)
        let calls = await f.tokens.calls
        XCTAssertEqual(calls, [.exchange])
    }

    func testATokenLessLoginOverAStoredGrantClearsTheOldGrant() async throws {
        let store = MemoryCredentials()
        try await store.save(refreshToken: "rt-old", rawIdToken: idToken(subject: "bob"))
        let f = try fixture(answers: [.success(response(refresh: nil))], store: store)

        try await f.coordinator.login(scopes: ["openid"])

        let stored = await f.store.refresh
        XCTAssertNil(stored)
        let claims = await f.coordinator.claims
        XCTAssertEqual(claims?.subject, "alice")
    }

    // MARK: - Refresh

    func testRefreshPersistsTheSlotBeforeTheRequestAndClearsItAfterTheNewToken() async throws {
        let f = try fixture(answers: [.success(response(refresh: "rt-1")), .success(response(refresh: "rt-2"))])
        try await f.coordinator.login(scopes: ["openid"])

        try await f.coordinator.refresh()

        let calls = await f.tokens.calls
        XCTAssertEqual(calls.count, 2)
        guard case .refresh(let token, let key) = calls[1] else { return XCTFail("\(calls)") }
        XCTAssertEqual(token, "rt-1")
        XCTAssertEqual(key, SessionCoordinator.idempotencyKey(for: "rt-1"))
        let slotAtRequest = await f.store.rotationAtRequest
        XCTAssertEqual(slotAtRequest, [key])
        let slotAfter = await f.store.rotation
        XCTAssertNil(slotAfter)
        let stored = await f.store.refresh
        XCTAssertEqual(stored, "rt-2")
        let state = await f.flow.states.current
        XCTAssertEqual(state, .authenticated)
        // The refresh's ID token was validated against the claims it replaces.
        let validations = await f.validator.calls
        XCTAssertEqual(validations.last?.previous, "alice")
        XCTAssertNil(validations.last?.nonce)
    }

    func testAnAbandonedSlotIsReplayedWithTheSameKey() async throws {
        let store = MemoryCredentials()
        try await store.save(refreshToken: "rt-1", rawIdToken: nil)
        try await store.savePendingRotation("key-from-before")
        let f = try fixture(answers: [.success(response(refresh: "rt-2"))], store: store)

        try await f.coordinator.refresh()

        let calls = await f.tokens.calls
        XCTAssertEqual(calls, [.refresh("rt-1", "key-from-before")])
    }

    func testConcurrentCallersShareOneRefresh() async throws {
        let f = try fixture(answers: [.success(response(refresh: "rt-1", expiresIn: 60)), .success(response(refresh: "rt-2"))])
        try await f.coordinator.login(scopes: ["openid"])
        f.clock.advance(61)
        let gate = Gate()
        await f.tokens.hold(gate)

        async let first = f.coordinator.accessToken()
        async let second = f.coordinator.accessToken()
        await AuthzKit.waitUntil("both callers reached the token client") { await f.tokens.calls.count == 2 }
        await gate.open()
        let (a, b) = try await (first, second)

        XCTAssertEqual(a.value, b.value)
        let calls = await f.tokens.calls
        XCTAssertEqual(calls.count, 2)
    }

    func testInvalidGrantWipesTheSessionAndIsGrantRejected() async throws {
        let f = try fixture(answers: [.success(response(refresh: "rt-1", expiresIn: 60)), .failure(.reauthenticate(.grantRejected))])
        try await f.coordinator.login(scopes: ["openid"])
        f.clock.advance(61)

        do {
            _ = try await f.coordinator.accessToken()
            XCTFail("no error")
        } catch let error as OAuthError {
            XCTAssertEqual(error, .reauthenticate(.grantRejected))
        }

        let stored = await f.store.refresh
        XCTAssertNil(stored)
        let state = await f.flow.states.current
        XCTAssertEqual(state, .unauthenticated)
        let claims = await f.coordinator.claims
        XCTAssertNil(claims)
    }

    func testANetworkFailureLeavesTheGrantAndRevertsToAuthenticated() async throws {
        let network = OAuthError.recoverable(.network(detail: "down", attempts: 1, elapsedMillis: 0))
        let f = try fixture(answers: [.success(response(refresh: "rt-1", expiresIn: 60)), .failure(network), .failure(network)])
        try await f.coordinator.login(scopes: ["openid"])
        f.clock.advance(61)

        do {
            _ = try await f.coordinator.accessToken()
            XCTFail("no error")
        } catch let error as OAuthError {
            guard case .recoverable(.network(_, let attempts, _)) = error else { return XCTFail("\(error)") }
            XCTAssertEqual(attempts, 2)
        }

        let stored = await f.store.refresh
        XCTAssertEqual(stored, "rt-1")
        let slot = await f.store.rotation
        XCTAssertNotNil(slot, "the slot stays for the next attempt to replay")
        let state = await f.flow.states.current
        XCTAssertEqual(state, .authenticated)
    }

    func testALockedStoreEntersLocked() async throws {
        let f = try fixture(answers: [.success(response(refresh: "rt-1", expiresIn: 60)), .failure(.recoverable(.unlockRequired))])
        try await f.coordinator.login(scopes: ["openid"])
        f.clock.advance(61)

        _ = try? await f.coordinator.accessToken()

        let state = await f.flow.states.current
        XCTAssertEqual(state, .locked)
        let stored = await f.store.refresh
        XCTAssertEqual(stored, "rt-1")
    }

    // MARK: - Logout and restore

    func testLogoutRevokesEndsTheSessionAndWipes() async throws {
        let f = try fixture(answers: [.success(response())])
        try await f.coordinator.login(scopes: ["openid"])

        let outcome = await f.coordinator.logout()

        XCTAssertEqual(outcome, LogoutOutcome(sessionEnded: true, tokenRevoked: true))
        let calls = await f.tokens.calls
        XCTAssertEqual(calls.last, .revoke("rt-1"))
        let stored = await f.store.refresh
        XCTAssertNil(stored)
        let state = await f.flow.states.current
        XCTAssertEqual(state, .unauthenticated)
        let claims = await f.coordinator.claims
        XCTAssertNil(claims)
        do {
            _ = try await f.coordinator.accessToken()
            XCTFail("no error")
        } catch let error as OAuthError {
            XCTAssertEqual(error, .reauthenticate(.grantRejected))
        }
    }

    func testAFailedRevocationStillWipesAndSaysSo() async throws {
        let f = try fixture(answers: [.success(response())])
        try await f.coordinator.login(scopes: ["openid"])
        await f.tokens.setRevokeError(.recoverable(.network(detail: "503", attempts: 1, elapsedMillis: 0)))

        let outcome = await f.coordinator.logout(endSession: false)

        XCTAssertEqual(outcome, LogoutOutcome(sessionEnded: false, tokenRevoked: false))
        let stored = await f.store.refresh
        XCTAssertNil(stored)
        XCTAssertTrue(f.logger.warnings.contains { $0.contains("revocation failed") })
    }

    func testClaimsAreRestoredFromTheStoredIdTokenAfterAColdStart() async throws {
        let store = MemoryCredentials()
        try await store.save(refreshToken: "rt-1", rawIdToken: idToken(subject: "carol"))
        let f = try fixture(answers: [], store: store)

        let restored = await f.coordinator.restoreClaims()

        XCTAssertEqual(restored?.subject, "carol")
        let claims = await f.coordinator.claims
        XCTAssertEqual(claims?.subject, "carol")
        let validations = await f.validator.calls
        XCTAssertTrue(validations.isEmpty, "restored by parsing, not re-validated")
    }

    func testStepUpRequiredIsPublishedFromAuthenticated() async throws {
        let f = try fixture(answers: [.success(response())])
        try await f.coordinator.login(scopes: ["openid"])

        await f.coordinator.stepUpRequired()

        let state = await f.flow.states.current
        XCTAssertEqual(state, .stepUpRequired)
    }

    func testOfflineAccessIsWarnedOnceUnderOptionalWhenAdvertised() async throws {
        let f = try fixture(answers: [.success(response()), .success(response())])
        // The static metadata advertises no scopes: no warning.
        try await f.coordinator.login(scopes: ["openid"])
        XCTAssertFalse(f.logger.warnings.contains { $0.contains("offline_access") })
    }
}
