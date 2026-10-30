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
        var saveFailure: OAuthError?
        func failSave(_ error: OAuthError) { saveFailure = error }
        func save(refreshToken: String, rawIdToken: String?) async throws {
            if let saveFailure { throw saveFailure }
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
        var maxAges: [Int?] = []
        var rejection: IdTokenRejection?
        func reject(_ reason: IdTokenRejection) { rejection = reason }
        func validate(idToken: String, expectedNonce: String?, accessToken: String?, maxAge: Int?, previous: IdTokenClaims?, serverTime: Date?) async throws -> IdTokenClaims {
            calls.append((expectedNonce, previous?.subject))
            maxAges.append(maxAge)
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
        let pendingStore: MemoryPendingStore
    }

    private func idToken(subject: String = "alice", nonce: String = "n") -> String {
        let now = Int(Date().timeIntervalSince1970)
        return JoseTestTokens.rsa("RS256", payload: JoseTestTokens.json(["iss": Self.issuer, "sub": subject, "aud": "mobile", "iat": now, "exp": now + 3600, "nonce": nonce]))
    }

    private func response(refresh: String? = "rt-1", expiresIn: Int = 300, subject: String = "alice") -> TokenResponse {
        TokenResponse(accessToken: "at-\(refresh ?? "none")-\(UUID().uuidString.prefix(4))", tokenType: "Bearer", expiresIn: expiresIn, refreshToken: refresh, idToken: idToken(subject: subject), scope: "openid")
    }

    private func fixture(answers: [Result<TokenResponse, OAuthError>], policy: RefreshTokenPolicy = .optional, store: MemoryCredentials = MemoryCredentials(), retry: RetryPolicy? = nil, pending: PendingAuthorizationRequest? = nil, browser: ScriptedBrowser = ScriptedBrowser.answering(), clock injectedClock: TickingClock? = nil, validatorOverride: IdTokenValidator? = nil, warmUp: (@Sendable () async -> Void)? = nil) throws -> Fixture {
        let clock = injectedClock ?? TickingClock(Date(timeIntervalSince1970: 1_700_000_000))
        let configuration = CoreConfiguration(issuer: Self.issuer, clientId: "mobile", redirectUri: URL(string: Self.redirect)!, postLogoutRedirectUri: URL(string: "https://app.example.com/signed-out"))
        let discovery = DiscoveryService(issuer: Self.issuer, client: StaticDiscoveryClient(metadata: AuthzKit.metadata()), cache: MemoryMetadataCache())
        let pendingStore = MemoryPendingStore(pending)
        let flow = AuthorizationFlow(
            configuration: configuration, discovery: discovery, pendingStore: pendingStore,
            browser: browser, states: SessionStateHub(),
            clock: Clock(now: { Date() }), hasStoredGrant: { try await store.hasGrant() }
        )
        let tokens = ScriptedTokenClient(answers, store: store)
        let validator = RecordingValidator()
        let logger = Warnings()
        let coordinator = SessionCoordinator(
            flow: flow, tokenClient: tokens, credentialStore: store,
            retryPolicy: try retry ?? RetryPolicy(maxAttemptsPerOrigin: 2, maxTotalAttempts: 2, initialBackoff: 0, backoffMultiplier: 1, maxBackoff: 0, totalBudget: 10),
            clock: Clock(now: { clock.peek() }), logger: logger, refreshTokens: policy, idTokenValidator: validatorOverride ?? validator, warmUp: warmUp
        )
        return Fixture(coordinator: coordinator, flow: flow, store: store, tokens: tokens, validator: validator, logger: logger, clock: clock, pendingStore: pendingStore)
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

    /// Ory Hydra answers `token_type: bearer`. What the integrator holds is the scheme to write
    /// after `Authorization:`, in the spec's spelling (issue #77).
    func testATokenTypeInTheProvidersSpellingIsHandedOutAsTheSchemeBearer() async throws {
        let provider = TokenResponse(accessToken: "at-1", tokenType: "bearer", expiresIn: 300, refreshToken: "rt-1", idToken: idToken(), scope: "openid")
        let f = try fixture(answers: [.success(provider)])

        try await f.coordinator.login(scopes: ["openid"])

        let token = try await f.coordinator.accessToken()
        XCTAssertEqual(token.tokenType, "Bearer")
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

    // MARK: - Resume: a redirect delivered to a cold-started process

    /// What a previous process persisted before it was killed with the browser open. The flow's
    /// clock here is the wall clock, so the request is aged from it.
    private func restoredPending(maxAge: Int? = nil, age: TimeInterval = 60) -> PendingAuthorizationRequest {
        AuthzKit.pending(state: "restored-state", createdAt: Date().addingTimeInterval(-age), maxAge: maxAge)
    }

    private func delivering(state: String = "restored-state", iss: String? = AuthzKit.issuer) -> ScriptedBrowser {
        ScriptedBrowser(
            onAuthorize: { _, _ in throw AssertionError("a cold-started process opens no browser") },
            onAwait: { _ in .redirect(AuthzKit.redirect(answering: URL(string: "https://x.example.com/?state=\(state)")!, iss: iss)) }
        )
    }

    private struct AssertionError: Error {
        let message: String
        init(_ message: String) { self.message = message }
    }

    private func resumeFails(_ f: Fixture, file: StaticString = #filePath, line: UInt = #line) async -> OAuthError? {
        do {
            try await f.coordinator.resumePendingLogin()
            XCTFail("expected an error", file: file, line: line)
            return nil
        } catch {
            return error as? OAuthError
        }
    }

    func testARedirectDeliveredToAColdStartedProcessCompletesTheSignInFromTheRestoredRequest() async throws {
        let f = try fixture(answers: [.success(response())], pending: restoredPending(maxAge: 300), browser: delivering())

        // Authorizing on cold start, never unauthenticated (scenario 12).
        try await f.flow.ensureRestored()
        let restored = await f.flow.states.current
        XCTAssertEqual(restored, .authorizing)
        let resumed = try await f.coordinator.resumePendingLogin()

        XCTAssertNotNil(resumed)
        let state = await f.flow.states.current
        XCTAssertEqual(state, .authenticated)
        let stored = await f.store.refresh
        XCTAssertEqual(stored, "rt-1")
        let pending = await f.pendingStore.stored
        XCTAssertNil(pending)
        let claims = await f.coordinator.claims
        XCTAssertEqual(claims?.subject, "alice")
        let validations = await f.validator.calls
        XCTAssertEqual(validations.map(\.nonce), ["nonce-1"], "the restored nonce, not a regenerated one")
        let maxAges = await f.validator.maxAges
        XCTAssertEqual(maxAges, [300], "max_age comes from the restored request: no caller is left to supply it")
    }

    func testAResumedSignInClearsThePendingRequestOnlyAfterTheGrantIsStored() async throws {
        let store = MemoryCredentials()
        await store.failSave(OAuthError.recoverable(.unlockRequired))
        let f = try fixture(answers: [.success(response())], store: store, pending: restoredPending(), browser: delivering())

        _ = await resumeFails(f)

        // A kill (or a key that locks) between the exchange and the write finds the request
        // still in place, not a session that looks as if it never started.
        let pending = await f.pendingStore.stored
        XCTAssertNotNil(pending)
        let clears = await f.pendingStore.clearCount
        XCTAssertEqual(clears, 0)
        let stored = await store.refresh
        XCTAssertNil(stored)
    }

    func testResumingWithNothingPendingIsANoOpWithNoTokenRequest() async throws {
        let f = try fixture(answers: [], browser: delivering())

        let resumed = try await f.coordinator.resumePendingLogin()

        XCTAssertNil(resumed)
        let calls = await f.tokens.calls
        XCTAssertTrue(calls.isEmpty)
        let state = await f.flow.states.current
        XCTAssertEqual(state, .unauthenticated)
    }

    func testAResumedRedirectCarryingAnotherStateIsRefusedBeforeAnyTokenRequest() async throws {
        let f = try fixture(answers: [.success(response())], pending: restoredPending(), browser: delivering(state: "forged"))

        let error = await resumeFails(f)

        XCTAssertEqual(error, .configuration(.stateMismatch))
        let calls = await f.tokens.calls
        XCTAssertTrue(calls.isEmpty)
        let stored = await f.store.refresh
        XCTAssertNil(stored)
        let pending = await f.pendingStore.stored
        XCTAssertNil(pending)
        let state = await f.flow.states.current
        XCTAssertEqual(state, .unauthenticated)
    }

    func testAResumedRedirectFromAnotherIssuerIsRefusedBeforeAnyTokenRequest() async throws {
        let f = try fixture(answers: [.success(response())], pending: restoredPending(), browser: delivering(iss: "https://evil.example.com"))

        let error = await resumeFails(f)

        XCTAssertEqual(error, .configuration(.issuerMismatch(expected: Self.issuer, received: "https://evil.example.com")))
        let calls = await f.tokens.calls
        XCTAssertTrue(calls.isEmpty)
    }

    func testAResumedSignInWhoseIdTokenIsRefusedPersistsNothingAndClearsTheRequest() async throws {
        let f = try fixture(answers: [.success(response())], pending: restoredPending(), browser: delivering())
        await f.validator.reject(.nonce)

        let error = await resumeFails(f)

        XCTAssertEqual(error, .configuration(.idTokenRejected(.nonce)))
        let stored = await f.store.refresh
        XCTAssertNil(stored)
        let claims = await f.coordinator.claims
        XCTAssertNil(claims)
        // The code is spent: a slot kept here could only be resumed into invalid_grant.
        let pending = await f.pendingStore.stored
        XCTAssertNil(pending)
        let state = await f.flow.states.current
        XCTAssertEqual(state, .unauthenticated)
    }

    func testAResumedSignInWithNoIdTokenIsRefusedWhenAValidatorIsPresent() async throws {
        let bare = TokenResponse(accessToken: "at", tokenType: "Bearer", expiresIn: 300, refreshToken: "rt-1", idToken: nil, scope: "openid")
        let f = try fixture(answers: [.success(bare)], pending: restoredPending(), browser: delivering())

        let error = await resumeFails(f)

        XCTAssertEqual(error, .configuration(.idTokenRejected(.malformed)))
        let stored = await f.store.refresh
        XCTAssertNil(stored)
    }

    func testAPendingRequestOlderThanTenMinutesIsNeverResumed() async throws {
        let f = try fixture(answers: [.success(response())], pending: restoredPending(age: PendingAuthorizationRequest.maxAge + 5), browser: delivering())

        let error = await resumeFails(f)

        XCTAssertEqual(error, .recoverable(.pendingRequestExpired))
        let calls = await f.tokens.calls
        XCTAssertTrue(calls.isEmpty)
        let pending = await f.pendingStore.stored
        XCTAssertNil(pending)
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

    // MARK: - Server errors (spec/retry-policy.md, scenarios 34 to 36)

    private func serverError(_ status: Int, retryAfter: Int64? = nil) -> OAuthError {
        .recoverable(.server(status: status, retryAfterMillis: retryAfter, attempts: 1, elapsedMillis: 0))
    }

    /// A refresh is repeated on a transient server answer, under the budget, and the session stays
    /// where it was.
    func testARefreshIsRepeatedOnAnAnswerOf503AndSucceeds() async throws {
        let f = try fixture(answers: [.success(response(refresh: "rt-1", expiresIn: 60)), .failure(serverError(503)), .success(response(refresh: "rt-2"))])
        try await f.coordinator.login(scopes: ["openid"])
        f.clock.advance(61)

        _ = try await f.coordinator.accessToken()

        let calls = await f.tokens.calls
        XCTAssertEqual(calls.count, 3, "the exchange, the failed refresh and its repeat")
        let state = await f.flow.states.current
        XCTAssertEqual(state, .authenticated)
    }

    func testARefreshThatExhaustsTheBudgetOnFiveHundredsSurfacesServerWithTheStatusAndLeavesTheGrant() async throws {
        let f = try fixture(answers: [.success(response(refresh: "rt-1", expiresIn: 60)), .failure(serverError(500)), .failure(serverError(500))])
        try await f.coordinator.login(scopes: ["openid"])
        f.clock.advance(61)

        do {
            _ = try await f.coordinator.accessToken()
            XCTFail("no error")
        } catch let error as OAuthError {
            guard case .recoverable(.server(500, nil, let attempts, _)) = error else { return XCTFail("\(error)") }
            XCTAssertEqual(attempts, 2)
        }

        let stored = await f.store.refresh
        XCTAssertEqual(stored, "rt-1")
        let state = await f.flow.states.current
        XCTAssertEqual(state, .authenticated, "5xx never ends the session (spec/state-machine.md)")
    }

    func testAFiveHundredAndOneIsNotRepeatedByARefresh() async throws {
        let f = try fixture(answers: [.success(response(refresh: "rt-1", expiresIn: 60)), .failure(serverError(501)), .success(response(refresh: "rt-2"))])
        try await f.coordinator.login(scopes: ["openid"])
        f.clock.advance(61)

        do {
            _ = try await f.coordinator.accessToken()
            XCTFail("no error")
        } catch let error as OAuthError {
            XCTAssertEqual(error, serverError(501))
        }
        let calls = await f.tokens.calls
        XCTAssertEqual(calls.count, 2, "the exchange and one refresh")
    }

    /// A `Retry-After` the budget cannot hold ends the refresh at once, and a second call inside
    /// the window sends nothing at all: the cooldown (scenario 36).
    func testARetryAfterBeyondTheBudgetIsHandedToTheAppAndQuietsTheNextRefresh() async throws {
        let f = try fixture(answers: [.success(response(refresh: "rt-1", expiresIn: 60)), .failure(serverError(429, retryAfter: 30_000)), .success(response(refresh: "rt-2"))])
        try await f.coordinator.login(scopes: ["openid"])
        f.clock.advance(61)

        do {
            _ = try await f.coordinator.accessToken()
            XCTFail("no error")
        } catch let error as OAuthError {
            guard case .recoverable(.server(429, 30_000, 1, _)) = error else { return XCTFail("\(error)") }
        }
        let afterFirst = await f.tokens.calls.count

        do {
            _ = try await f.coordinator.accessToken()
            XCTFail("no error")
        } catch let error as OAuthError {
            guard case .recoverable(.server(429, let left?, 0, _)) = error else { return XCTFail("\(error)") }
            XCTAssertLessThanOrEqual(left, 30_000)
        }
        let afterSecond = await f.tokens.calls.count
        XCTAssertEqual(afterSecond, afterFirst, "nothing was sent while the server asked for quiet")
        let state = await f.flow.states.current
        XCTAssertEqual(state, .authenticated)
    }

    func testAnOperationJoinsTheBudgetOfTheOneThatIsRunningAndANewOperationStartsItsOwn() async throws {
        let f = try fixture(answers: [])
        let outer = await f.coordinator.operation { OperationBudget.current }
        XCTAssertNotNil(outer)
        let (inner, again): (RetryBudget?, RetryBudget?) = await f.coordinator.operation {
            let first = OperationBudget.current
            let second = await f.coordinator.operation { OperationBudget.current }
            return (first, second)
        }
        XCTAssertTrue(inner === again, "an operation started inside another shares its budget")
        let fresh: Bool = await f.coordinator.operation {
            let first = OperationBudget.current
            let own = await f.coordinator.newOperation { OperationBudget.current }
            return first !== own
        }
        XCTAssertTrue(fresh, "the part of a login after the browser has a budget of its own")
        XCTAssertNil(OperationBudget.current, "and nothing leaks out of the operation")
    }

    /// A validator that, like the real one reading the key set, makes a repeatable request under
    /// the operation's budget: it fails `failures` times with a 500, then validates.
    private struct KeySetValidator: IdTokenValidator {
        let requests: Box<Int>
        let failures: Int
        func validate(idToken: String, expectedNonce: String?, accessToken: String?, maxAge: Int?, previous: IdTokenClaims?, serverTime: Date?) async throws -> IdTokenClaims {
            let requests = self.requests
            let failures = self.failures
            try await OperationBudget.run(origin: "https://id.example.com") {
                let n = await requests.value + 1
                await requests.set(n)
                if n <= failures { throw OAuthError.recoverable(.server(status: 500, retryAfterMillis: nil, attempts: 1, elapsedMillis: 0)) }
            }
            return try IdTokenClaimsParser.parseStored(idToken)
        }
    }

    /// The time the user spends in the browser is not the SDK's (`spec/retry-policy.md`, "Order of
    /// work"): five minutes on the sign-in page, then a failing request the budget repeats, still
    /// gets its whole allowance and its time.
    func testAFiveMinuteBrowserLegDoesNotSpendTheBudgetOfTheRequestsAfterIt() async throws {
        let clock = TickingClock(Date(timeIntervalSince1970: 1_700_000_000))
        let browser = ScriptedBrowser { uri, _ in
            clock.advance(300)
            return .redirect(AuthzKit.redirect(answering: uri))
        }
        let requests = Box(0)
        let f = try fixture(answers: [.success(response())], browser: browser, clock: clock, validatorOverride: KeySetValidator(requests: requests, failures: 1))
        let opened = clock.peek()

        try await f.coordinator.operation { try await f.coordinator.login(scopes: ["openid"]) }

        XCTAssertGreaterThanOrEqual(clock.peek().timeIntervalSince(opened), 300, "the browser leg really took five minutes")
        let made = await requests.value
        XCTAssertEqual(made, 2, "the failed request was repeated once the user was back")
        let state = await f.flow.states.current
        XCTAssertEqual(state, .authenticated)
    }

    func testAfterAFiveMinuteBrowserLegAFailingRequestStillGetsTheWholeAllowance() async throws {
        let clock = TickingClock(Date(timeIntervalSince1970: 1_700_000_000))
        let browser = ScriptedBrowser { uri, _ in
            clock.advance(300)
            return .redirect(AuthzKit.redirect(answering: uri))
        }
        let requests = Box(0)
        let f = try fixture(answers: [.success(response())], browser: browser, clock: clock, validatorOverride: KeySetValidator(requests: requests, failures: 100))

        do {
            try await f.coordinator.operation { try await f.coordinator.login(scopes: ["openid"]) }
            XCTFail("no error")
        } catch let error as OAuthError {
            // The fixture's policy allows two attempts per origin: both are made, none is lost to the browser.
            guard case .recoverable(.server(500, nil, 2, _)) = error else { return XCTFail("\(error)") }
        }
        let made = await requests.value
        XCTAssertEqual(made, 2)
        let state = await f.flow.states.current
        XCTAssertEqual(state, .unauthenticated)
    }

    /// "One request, no retries, failure ignored, before the browser opens" (`spec/retry-policy.md`).
    func testTheKeySetIsWarmedBeforeTheBrowserOpensOutsideTheBudgetAndItsFailureIsIgnored() async throws {
        let order = Box<[String]>([])
        let seenBudget = Box<Bool?>(nil)
        let browser = ScriptedBrowser { uri, _ in
            await order.set(await order.value + ["browser"])
            return .redirect(AuthzKit.redirect(answering: uri))
        }
        let f = try fixture(answers: [.success(response())], browser: browser, warmUp: {
            await seenBudget.set(OperationBudget.current != nil)
            await order.set(await order.value + ["warm-up"])
        })

        try await f.coordinator.operation { try await f.coordinator.login(scopes: ["openid"]) }

        let seen = await order.value
        XCTAssertEqual(Array(seen.prefix(2)), ["warm-up", "browser"], "the first warm-up precedes the browser")
        let inBudget = await seenBudget.value
        XCTAssertEqual(inBudget, false, "outside any budget: one attempt, no repeat")
        let state = await f.flow.states.current
        XCTAssertEqual(state, .authenticated, "and a warm-up that finds nothing is not a failure of the login")
    }
}
