import Foundation
import XCTest
@testable import OAuthCore

/// Regression tests for the iOS audit (W1 to W21). Each asserts the CORRECT behaviour, so each is
/// red until its bug is fixed. They reuse the fakes of `SessionCoordinatorTests`.
extension SessionCoordinatorTests {
    // MARK: - W1

    /// AUDIT: W1. The provider rotated when it answered, so the new refresh token exists only in
    /// that response. A store that locks between the answer and `saveRefreshed` must not cost the
    /// grant: the next refresh has to spend the rotated token (kept in memory or retried), not the
    /// spent one the slot still names.
    func testRotatedRefreshTokenSurvivesTheStoreLockingBetweenAnswerAndSave() async throws {
        let f = try fixture(answers: [
            .success(response(refresh: "rt-1", expiresIn: 60)),
            .success(response(refresh: "rt-2", expiresIn: 60)),
            .success(response(refresh: "rt-3")),
        ])
        try await f.coordinator.login(scopes: ["openid"])
        f.clock.advance(61)
        await f.store.failNextSaveRefreshed(.recoverable(.unlockRequired))

        do {
            _ = try await f.coordinator.accessToken()
            XCTFail("the locked store should have failed the refresh")
        } catch let error as OAuthError {
            XCTAssertEqual(error, .recoverable(.unlockRequired))
        }

        // The device unlocks; the app asks again.
        _ = try await f.coordinator.accessToken()

        let calls = await f.tokens.calls
        guard case .refresh(let spent, _)? = calls.last else { return XCTFail("\(calls)") }
        XCTAssertEqual(spent, "rt-2", "the second refresh replayed the token the first one already spent")
        let clears = await f.store.clears
        XCTAssertEqual(clears, 0, "nothing is wiped")
        let state = await f.flow.states.current
        XCTAssertEqual(state, .authenticated)
    }

    /// AUDIT: W1. A caller cancelled after the server answered must not cost the rotated token:
    /// the flight is its own task and persists it. (Expected to pass today: the flight is
    /// unstructured; kept so a fix of W15 cannot regress it.)
    func testRotatedRefreshTokenIsPersistedWhenTheCallerIsCancelledAfterTheServerAnswered() async throws {
        let f = try fixture(answers: [.success(response(refresh: "rt-1", expiresIn: 60)), .success(response(refresh: "rt-2"))])
        try await f.coordinator.login(scopes: ["openid"])
        f.clock.advance(61)
        let gate = Gate()
        await f.tokens.hold(gate)

        let caller = Task { try await f.coordinator.accessToken() }
        await AuthzKit.waitUntil("the refresh reached the token client") { await f.tokens.calls.count == 2 }
        caller.cancel()
        await gate.open()
        _ = await caller.result

        await AuthzKit.waitUntil("the rotated token was stored") { await f.store.refresh == "rt-2" }
    }

    // MARK: - W2

    /// AUDIT: W2. `logout()` while the code exchange is out: the wipe cleared the stores, and the
    /// exchange must not then save a new refresh token and publish `authenticated`.
    func testLogoutDuringTheCodeExchangeIsNotUndoneByTheLoginFinishing() async throws {
        let f = try fixture(answers: [.success(response(refresh: "rt-new"))])
        let gate = Gate()
        await f.tokens.holdExchange(gate)

        let login = Task { try await f.coordinator.login(scopes: ["openid"]) }
        await AuthzKit.waitUntil("the exchange is out") { await f.tokens.calls.contains(.exchange) }
        _ = await f.coordinator.logout(revoke: false, endSession: false)
        await gate.open()
        _ = await login.result

        let stored = await f.store.refresh
        XCTAssertNil(stored, "the login that outlived the logout saved its refresh token")
        let state = await f.flow.states.current
        XCTAssertEqual(state, .unauthenticated)
        let claims = await f.coordinator.claims
        XCTAssertNil(claims)
    }

    /// AUDIT: W2. A refresh that started under the old grant must not overwrite the refresh token
    /// a step-up login stored while it was in flight.
    func testARefreshStartedUnderTheOldGrantDoesNotOverwriteTheTokenOfAStepUpLogin() async throws {
        let f = try fixture(answers: [
            .success(response(refresh: "rt-old", expiresIn: 60)),
            .success(response(refresh: "rt-stepup")),
            .success(response(refresh: "rt-old-rotated")),
        ])
        try await f.coordinator.login(scopes: ["openid"])
        f.clock.advance(61)
        let gate = Gate()
        await f.tokens.hold(gate)

        let refresh = Task { try await f.coordinator.accessToken() }
        await AuthzKit.waitUntil("the refresh is out") { await f.tokens.calls.count == 2 }
        try await f.coordinator.login(scopes: ["openid"], acrValues: ["urn:example:acr:2"])
        let afterStepUp = await f.store.refresh
        XCTAssertEqual(afterStepUp, "rt-stepup")
        await gate.open()
        _ = await refresh.result

        let stored = await f.store.refresh
        XCTAssertEqual(stored, "rt-stepup", "the refresh of the previous grant overwrote the new one")
    }

    // MARK: - W3

    /// AUDIT: W3. A local wipe that failed (`clear()` throws) must not look like a clean sign-out:
    /// the surviving grant must not mint tokens for a user who logged out. (The other half of the
    /// expectation, `LogoutOutcome` saying the wipe was incomplete, needs a field that does not
    /// exist yet; see the report.)
    func testAccessTokenAfterALogoutWhoseWipeFailedDoesNotMintFromTheSurvivingGrant() async throws {
        let f = try fixture(answers: [
            .success(response(refresh: "rt-1")),
            .success(response(refresh: "rt-2")),
        ])
        try await f.coordinator.login(scopes: ["openid"])
        await f.store.failClear(.recoverable(.unlockRequired))

        _ = await f.coordinator.logout(revoke: false, endSession: false)

        do {
            let token = try await f.coordinator.accessToken()
            XCTFail("minted \(token) after logout from the grant the wipe could not remove")
        } catch let error as OAuthError {
            XCTAssertEqual(error, .reauthenticate(.grantRejected))
        }
        let calls = await f.tokens.calls
        XCTAssertFalse(calls.contains { if case .refresh = $0 { true } else { false } })
    }

    // MARK: - W4

    /// AUDIT: W4. The local credentials are wiped before the end-session browser opens: a process
    /// killed while the sheet is up must not leave a refresh token behind. `id_token_hint` is read
    /// first.
    func testLogoutWipesTheLocalCredentialsBeforeTheEndSessionBrowserOpens() async throws {
        let store = MemoryCredentials()
        let opened = Box(false)
        let refreshWhenOpened = Box<String?>("<browser never opened>")
        let hint = Box<String?>(nil)
        let browser = ScriptedBrowser { uri, _ in
            if uri.path.hasSuffix("/logout") {
                await opened.set(true)
                await refreshWhenOpened.set(await store.refresh)
                await hint.set(AuthorizationResponseValidator.parseQuery(uri)["id_token_hint"])
                return .userCancelled
            }
            return .redirect(AuthzKit.redirect(answering: uri))
        }
        let f = try fixture(answers: [.success(response(refresh: "rt-1"))], store: store, browser: browser)
        try await f.coordinator.login(scopes: ["openid"])

        _ = await f.coordinator.logout(revoke: false, endSession: true)

        let wasOpened = await opened.value
        XCTAssertTrue(wasOpened)
        let atOpen = await refreshWhenOpened.value
        XCTAssertNil(atOpen, "the refresh token was still stored while the end-session sheet was up")
        let sentHint = await hint.value
        XCTAssertNotNil(sentHint, "the id_token_hint must be read before the wipe")
    }

    // MARK: - W6

    /// AUDIT: W6. A rotation slot that does not name the token currently stored (left by an earlier
    /// generation, then a login or step-up replaced the token) is stale: the refresh must derive its
    /// key from the stored token, not replay the slot. Note `testAnAbandonedSlotIsReplayedWithTheSameKey`
    /// stores a slot that is not the hash of its token and will have to name `idempotencyKey(for:)`.
    func testASlotThatDoesNotNameTheStoredTokenIsNotReplayed() async throws {
        let store = MemoryCredentials()
        try await store.save(refreshToken: "rt-new", rawIdToken: nil)
        try await store.savePendingRotation(SessionCoordinator.idempotencyKey(for: "rt-spent"))
        let f = try fixture(answers: [.success(response(refresh: "rt-next"))], store: store)

        try await f.coordinator.refresh()

        let calls = await f.tokens.calls
        XCTAssertEqual(calls, [.refresh("rt-new", SessionCoordinator.idempotencyKey(for: "rt-new"))])
    }

    // MARK: - W15

    /// AUDIT: W15. `Task.value` ignores the awaiting task's cancellation: a cancelled
    /// `accessToken()` must come back at once with `CancellationError` while the flight goes on.
    func testACancelledAccessTokenCallerReturnsPromptlyWhileTheFlightContinues() async throws {
        let f = try fixture(answers: [.success(response(refresh: "rt-1", expiresIn: 60)), .success(response(refresh: "rt-2"))])
        try await f.coordinator.login(scopes: ["openid"])
        f.clock.advance(61)
        let gate = Gate()
        await f.tokens.hold(gate)
        let outcome = Box("pending")
        let returned = expectation(description: "the cancelled caller returned")

        let caller = Task {
            do { _ = try await f.coordinator.accessToken(); await outcome.set("token") }
            catch is CancellationError { await outcome.set("cancelled") }
            catch { await outcome.set("other: \(error)") }
            returned.fulfill()
        }
        await AuthzKit.waitUntil("the refresh is out") { await f.tokens.calls.count == 2 }
        caller.cancel()
        await fulfillment(of: [returned], timeout: 2)
        let result = await outcome.value
        // Let the flight finish either way, so the test does not leak it.
        await gate.open()
        _ = await caller.result

        XCTAssertEqual(result, "cancelled", "the cancelled caller stayed blocked on the flight")
        await AuthzKit.waitUntil("the flight stored the rotated token") { await f.store.refresh == "rt-2" }
    }
}

final class AuditDiscoveryTests: XCTestCase {
    private let document = """
    {"issuer":"https://id.example.com","authorization_endpoint":"https://id.example.com/authorize",
     "token_endpoint":"https://id.example.com/token","jwks_uri":"https://id.example.com/jwks"}
    """

    /// AUDIT: W15. Discovery's `task.value` has the same flaw: a cancelled caller must return.
    func testACancelledDiscoveryCallerReturnsPromptlyWhileTheFetchContinues() async throws {
        let gate = Gate()
        let document = self.document
        let http = RecordingHTTP { _ in
            await gate.wait()
            return HTTPResponse(statusCode: 200, body: Data(document.utf8))
        }
        let service = DiscoveryService(issuer: AuthzKit.issuer, client: HTTPDiscoveryClient(httpClient: http), cache: MemoryMetadataCache())
        let outcome = Box("pending")
        let returned = expectation(description: "the cancelled caller returned")

        let caller = Task {
            do { _ = try await service.metadata(); await outcome.set("metadata") }
            catch is CancellationError { await outcome.set("cancelled") }
            catch { await outcome.set("other: \(error)") }
            returned.fulfill()
        }
        await AuthzKit.waitUntil("the fetch is out") { await http.requests.count == 1 }
        caller.cancel()
        await fulfillment(of: [returned], timeout: 2)
        let result = await outcome.value
        await gate.open()
        _ = await caller.result

        XCTAssertEqual(result, "cancelled", "the cancelled caller stayed blocked on the fetch")
    }

    /// AUDIT: W16. Cached metadata is served as a fallback however old it is; the JWKS cache stops
    /// at 7 days. A document saved 30 days ago with the refetch failing must be refused.
    func testMetadataCachedThirtyDaysAgoIsNotServedWhenTheRefetchFails() async throws {
        let cache = MemoryMetadataCache()
        try await cache.save(AuthzKit.metadata())
        let later = Date().addingTimeInterval(30 * 86_400)
        let service = DiscoveryService(
            issuer: AuthzKit.issuer, client: HTTPDiscoveryClient(httpClient: RecordingHTTP.json(503, "")), cache: cache,
            clock: Clock(now: { later }, uptime: { 1000 })
        )

        do {
            let served = try await service.metadata()
            XCTFail("served a 30-day-old document: \(served.issuer)")
        } catch let error as OAuthError {
            guard case .recoverable = error else { return XCTFail("\(error)") }
        }
    }
}

final class AuditProtocolTests: XCTestCase {
    // MARK: W14

    /// AUDIT: W14. `OAuthError` reaches app code as `Error`; without `LocalizedError`
    /// `localizedDescription` is the useless "The operation couldn't be completed. (OAuthCore.OAuthError error 0.)".
    func testOAuthErrorConformsToLocalizedErrorWithAUsefulDescription() {
        let samples: [OAuthError] = [
            .reauthenticate(.grantRejected), .recoverable(.unlockRequired), .configuration(.stateMismatch),
            .stepUp(acrValues: ["a"], maxAge: nil),
        ]
        for error in samples {
            let described = (error as Error as? LocalizedError)?.errorDescription
            XCTAssertNotNil(described, "\(error) has no errorDescription")
            XCTAssertFalse((error as Error).localizedDescription.contains("error 0"), "\(error): \((error as Error).localizedDescription)")
        }
    }

    private func redirect(_ pairs: [(String, String)]) -> URL {
        URL(string: AuthzKit.redirect + "?" + FormEncoding.encode(pairs))!
    }

    /// AUDIT: W14. The `error` code of a redirect is the server's (or whoever delivered the URL);
    /// it ends up in logs `.public`, so it must be a bounded token before it is carried.
    func testAnAuthorizationErrorCodeWithJunkCharactersIsBoundedBeforeItIsCarried() {
        let junk = "bad\ncode \u{1B}[31m" + String(repeating: "A", count: 5_000)
        let url = redirect([("state", "state-1"), ("iss", AuthzKit.issuer), ("error", junk)])

        XCTAssertThrowsError(try AuthorizationResponseValidator.validate(redirect: url, pending: AuthzKit.pending(), issuer: AuthzKit.issuer, issParameterSupported: false)) {
            guard case .configuration(.authorizationRejected(let code, let description))? = $0 as? OAuthError else { return XCTFail("\($0)") }
            XCTAssertLessThanOrEqual(code.count, 64)
            XCTAssertTrue(code.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || "_-.".contains($0)) }, "code is not a token: \(code.debugDescription)")
            XCTAssertLessThanOrEqual(description?.count ?? 0, 256)
            XCTAssertLessThanOrEqual(String(describing: $0).count, 512)
        }
    }

    /// AUDIT: W14. The `iss` a redirect carried is echoed in `issuerMismatch(received:)`.
    func testAnIssuerMismatchBoundsWhatItEchoesOfTheReceivedIssuer() {
        let url = redirect([("state", "state-1"), ("iss", "https://evil.example.org/" + String(repeating: "x", count: 5_000)), ("code", "c")])

        XCTAssertThrowsError(try AuthorizationResponseValidator.validate(redirect: url, pending: AuthzKit.pending(), issuer: AuthzKit.issuer, issParameterSupported: false)) {
            guard case .configuration(.issuerMismatch(_, let received))? = $0 as? OAuthError else { return XCTFail("\($0)") }
            XCTAssertLessThanOrEqual(received?.count ?? 0, 256)
        }
    }

    // MARK: W17

    /// AUDIT: W17 (correctness only; the per-response `DateFormatter` is a performance finding, not tested).
    func testHTTPDateParsesRfc1123AndRejectsGarbage() {
        XCTAssertEqual(HTTPDate.parse("Sun, 06 Nov 1994 08:49:37 GMT"), Date(timeIntervalSince1970: 784_111_777))
        XCTAssertNil(HTTPDate.parse("not a date"))
    }

    // MARK: W19

    private struct Source: AccessTokenSource {
        func accessToken() async throws -> AccessToken { AccessToken(value: "at", tokenType: "Bearer") }
        func renewAccessToken() async throws -> AccessToken { AccessToken(value: "at", tokenType: "Bearer") }
    }

    /// AUDIT: W19. A signed UserInfo response that verifies and has the right `sub` but names
    /// another issuer and another audience must be refused (OpenID Connect Core 5.3.2: `iss` and
    /// `aud`, when present, are the OP's and the client's). The client has no configured issuer or
    /// client id today, so the fix adds them to `HTTPUserInfoClient.init`; this test then needs
    /// those arguments (issuer https://id.example.com, client id "client-123").
    func testSignedUserInfoNamingAnotherIssuerAndAudienceIsRefused() async {
        let stub = JoseStubHTTP()
        await stub.enqueue("/jwks.json", body: JoseTestTokens.jwks(JoseTestKeys.rsa.jwk(kid: "rsa")))
        let payload = JoseTestTokens.json(["sub": "user-1", "iss": "https://evil.example.org", "aud": "someone-elses-client"])
        await stub.enqueue("/userinfo", headers: ["Content-Type": "application/jwt"], text: JoseTestTokens.rsa("RS256", payload: payload))
        let client = HTTPUserInfoClient(
            userinfoEndpoint: { "https://id.example.com/userinfo" }, httpClient: stub, dpop: nil,
            verifier: JwsVerifier(jwksUri: { "https://id.example.com/jwks.json" }, allowedAlgorithms: { [] }, jwks: JwksClient(httpClient: stub))
        )

        do {
            let info = try await client.fetch(tokens: Source(), expectedSubject: "user-1")
            XCTFail("accepted a response from another issuer: \(info)")
        } catch let error as OAuthError {
            guard case .configuration(.userInfoRejected) = error else { return XCTFail("\(error)") }
        } catch {
            XCTFail("\(error)")
        }
    }

    // MARK: W20

    /// AUDIT: W20. PAR's `expires_in` is ignored: a `request_uri` that lived 1 s must not be
    /// redeemed by a redirect that arrives 5 s later.
    func testARedirectAfterTheRequestUriExpiredIsRefusedAsAnExpiredRequest() async throws {
        let manual = ManualClock()
        let par = RecordingHTTP.json(201, #"{"request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":1}"#)
        let pendingStore = MemoryPendingStore()
        let browser = ScriptedBrowser { uri, _ in
            manual.advance(5)
            let state = await pendingStore.stored?.state
            return .redirect(AuthzKit.redirect(answering: uri, state: state))
        }
        let metadata = AuthzKit.metadata(parEndpoint: "https://id.example.com/par")
        let flow = AuthorizationFlow(
            configuration: AuthzKit.configuration,
            discovery: DiscoveryService(issuer: AuthzKit.issuer, client: StaticDiscoveryClient(metadata: metadata), cache: MemoryMetadataCache()),
            pendingStore: pendingStore, browser: browser, states: SessionStateHub(), clock: manual.clock,
            starter: PushedAuthorizationStarter(configuration: AuthzKit.configuration, httpClient: par, policy: .whenAdvertised)
        )

        do {
            _ = try await flow.authorize(scopes: ["openid"])
            XCTFail("a grant was issued from an expired request_uri")
        } catch let error as OAuthError {
            XCTAssertEqual(error, .recoverable(.pendingRequestExpired))
        }
    }
}
