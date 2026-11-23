import Foundation
import XCTest
@testable import OAuthClient
@testable import OAuthCore
@testable import VersolaEdge
@testable import VersolaSDK

/// What follows a sign-in (`spec/versola-sdk-api.md` sections 6, 7, 10 and 12): step-up and the account
/// check, refresh, sign-out, and the authenticated session scoped to edge.
private let stepUpChallenge = OAuthError.stepUp(acrValues: ["sensitive"], maxAge: 120)

final class VersolaSessionTests: XCTestCase {
    override func setUp() async throws {
        await Versola.forgetAll()
        StubURLProtocol.reset()
    }

    override func tearDown() async throws {
        await Versola.forgetAll()
        StubURLProtocol.reset()
    }

    private func signedIn(subject: String = "alice", options: LoginOptions = LoginOptions(), world: World = World()) async throws -> (World, Versola) {
        await world.edge.setSubjects([subject])
        let client = try await world.create()
        try await client.login(options)
        return (world, client)
    }

    private func revokedTokens(_ world: World) async -> [String] { await world.edge.revoked }

    // MARK: stepUp

    func testStepUpWithoutASessionIsAnInvalidConfigurationAndOpensNoBrowser() async throws {
        let world = World()
        let client = try await world.create()

        let error = await thrown { try await client.stepUp(stepUpChallenge) }

        guard case .configuration(.invalidConfiguration(let detail))? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertTrue(detail.contains("there is none"), detail)
        let opened = await world.browser.opened
        let requests = await world.edge.requests
        XCTAssertTrue(opened.isEmpty)
        XCTAssertTrue(requests.isEmpty)
    }

    func testStepUpWithAnyErrorButAStepUpChallengeIsAMisuse() async throws {
        let (world, client) = try await signedIn()
        let startsBefore = await world.edge.starts.count

        for notAChallenge in [OAuthError.recoverable(.userCancelled), .reauthenticate(.grantRejected), .configuration(.stateMismatch)] {
            let error = await thrown { try await client.stepUp(notAChallenge) }
            guard case .configuration(.invalidConfiguration)? = error else { XCTFail("\(notAChallenge): \(String(describing: error))"); continue }
        }
        let startsAfter = await world.edge.starts.count
        XCTAssertEqual(startsAfter, startsBefore)
    }

    func testStepUpWithoutOptionsAsksForTheGrantedScopeTheChallengesAcrAndMaxAge() async throws {
        let world = World()
        let (_, client) = try await signedIn(options: LoginOptions(scopes: ["email"]), world: world)
        await world.edge.setClaimOverrides(["auth_time": Int(Sdk.now.timeIntervalSince1970) - 5, "acr": "sensitive"])
        // What the response granted is what is remembered: the scripted edge answers "openid offline_access".
        let remembered = await world.scopes.load()
        XCTAssertEqual(remembered, ["openid", "offline_access"])
        await world.scopes.save(["openid", "offline_access", "email"])

        try await client.stepUp(stepUpChallenge)

        let starts = await world.edge.starts
        XCTAssertEqual(starts.count, 2)
        let form = Dictionary(grouping: starts[1].form, by: \.0).mapValues { $0.map(\.1) }
        XCTAssertEqual(form["scope"]?.first?.split(separator: " ").sorted(), ["email", "offline_access", "openid"])
        XCTAssertEqual(form["acr_values"], ["sensitive"])
        XCTAssertEqual(form["max_age"], ["120"])
        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
    }

    func testStepUpWithOptionsOverridesTheScopesAndTakesAcrAndMaxAgeFromTheChallenge() async throws {
        let world = World()
        let (_, client) = try await signedIn(world: world)
        await world.edge.setClaimOverrides(["auth_time": Int(Sdk.now.timeIntervalSince1970) - 5])

        try await client.stepUp(stepUpChallenge, options: LoginOptions(scopes: ["payments"], acrValues: ["ignored"], maxAge: 9999))

        let starts = await world.edge.starts
        let form = Dictionary(grouping: starts[1].form, by: \.0).mapValues { $0.map(\.1) }
        XCTAssertEqual(form["scope"]?.first?.split(separator: " ").sorted(), ["offline_access", "openid", "payments"])
        XCTAssertEqual(form["acr_values"], ["sensitive"], "from the challenge")
        XCTAssertEqual(form["max_age"], ["120"], "from the challenge")
    }

    func testStepUpAnsweredByTheSameUserReplacesTheGrant() async throws {
        let (world, client) = try await signedIn(subject: "alice")
        await world.edge.setClaimOverrides(["auth_time": Int(Sdk.now.timeIntervalSince1970) - 5])

        try await client.stepUp(stepUpChallenge)

        let refresh = try await world.credentials.refreshToken()
        let claims = await client.claims
        let state = await client.sessionState
        XCTAssertEqual(refresh, "rt-2")
        XCTAssertEqual(claims?.subject, "alice")
        XCTAssertEqual(state, .authenticated)
        let revoked = await revokedTokens(world)
        XCTAssertTrue(revoked.isEmpty)
    }

    func testStepUpAnsweredByAnotherUserIsAnAccountMismatchTheSessionIsIntactAndTheRefusedTokenIsRevoked() async throws {
        let world = World()
        await world.edge.setSubjects(["alice", "bob"])
        let client = try await world.create()
        try await client.login()
        let idTokenBefore = try await world.credentials.rawIdToken()
        await world.edge.setClaimOverrides(["auth_time": Int(Sdk.now.timeIntervalSince1970) - 5])

        let error = await thrown { try await client.stepUp(stepUpChallenge) }

        XCTAssertEqual(error, .recoverable(.accountMismatch))
        XCTAssertEqual(error?.code, "recoverable.account_mismatch")
        let refresh = try await world.credentials.refreshToken()
        let idTokenAfter = try await world.credentials.rawIdToken()
        let claims = await client.claims
        let state = await client.sessionState
        let pending = try await world.pending.load()
        XCTAssertEqual(refresh, "rt-1", "the session is as it was")
        XCTAssertEqual(idTokenAfter, idTokenBefore)
        XCTAssertEqual(claims?.subject, "alice")
        XCTAssertEqual(state, .authenticated)
        XCTAssertNil(pending)
        // Bounded await: the revocation is best effort and detached from the call that failed.
        await waitUntil("bob's refresh token is revoked") { await world.edge.revoked == ["rt-2"] }
        let revokeRequests = await world.edge.requests(path: "/native/revoke/")
        XCTAssertEqual(ScriptedEdge.proofClaims(try XCTUnwrap(revokeRequests.first))["htu"] as? String, Sdk.revocationEndpoint)
        let session = try client.session()
        _ = session
    }

    func testAnAccountMismatchLeavesTheRememberedScopeAndTheEndpointsOfTheSessionAlone() async throws {
        let world = World()
        await world.edge.setSubjects(["alice", "bob"])
        let client = try await world.create()
        try await client.login(LoginOptions(scopes: ["email"]))
        await world.scopes.save(["openid", "offline_access", "email"])
        await world.edge.setClaimOverrides(["auth_time": Int(Sdk.now.timeIntervalSince1970) - 5])

        _ = await thrown { try await client.stepUp(stepUpChallenge) }

        let remembered = await world.scopes.load()
        XCTAssertEqual(remembered, ["openid", "offline_access", "email"])
    }

    func testAStoreThatCannotBeReadFailsTheStepUpBeforeTheBrowserOpensWithTheStoresOwnError() async throws {
        // A cold start: a grant and an ID token are stored, nothing is in memory, and the store is locked.
        let world = World()
        func b64(_ text: String) -> String {
            Data(text.utf8).base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        }
        let stored = "\(b64(#"{"alg":"ES256"}"#)).\(b64(#"{"iss":"https://id.example.com","sub":"carol","aud":"x","exp":1900000000,"iat":1800000000}"#)).sig"
        try await world.credentials.save(refreshToken: "rt-stored", rawIdToken: stored)
        let locked = LockedCredentials(wrapping: world.credentials)
        locked.lock()
        let client = try await Versola.create(
            configuration: try world.configuration(),
            wiring: Versola.Wiring(
                browser: world.browser, credentialStore: locked, pendingStore: world.pending, endpointsStore: world.endpoints,
                grantedScopeStore: world.scopes, httpClient: world.edge,
                makeDpopKey: { hardware, logger, held in SecureEnclaveDpopKey(store: world.keys, requireHardware: hardware, logger: logger, secureEnclaveAvailable: false, isGrantHeld: held) },
                clock: Sdk.fixedClock
            )
        )

        let error = await thrown { try await client.stepUp(stepUpChallenge) }

        XCTAssertEqual(error, .recoverable(.unlockRequired))
        let opened = await world.browser.opened
        let requests = await world.edge.requests
        XCTAssertTrue(opened.isEmpty, "the browser does not open for a session whose user cannot be learned")
        XCTAssertTrue(requests.isEmpty)
    }

    func testAStepUpAndAPlainLoginThatDifferOnlyInTheExpectedSubjectAreNotOneFlight() async throws {
        let world = World()
        let (_, client) = try await signedIn(world: world)
        let gate = Gate()
        await world.browser.hold(gate)
        await world.edge.setClaimOverrides(["auth_time": Int(Sdk.now.timeIntervalSince1970) - 5])
        let openedBefore = await world.browser.opened.count

        // The step-up carries alice's `sub`; a login with the same scopes, acr and max_age carries none.
        async let stepUp: OAuthError? = thrown { try await client.stepUp(stepUpChallenge, options: LoginOptions(scopes: ["email"])) }
        await waitUntil("the step-up's browser is up") { await world.browser.opened.count == openedBefore + 1 }
        let joinAttempt = await thrown { try await client.login(LoginOptions(scopes: ["email"], acrValues: ["sensitive"], maxAge: 120)) }

        guard case .configuration(.invalidConfiguration(let detail))? = joinAttempt else { await gate.open(); return XCTFail("\(String(describing: joinAttempt))") }
        XCTAssertTrue(detail.contains("already in progress"), detail)
        let openedDuring = await world.browser.opened.count
        XCTAssertEqual(openedDuring, openedBefore + 1, "no second browser, and no join")

        // The identical step-up does join: one browser, one exchange, one outcome for both.
        async let joined: OAuthError? = thrown { try await client.stepUp(stepUpChallenge, options: LoginOptions(scopes: ["email"])) }
        await gate.open()
        let first = await stepUp, second = await joined
        XCTAssertNil(first)
        XCTAssertNil(second)
        let completes = await world.edge.requests(path: "/native/complete/")
        XCTAssertEqual(completes.count, 2, "the sign-in, and one step-up exchange for the two callers")
    }

    // MARK: refresh

    func testRefreshSpendsTheRefreshTokenThroughEdgeSignedForTheStoredTokenEndpoint() async throws {
        let (world, client) = try await signedIn()

        try await client.refresh()

        let requests = await world.edge.requests(path: "/native/token/")
        XCTAssertEqual(requests.count, 1)
        let request = try XCTUnwrap(requests.first)
        XCTAssertEqual(ScriptedEdge.decode(request).map(\.0), ["grant_type", "refresh_token"])
        XCTAssertEqual(ScriptedEdge.decode(request).last?.1, "rt-1")
        XCTAssertNotNil(request.headers["Idempotency-Key"])
        XCTAssertEqual(ScriptedEdge.proofClaims(request)["htu"] as? String, Sdk.tokenEndpoint)
    }

    func testRefreshAfterTheStoredEndpointsAreGoneIsCredentialsInvalidatedWithNothingSentAndTheGrantIsWiped() async throws {
        let (world, client) = try await signedIn()
        let tokenRequestsBefore = await world.edge.requests(path: "/native/token/").count
        try await world.endpoints.save(EdgeNativeEndpoints(tokenEndpoint: "http://auth.example.com/token", revocationEndpoint: Sdk.revocationEndpoint))

        let error = await thrown { try await client.refresh() }

        XCTAssertEqual(error, .reauthenticate(.credentialsInvalidated))
        let tokenRequestsAfter = await world.edge.requests(path: "/native/token/").count
        XCTAssertEqual(tokenRequestsAfter, tokenRequestsBefore, "nothing was sent, and nothing was inferred")
        let hasGrant = try await world.credentials.hasGrant()
        let state = await client.sessionState
        XCTAssertFalse(hasGrant)
        XCTAssertEqual(state, .unauthenticated)
    }

    func testRefreshOfARejectedGrantWipesTheSessionAndTheKey() async throws {
        let (world, client) = try await signedIn()
        await world.edge.setRefreshOverride(HTTPResponse(statusCode: 400, body: Data(#"{"error":"invalid_grant"}"#.utf8)))

        let error = await thrown { try await client.refresh() }

        XCTAssertEqual(error, .reauthenticate(.grantRejected))
        XCTAssertTrue(world.keys.isEmpty, "the key a rejected grant was bound to is destroyed")
        let remembered = await world.scopes.load()
        XCTAssertTrue(remembered.isEmpty)
    }

    // MARK: logout

    func testLogoutRevokesThroughEdgeEndsTheIssuersSessionInTheBrowserAndWipes() async throws {
        let (world, client) = try await signedIn()

        let outcome = await client.logout()

        XCTAssertEqual(outcome, LogoutOutcome(sessionEnded: true, tokenRevoked: true))
        let revoked = await world.edge.revoked
        XCTAssertEqual(revoked, ["rt-1"])
        let revokeRequests = await world.edge.requests(path: "/native/revoke/")
        let revoke = try XCTUnwrap(revokeRequests.first)
        XCTAssertEqual(ScriptedEdge.proofClaims(revoke)["htu"] as? String, Sdk.revocationEndpoint)
        XCTAssertEqual(ScriptedEdge.decode(revoke).map(\.0), ["token_type_hint", "token"])

        // The end-session page is the issuer's /logout, with the hint, the client, the return address and a state.
        let opened = await world.browser.opened
        let logout = try XCTUnwrap(opened.last)
        XCTAssertEqual("\(logout.scheme ?? "")://\(logout.host ?? "")\(logout.path)", Sdk.issuer + "/logout")
        let query = AuthorizationResponseValidator.parseQuery(logout)
        XCTAssertEqual(Set(query.keys), ["id_token_hint", "client_id", "post_logout_redirect_uri", "state"])
        XCTAssertEqual(query["client_id"], world.clientId)
        XCTAssertEqual(query["post_logout_redirect_uri"], Sdk.postLogout)

        // The wipe: credentials, the granted scope, the key. The endpoints are not credentials and stay.
        let hasGrant = try await world.credentials.hasGrant()
        let remembered = await world.scopes.load()
        let endpoints = try await world.endpoints.load()
        let state = await client.sessionState
        let claims = await client.claims
        XCTAssertFalse(hasGrant)
        XCTAssertTrue(remembered.isEmpty)
        XCTAssertTrue(world.keys.isEmpty)
        XCTAssertNotNil(endpoints)
        XCTAssertEqual(state, .unauthenticated)
        XCTAssertNil(claims)
    }

    func testLogoutWithoutEndSessionOpensNoBrowser() async throws {
        let (world, client) = try await signedIn()
        let openedBefore = await world.browser.opened.count

        let outcome = await client.logout(LogoutOptions(endSession: false))

        XCTAssertEqual(outcome, LogoutOutcome(sessionEnded: false, tokenRevoked: true))
        let openedAfter = await world.browser.opened.count
        XCTAssertEqual(openedAfter, openedBefore)
        let state = await client.sessionState
        XCTAssertEqual(state, .unauthenticated)
    }

    func testLogoutWithoutRevokeSendsNoRevocation() async throws {
        let (world, client) = try await signedIn()

        let outcome = await client.logout(LogoutOptions(revoke: false))

        XCTAssertEqual(outcome, LogoutOutcome(sessionEnded: true, tokenRevoked: false))
        let revokeRequests = await world.edge.requests(path: "/native/revoke/")
        XCTAssertTrue(revokeRequests.isEmpty)
    }

    func testTheWipeHappensWhateverTheServerSideStepsDid() async throws {
        let (world, client) = try await signedIn()
        await world.edge.setRevokeOverride(HTTPResponse(statusCode: 404))
        await world.browser.setEndSessionAnswers(false)

        let outcome = await client.logout()

        XCTAssertEqual(outcome, LogoutOutcome(sessionEnded: false, tokenRevoked: false))
        let hasGrant = try await world.credentials.hasGrant()
        let state = await client.sessionState
        XCTAssertFalse(hasGrant)
        XCTAssertEqual(state, .unauthenticated)
        XCTAssertTrue(world.keys.isEmpty)
    }

    // MARK: session()

    func testSessionAttachesTheTokenAndAProofToTheEdgeOriginOnly() async throws {
        let (world, client) = try await signedIn()
        StubURLProtocol.install { _ in (200, [:], Data("ok".utf8)) }
        let session = try client.session()

        let (_, edgeResponse) = try await session.data(for: URLRequest(url: URL(string: "https://id.example.com/resources/orders?x=1")!))
        let (_, otherResponse) = try await session.data(for: URLRequest(url: URL(string: "https://api.example.com/orders")!))

        XCTAssertEqual(edgeResponse.statusCode, 200)
        XCTAssertEqual(otherResponse.statusCode, 200)
        let requests = StubURLProtocol.requests
        XCTAssertEqual(requests.count, 2)
        let edge = requests[0], other = requests[1]
        XCTAssertEqual(edge.value(forHTTPHeaderField: "Authorization"), "DPoP at-1")
        let proof = try XCTUnwrap(edge.value(forHTTPHeaderField: "DPoP"))
        let claims = ScriptedEdge.proofClaims(header: proof)
        XCTAssertEqual(claims["htu"] as? String, "https://id.example.com/resources/orders", "the request URL without its query")
        XCTAssertNotNil(claims["ath"], "bound to the access token")
        XCTAssertNil(other.value(forHTTPHeaderField: "Authorization"), "another origin passes through untouched")
        XCTAssertNil(other.value(forHTTPHeaderField: "DPoP"))
        // And the token never went to the edge's native endpoints through this session.
        let native = await world.edge.requests(path: "/native/token/")
        XCTAssertTrue(native.isEmpty)
    }

    func testSessionDoesNotAttachTheTokenToAnotherPortSchemeOrHostOfTheEdge() async throws {
        let (_, client) = try await signedIn()
        StubURLProtocol.install { _ in (200, [:], Data()) }
        let session = try client.session()

        for url in ["https://id.example.com:8443/resources", "http://id.example.com/resources", "https://id.example.com.evil.example.net/resources", "https://sub.id.example.com/resources"] {
            _ = try await session.data(for: URLRequest(url: URL(string: url)!))
        }

        for request in StubURLProtocol.requests {
            XCTAssertNil(request.value(forHTTPHeaderField: "Authorization"), request.url?.absoluteString ?? "")
            XCTAssertNil(request.value(forHTTPHeaderField: "DPoP"), request.url?.absoluteString ?? "")
        }
    }

    func testSessionRaisesTheEdgesStepUpChallengeAsTheStepUpError() async throws {
        let (_, client) = try await signedIn()
        StubURLProtocol.install { _ in
            (401, ["WWW-Authenticate": #"Bearer error="insufficient_user_authentication", acr_values="sensitive", max_age="120""#], Data())
        }
        let session = try client.session()

        let error = await thrown { _ = try await session.data(for: URLRequest(url: URL(string: "https://id.example.com/resources/payments")!)) }

        XCTAssertEqual(error, .stepUp(acrValues: ["sensitive"], maxAge: 120))
        let state = await client.sessionState
        XCTAssertEqual(state, .stepUpRequired)
    }

    // MARK: redirect delivery

    func testHandleRedirectIsFalseWhenThereIsNoSystemBrowserToDeliverTo() async throws {
        let world = World()
        let client = try await world.create()
        let delivered = await client.handleRedirect(URL(string: "\(Sdk.redirect)?code=c&state=s")!)
        XCTAssertFalse(delivered, "the injected browser is not the system one")
    }
}

/// A credential store that stops answering reads when told to, as a Keychain does before first unlock.
final class LockedCredentials: CredentialStore, Sendable {
    private let wrapped: InMemoryCredentialStore
    private let isLocked = OSAllocatedLockedFlag()
    init(wrapping store: InMemoryCredentialStore) { wrapped = store }
    func lock() { isLocked.set(true) }
    private func guarded() throws { if isLocked.value { throw OAuthError.recoverable(.unlockRequired) } }
    func hasGrant() async throws -> Bool { try await wrapped.hasGrant() }
    func refreshToken() async throws -> String? { try guarded(); return try await wrapped.refreshToken() }
    func rawIdToken() async throws -> String? { try guarded(); return try await wrapped.rawIdToken() }
    func save(refreshToken: String, rawIdToken: String?) async throws { try await wrapped.save(refreshToken: refreshToken, rawIdToken: rawIdToken) }
    func saveRefreshed(refreshToken: String?, rawIdToken: String?) async throws { try await wrapped.saveRefreshed(refreshToken: refreshToken, rawIdToken: rawIdToken) }
    func savePendingRotation(_ idempotencyKey: String?) async throws { try await wrapped.savePendingRotation(idempotencyKey) }
    func pendingRotation() async throws -> String? { try await wrapped.pendingRotation() }
    func clear() async throws { try await wrapped.clear() }
}

import os

final class OSAllocatedLockedFlag: Sendable {
    private let flag = OSAllocatedUnfairLock(initialState: false)
    var value: Bool { flag.withLock { $0 } }
    func set(_ value: Bool) { flag.withLock { $0 = value } }
}
