import Foundation
import XCTest
@testable import OAuthClient
@testable import OAuthCore
@testable import VersolaEdge
@testable import VersolaSDK

/// `login()` end to end against a scripted edge and a scripted browser (`spec/versola-sdk-api.md`
/// sections 5, 7 and 9): the start form, the browser URL, no discovery and no key-set request, the redirect
/// checks before any token call, the claims-only ID-token checks, the state sequence. Scenarios 01, 15, 16,
/// 25 and 27's unit-tier twin; the wiring against a real stack is the conformance tier.
final class VersolaLoginTests: XCTestCase {
    override func setUp() async throws { await Versola.forgetAll() }
    override func tearDown() async throws { await Versola.forgetAll() }

    // MARK: the happy path

    func testLoginStartsThroughEdgeOpensTheAnsweredEndpointRedeemsThroughEdgeAndPublishesTheStatesInOrder() async throws {
        let world = World()
        // max_age is sent, so the ID token must carry an auth_time that satisfies it.
        await world.edge.setClaimOverrides(["auth_time": Int(Sdk.now.timeIntervalSince1970) - 5])
        let client = try await world.create()
        let states = StateRecorder()
        await states.start(await client.sessionStates())

        try await client.login(LoginOptions(scopes: ["email"], acrValues: ["sensitive"], maxAge: 300, loginHint: "alice@example.com"))

        await waitUntil("the recorder saw authenticated") { await states.states.last == .authenticated }
        await states.stop()
        let sequence = await states.states
        XCTAssertEqual(sequence, [.unauthenticated, .authorizing, .authenticated])

        // The start form.
        let starts = await world.edge.starts
        XCTAssertEqual(starts.count, 1)
        let form = Dictionary(grouping: starts[0].form, by: \.0).mapValues { $0.map(\.1) }
        XCTAssertEqual(form["redirect_uri"], [Sdk.redirect])
        XCTAssertEqual(form["scope"]?.first?.split(separator: " ").sorted(), ["email", "offline_access", "openid"])
        XCTAssertEqual(form["acr_values"], ["sensitive"])
        XCTAssertEqual(form["max_age"], ["300"])
        XCTAssertEqual(form["login_hint"], ["alice@example.com"])
        for forbidden in ["client_id", "state", "response_type", "code_challenge", "code_challenge_method", "dpop_jkt", "id_token_hint"] {
            XCTAssertNil(form[forbidden], forbidden)
        }

        // The browser: edge's endpoint with exactly client_id and request_uri.
        let opened = await world.browser.opened
        XCTAssertEqual(opened.count, 1)
        let components = try XCTUnwrap(URLComponents(url: opened[0], resolvingAgainstBaseURL: false))
        XCTAssertEqual("\(components.scheme ?? "")://\(components.host ?? "")\(components.path)", Sdk.authorizationEndpoint)
        XCTAssertEqual(components.queryItems?.map(\.name), ["client_id", "request_uri"])
        XCTAssertEqual(components.queryItems?.first { $0.name == "request_uri" }?.value, "urn:ietf:params:oauth:request_uri:v1.kz-1.AbC_d-9")
        let browserOptions = await world.browser.options
        XCTAssertEqual(browserOptions.first?.expectedState, "edge-state-1")
        XCTAssertEqual(browserOptions.first?.ephemeral, false)
        XCTAssertEqual(browserOptions.first?.redirectURI?.absoluteString, Sdk.redirect)

        // The completion: the four members, the opaque values byte for byte, proof for auth's endpoint.
        let completes = await world.edge.completes
        XCTAssertEqual(completes.count, 1)
        XCTAssertEqual(completes[0].map(\.0), ["code", "state", "iss", "blob"])
        XCTAssertEqual(completes[0].map(\.1), ["v1.kz-2.Zz+/=", "edge-state-1", Sdk.issuer, "v1.kz-1.blob-1"])
        let completeRequests = await world.edge.requests(path: "/native/complete/")
        let complete = try XCTUnwrap(completeRequests.first)
        XCTAssertEqual(ScriptedEdge.proofClaims(complete)["htu"] as? String, Sdk.tokenEndpoint)
        let startRequests = await world.edge.requests(path: "/native/start/")
        let start = try XCTUnwrap(startRequests.first)
        XCTAssertEqual(ScriptedEdge.proofClaims(start)["htu"] as? String, "https://id.example.com/native/start/\(world.clientId)")

        // Only edge's native endpoints were called: no discovery, no key set, no token endpoint of the issuer.
        let paths = await world.edge.paths()
        XCTAssertEqual(paths, ["/native/start/\(world.clientId)", "/native/complete/\(world.clientId)"])

        // The claims, the stores.
        let claims = await client.claims
        XCTAssertEqual(claims?.subject, "alice")
        XCTAssertEqual(claims?.issuer, Sdk.issuer)
        let refresh = try await world.credentials.refreshToken()
        XCTAssertEqual(refresh, "rt-1")
        let stored = try await world.endpoints.load()
        XCTAssertEqual(stored, EdgeNativeEndpoints(tokenEndpoint: Sdk.tokenEndpoint, revocationEndpoint: Sdk.revocationEndpoint))
        let pending = try await world.pending.load()
        XCTAssertNil(pending, "the pending request is wiped once the grant is stored")
        let remembered = await world.scopes.load()
        XCTAssertEqual(remembered, ["openid", "offline_access"], "the response's own scope")
    }

    func testTheKeyAttestationIsTheTierReadBackFromTheKey() async throws {
        let world = World()
        let client = try await world.create()
        let before = try await client.keyAttestation()
        XCTAssertEqual(before?.tier, .software, "asking generates the key, and the tier is read back from it")
        XCTAssertFalse(world.keys.isEmpty)
    }

    func testRequireHardwareKeyRefusesBeforeAnyRequestToEdge() async throws {
        let world = World()
        let client = try await world.create(try world.configuration(requireHardwareKey: true))

        let error = await thrown { try await client.login() }

        guard case .configuration(.hardwareBindingUnavailable)? = error else { return XCTFail("\(String(describing: error))") }
        let requests = await world.edge.requests
        XCTAssertEqual(requests.count, 0, "before /native/start")
        let opened = await world.browser.opened
        XCTAssertTrue(opened.isEmpty)
        let state = await client.sessionState
        XCTAssertEqual(state, .unauthenticated)
    }

    func testEveryRequestOfALoginCarriesExactlyOneProofAndNoCredentialHeader() async throws {
        let world = World()
        let client = try await world.create()
        try await client.login()
        for request in await world.edge.requests {
            XCTAssertNotNil(request.headers["DPoP"], request.url.path)
            XCTAssertNil(request.headers["Authorization"], request.url.path)
        }
    }

    // MARK: the redirect is judged before any network call

    func testIssThatIsNotTheConfiguredIssuerIsAnIssuerMismatchWithNoCompleteRequest() async throws {
        let world = World()
        await world.browser.setRedirectIss("https://evil.example.com")
        let client = try await world.create()

        let error = await thrown { try await client.login() }

        XCTAssertEqual(error, .configuration(.issuerMismatch(expected: Sdk.issuer, received: "https://evil.example.com")))
        let completes = await world.edge.requests(path: "/native/complete/")
        XCTAssertTrue(completes.isEmpty)
        let state = await client.sessionState
        XCTAssertEqual(state, .unauthenticated)
        let pending = try await world.pending.load()
        XCTAssertNil(pending)
    }

    func testAnIssThatIsMissingIsAnIssuerMismatchBecauseThisFacadeAlwaysRequiresIt() async throws {
        let world = World()
        await world.browser.setRedirectIss(nil)
        let client = try await world.create()

        let error = await thrown { try await client.login() }

        XCTAssertEqual(error, .configuration(.issuerMismatch(expected: Sdk.issuer, received: nil)))
        let completes = await world.edge.requests(path: "/native/complete/")
        XCTAssertTrue(completes.isEmpty, "no code is spent on a redirect that carries no iss")
    }

    func testAnIssDifferingOnlyByATrailingSlashIsAnotherIssuer() async throws {
        let world = World()
        await world.browser.setRedirectIss(Sdk.issuer + "/")
        let client = try await world.create()

        let error = await thrown { try await client.login() }

        XCTAssertEqual(error, .configuration(.issuerMismatch(expected: Sdk.issuer, received: Sdk.issuer + "/")))
        let completes = await world.edge.requests(path: "/native/complete/")
        XCTAssertTrue(completes.isEmpty)
    }

    func testAnIssuerConfiguredWithATrailingSlashSignsInWhenTheRedirectAndTheIdTokenCarryIt() async throws {
        let world = World()
        let slashed = Sdk.issuer + "/"
        await world.browser.setRedirectIss(slashed)
        await world.edge.setIdTokenIssuer(slashed)
        let client = try await world.create(try world.configuration(issuer: slashed))

        try await client.login()

        let claims = await client.claims
        XCTAssertEqual(claims?.issuer, slashed)
        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
    }

    func testAnIssuerConfiguredWithATrailingSlashFailsWhenTheRedirectDoesNotCarryIt() async throws {
        let world = World()
        let slashed = Sdk.issuer + "/"
        await world.edge.setIdTokenIssuer(slashed)
        let client = try await world.create(try world.configuration(issuer: slashed))

        let error = await thrown { try await client.login() }

        XCTAssertEqual(error, .configuration(.issuerMismatch(expected: slashed, received: Sdk.issuer)))
        let completes = await world.edge.requests(path: "/native/complete/")
        XCTAssertTrue(completes.isEmpty)
    }

    func testAnIssuerConfiguredWithATrailingSlashFailsWhenTheIdTokenDoesNotCarryIt() async throws {
        let world = World()
        let slashed = Sdk.issuer + "/"
        await world.browser.setRedirectIss(slashed)
        await world.edge.setIdTokenIssuer(Sdk.issuer)
        let client = try await world.create(try world.configuration(issuer: slashed))

        let error = await thrown { try await client.login() }

        XCTAssertEqual(error, .configuration(.idTokenRejected(.issuer)), "the issuer as configured, not a trimmed copy")
        let hasGrant = try await world.credentials.hasGrant()
        XCTAssertFalse(hasGrant)
    }

    func testAPartnersIssuerIsIndependentOfTheEdge() async throws {
        let world = World()
        let operatorIssuer = "https://operator.example.org"
        await world.browser.setRedirectIss(operatorIssuer)
        await world.edge.setIdTokenIssuer(operatorIssuer)
        let client = try await world.create(try world.configuration(edgeUrl: "https://partner-edge.example.com", issuer: operatorIssuer))

        try await client.login()

        let claims = await client.claims
        XCTAssertEqual(claims?.issuer, operatorIssuer)
    }

    // MARK: the ID token

    func testAnIdTokenThatFailsAnyClaimCheckLeavesNothingStoredAndRevokesWhatWasIssued() async throws {
        let at = Int(Sdk.now.timeIntervalSince1970)
        let cases: [(String, [String: Sendable?], IdTokenRejection)] = [
            ("wrong nonce", ["nonce": "someone-elses"], .nonce),
            ("missing nonce", ["nonce": nil], .nonce),
            ("wrong audience", ["aud": "another-client"], .audience),
            ("wrong issuer", ["iss": "https://evil.example.com"], .issuer),
            ("expired", ["exp": at - 3600], .expired),
            ("issued in the future", ["iat": at + 3600], .issuedAt),
            ("missing sub", ["sub": nil], .malformed),
        ]
        for (name, overrides, reason) in cases {
            let world = World()
            await world.edge.setClaimOverrides(overrides)
            let client = try await world.create()

            let error = await thrown { try await client.login() }

            XCTAssertEqual(error, .configuration(.idTokenRejected(reason)), name)
            let hasGrant = try await world.credentials.hasGrant()
            let idToken = try await world.credentials.rawIdToken()
            let claims = await client.claims
            let state = await client.sessionState
            let pending = try await world.pending.load()
            let remembered = await world.scopes.load()
            XCTAssertFalse(hasGrant, name)
            XCTAssertNil(idToken, name)
            XCTAssertNil(claims, name)
            XCTAssertEqual(state, .unauthenticated, name)
            XCTAssertNil(pending, name)
            XCTAssertTrue(remembered.isEmpty, name)
            // The refresh token the edge issued to a login nobody holds is revoked, best effort and detached.
            await waitUntil("\(name): the refresh token is revoked") { await world.edge.revoked == ["rt-1"] }
            await Versola.forgetAll()
        }
    }

    func testAnAtHashThatDoesNotMatchTheAccessTokenIsRejected() async throws {
        let world = World()
        await world.edge.setClaimOverrides(["at_hash": "AAAAAAAAAAAAAAAAAAAAAA"])
        let client = try await world.create()

        let error = await thrown { try await client.login() }

        XCTAssertEqual(error, .configuration(.idTokenRejected(.accessTokenHash)))
        let hasGrant = try await world.credentials.hasGrant()
        XCTAssertFalse(hasGrant)
    }

    func testAResponseWithoutAnIdTokenIsRejectedAsMalformed() async throws {
        let world = World()
        await world.edge.setIncludeIdToken(false)
        let client = try await world.create()

        let error = await thrown { try await client.login() }

        XCTAssertEqual(error, .configuration(.idTokenRejected(.malformed)))
        let hasGrant = try await world.credentials.hasGrant()
        XCTAssertFalse(hasGrant)
    }

    func testMaxAgeChecksTheIdTokensAuthTime() async throws {
        let at = Int(Sdk.now.timeIntervalSince1970)
        let stale = World()
        await stale.edge.setClaimOverrides(["auth_time": at - 3600])
        let staleError = await thrown { try await stale.create().login(LoginOptions(maxAge: 60)) }
        XCTAssertEqual(staleError, .configuration(.idTokenRejected(.authTime)))

        await Versola.forgetAll()
        let missing = World()
        let missingError = await thrown { try await missing.create().login(LoginOptions(maxAge: 60)) }
        XCTAssertEqual(missingError, .configuration(.idTokenRejected(.authTime)), "max_age without an auth_time")

        await Versola.forgetAll()
        let fresh = World()
        await fresh.edge.setClaimOverrides(["auth_time": at - 10])
        let client = try await fresh.create()
        try await client.login(LoginOptions(maxAge: 60))
        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
    }

    func testAResponseWithoutAnyRefreshTokenIsRefusedBecauseTheFacadeIsASession() async throws {
        let world = World()
        await world.edge.setCompleteOverride(HTTPResponse(statusCode: 200, headers: ["Content-Type": "application/json"], body: Data(#"{"access_token":"at","token_type":"DPoP","expires_in":300}"#.utf8)))
        let client = try await world.create()

        let error = await thrown { try await client.login() }

        guard case .configuration(.idTokenRejected)? = error else { return XCTFail("\(String(describing: error))") }
        let hasGrant = try await world.credentials.hasGrant()
        XCTAssertFalse(hasGrant)
    }

    // MARK: edge's refusals

    func testEdgeAnswering404ToTheStartNamesTheClientItDoesNotFront() async throws {
        let world = World()
        await world.edge.setStartOverride(HTTPResponse(statusCode: 404))
        let client = try await world.create()

        let error = await thrown { try await client.login() }

        XCTAssertEqual(error, .configuration(.facade(name: "edge_client_unknown", detail: world.clientId)))
        XCTAssertEqual(error?.code, "configuration.edge_client_unknown")
        let opened = await world.browser.opened
        XCTAssertTrue(opened.isEmpty)
        let state = await client.sessionState
        XCTAssertEqual(state, .unauthenticated)
    }

    func testInvalidGrantAtCompleteIsGrantRejectedAndLeavesNothingStored() async throws {
        let world = World()
        await world.edge.setCompleteOverride(HTTPResponse(statusCode: 400, body: Data(#"{"error":"invalid_grant"}"#.utf8)))
        let client = try await world.create()

        let error = await thrown { try await client.login() }

        XCTAssertEqual(error, .reauthenticate(.grantRejected))
        let hasGrant = try await world.credentials.hasGrant()
        let endpoints = try await world.endpoints.load()
        XCTAssertFalse(hasGrant)
        XCTAssertNil(endpoints, "nothing is remembered from a completion that failed")
    }

    func testACompletionAnsweredWith503IsNeverRepeatedAndCarriesEdgesRetryAfter() async throws {
        let world = World()
        await world.edge.setCompleteOverride(HTTPResponse(statusCode: 503, headers: ["Retry-After": "1"]))
        let client = try await world.create()

        let error = await thrown { try await client.login() }

        guard case .recoverable(.server(503, 1000, _, _))? = error else { return XCTFail("\(String(describing: error))") }
        let completes = await world.edge.requests(path: "/native/complete/")
        XCTAssertEqual(completes.count, 1, "a spent code is never replayed")
    }

    // MARK: the lifetime

    func testLoginWhoseBrowserOutlivesTheLifetimeEdgeGaveEndsAsPendingRequestExpired() async throws {
        let world = World()
        // The clock edge's `expires_in` is measured on moves past it while the sheet is up: the wait ends at the expiry.
        let gate = Gate()
        await world.browser.hold(gate)
        let clock = SteppingClock()
        let wiring = Versola.Wiring(
            browser: world.browser, credentialStore: world.credentials, pendingStore: world.pending, endpointsStore: world.endpoints,
            grantedScopeStore: world.scopes, httpClient: world.edge,
            makeDpopKey: { requireHardware, logger, isGrantHeld in
                SecureEnclaveDpopKey(store: world.keys, requireHardware: requireHardware, logger: logger, secureEnclaveAvailable: false, isGrantHeld: isGrantHeld)
            },
            clock: clock.clock
        )
        let client = try await Versola.create(configuration: try world.configuration(), wiring: wiring)

        async let outcome: OAuthError? = thrown { try await client.login() }
        await waitUntil("the browser is up") { await world.browser.opened.count == 1 }
        clock.advance(91)
        await gate.open()

        let error = await outcome
        XCTAssertEqual(error, .recoverable(.pendingRequestExpired), "a redirect after expires_in is not redeemed")
        let completes = await world.edge.requests(path: "/native/complete/")
        XCTAssertTrue(completes.isEmpty, "the facade does not spend a request to learn that edge would refuse it")
        let state = await client.sessionState
        let pending = try await world.pending.load()
        XCTAssertEqual(state, .unauthenticated)
        XCTAssertNil(pending)
    }
}

/// A wall clock the test moves, for a deadline measured against it.
final class SteppingClock: Sendable {
    private let offset = OSAllocatedUnfairLockBox()
    var clock: Clock { Clock(now: { Sdk.now.addingTimeInterval(self.offset.value) }) }
    func advance(_ seconds: TimeInterval) { offset.add(seconds) }
}

import os

final class OSAllocatedUnfairLockBox: Sendable {
    private let seconds = OSAllocatedUnfairLock(initialState: 0.0)
    var value: TimeInterval { seconds.withLock { $0 } }
    func add(_ delta: TimeInterval) { seconds.withLock { $0 += delta } }
}
