import CryptoKit
import Foundation
import os
import XCTest
@testable import OAuthClient

/// The facade end to end over a stubbed provider: discovery, PAR off, the browser leg replaced by
/// a fake that answers the redirect, the code exchange, ID-token validation against the stub's
/// JWKS, the authenticated call, UserInfo, and sign-out. The Android `OAuthClientTest`'s twin.
final class OAuthClientTests: XCTestCase {
    private static let issuer = "https://id.example.com"
    private static let redirect = "https://app.example.com/oauth"
    private static let key = P256.Signing.PrivateKey()

    /// Answers the authorization request with a redirect for its `state`, remembering the nonce.
    actor FakeBrowser: BrowserAuthorizationSession {
        var opened: [URL] = []
        var options: [BrowserSessionOptions] = []
        var nonce: String?
        func authorize(_ uri: URL, options: BrowserSessionOptions) async throws -> BrowserOutcome {
            opened.append(uri)
            self.options.append(options)
            let query = AuthorizationResponseValidator.parseQuery(uri)
            if uri.path.hasSuffix("/logout") {
                return .redirect(URL(string: "https://app.example.com/signed-out?state=\(query["state"] ?? "")")!)
            }
            nonce = query["nonce"]
            return .redirect(URL(string: "\(OAuthClientTests.redirect)?code=the-code&state=\(query["state"] ?? "")&iss=\(OAuthClientTests.issuer)")!)
        }
        func awaitPendingRedirect() async throws -> BrowserOutcome { throw CancellationError() }
        /// What the provider's token stub echoes into the ID token, for a login this browser did not open.
        func remember(nonce: String) { self.nonce = nonce }
    }

    /// The browser of a process the redirect cold-started: nothing is opened, and the redirect
    /// the system delivers through `handleRedirect` arrives when the test calls `release()`, as
    /// it does on a device, after the app has launched and observed `authorizing`.
    final class ColdStartBrowser: BrowserAuthorizationSession, Sendable {
        private let outcome: BrowserOutcome
        private let state = OSAllocatedUnfairLock(initialState: (awaited: 0, cancelled: 0))
        private let gate = AsyncStream.makeStream(of: Void.self)
        init(_ outcome: BrowserOutcome) { self.outcome = outcome }
        var awaited: Int { state.withLock { $0.awaited } }
        /// How many waits for the redirect ended because their task was cancelled.
        var cancelled: Int { state.withLock { $0.cancelled } }
        func authorize(_ uri: URL, options: BrowserSessionOptions) async throws -> BrowserOutcome {
            throw CancellationError()
        }
        func awaitPendingRedirect() async throws -> BrowserOutcome {
            state.withLock { $0.awaited += 1 }
            for await _ in gate.stream { break }
            if Task.isCancelled {
                state.withLock { $0.cancelled += 1 }
                throw CancellationError()
            }
            return outcome
        }
        func release() { gate.continuation.yield() }
    }

    /// A pending store whose first `load()` fails, as the Keychain does before the first unlock.
    actor FlakyPendingStore: PendingAuthorizationStore {
        private let underlying = InMemoryPendingAuthorizationStore()
        private var failures: Int
        init(failFirstLoads: Int) { failures = failFirstLoads }
        func save(_ request: PendingAuthorizationRequest) async throws { try await underlying.save(request) }
        func load() async throws -> PendingAuthorizationRequest? {
            if failures > 0 {
                failures -= 1
                throw OAuthError.recoverable(.unlockRequired)
            }
            return try await underlying.load()
        }
        func clear() async throws { try await underlying.clear() }
    }

    /// A logger that hands each warning to the test as it is written, so a test waits for it.
    final class SignalingLogger: OAuthLogger, Sendable {
        private let channel = AsyncStream.makeStream(of: String.self)
        var warnings: AsyncStream<String> { channel.stream }
        func info(_ message: String) {}
        func warn(_ message: String) { channel.continuation.yield(message) }
    }

    /// Polls, yielding between looks; bounded, so a regression fails instead of hanging.
    private func waitForState(_ expected: SessionState, of client: OAuthClient, file: StaticString = #filePath, line: UInt = #line) async {
        for _ in 0..<2_000_000 {
            if await client.sessionState == expected { return }
            await Task.yield()
        }
        XCTFail("timed out waiting for \(expected)", file: file, line: line)
    }

    private func tokenRequests() -> Int { StubURLProtocol.requests.filter { $0.url?.path == "/token" }.count }

    private static func jwks() -> String {
        let x963 = key.publicKey.x963Representation
        let x = x963[1..<33].base64URL, y = x963[33..<65].base64URL
        return #"{"keys":[{"kty":"EC","crv":"P-256","kid":"k1","alg":"ES256","use":"sig","x":"\#(x)","y":"\#(y)"}]}"#
    }

    private static func idToken(nonce: String, subject: String = "alice", audience: String) -> String {
        let now = Int(Date().timeIntervalSince1970)
        let header = Data(#"{"alg":"ES256","kid":"k1","typ":"JWT"}"#.utf8).base64URL
        let payload = Data(#"{"iss":"\#(issuer)","sub":"\#(subject)","aud":"\#(audience)","exp":\#(now + 3600),"iat":\#(now),"nonce":"\#(nonce)","auth_time":\#(now)}"#.utf8).base64URL
        let signature = try! key.signature(for: Data("\(header).\(payload)".utf8)).rawRepresentation.base64URL
        return "\(header).\(payload).\(signature)"
    }

    private static func discovery(endSession: Bool = true) -> String {
        var members = [
            #""issuer":"\#(issuer)""#, #""authorization_endpoint":"\#(issuer)/authorize""#, #""token_endpoint":"\#(issuer)/token""#,
            #""jwks_uri":"\#(issuer)/jwks""#, #""userinfo_endpoint":"\#(issuer)/userinfo""#, #""revocation_endpoint":"\#(issuer)/revoke""#,
            #""code_challenge_methods_supported":["S256"]"#, #""id_token_signing_alg_values_supported":["ES256"]"#,
        ]
        if endSession { members.append(#""end_session_endpoint":"\#(issuer)/logout""#) }
        return "{" + members.joined(separator: ",") + "}"
    }

    private var browser = FakeBrowser()
    private let logger = RecordingLogger()
    private var clientId = "mobile-\(UUID().uuidString.prefix(8))"

    override func setUp() async throws {
        browser = FakeBrowser()
        clientId = "mobile-\(UUID().uuidString.prefix(8))"
        let browser = self.browser
        let clientId = self.clientId
        StubURLProtocol.install { request in
            let path = request.url!.path
            let json = ["Content-Type": "application/json"]
            switch path {
            case "/.well-known/openid-configuration": return .response(status: 200, headers: json, body: Data(Self.discovery().utf8))
            case "/jwks": return .response(status: 200, headers: json, body: Data(Self.jwks().utf8))
            case "/token":
                let nonce = Self.blockingNonce(browser)
                let body = #"{"access_token":"at","token_type":"Bearer","expires_in":3600,"refresh_token":"rt","id_token":"\#(Self.idToken(nonce: nonce, audience: clientId))"}"#
                return .response(status: 200, headers: json, body: Data(body.utf8))
            case "/userinfo": return .response(status: 200, headers: json, body: Data(#"{"sub":"alice","name":"Alice"}"#.utf8))
            case "/revoke": return .response(status: 200)
            case "/api": return .response(status: 200, body: Data("ok".utf8))
            default: return .response(status: 404)
            }
        }
        await OAuthClient.forgetAll()
    }

    override func tearDown() {
        StubURLProtocol.reset()
    }

    /// The stub handler is synchronous; the nonce the browser saw is read through a semaphore.
    private static func blockingNonce(_ browser: FakeBrowser) -> String {
        let semaphore = DispatchSemaphore(value: 0)
        let box = OSAllocatedUnfairLock(initialState: "")
        Task { let nonce = await browser.nonce ?? ""; box.withLock { $0 = nonce }; semaphore.signal() }
        semaphore.wait()
        return box.withLock { $0 }
    }

    private func configuration(scopes: Set<String> = ["openid", "profile"], logger: any OAuthLogger) throws -> OAuthConfiguration {
        try OAuthConfiguration(
            issuer: Self.issuer, clientId: clientId, redirectUri: Self.redirect,
            postLogoutRedirectUri: "https://app.example.com/signed-out", scopes: scopes,
            pushedAuthorization: .never, protectedOrigins: ["https://api.example.com"],
            logger: logger, urlSession: StubURLProtocol.session()
        )
    }

    private func configuration(scopes: Set<String> = ["openid", "profile"]) throws -> OAuthConfiguration {
        try configuration(scopes: scopes, logger: logger)
    }

    private func client() async throws -> OAuthClient {
        try await OAuthClient.create(configuration: try configuration(), browser: browser, credentialStore: InMemoryCredentialStore(), pendingStore: InMemoryPendingAuthorizationStore())
    }

    func testLoginCallUserInfoAndLogoutAgainstTheStubbedProvider() async throws {
        let client = try await client()

        try await client.login()

        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
        let claims = await client.claims
        XCTAssertEqual(claims?.subject, "alice")
        let opened = await browser.opened
        XCTAssertEqual(opened.count, 1)
        XCTAssertTrue(opened[0].absoluteString.hasPrefix("\(Self.issuer)/authorize?"))
        let query = AuthorizationResponseValidator.parseQuery(opened[0])
        XCTAssertEqual(query["response_type"], "code")
        XCTAssertEqual(query["code_challenge_method"], "S256")
        XCTAssertEqual(query["scope"], "openid profile")
        let token = StubURLProtocol.requests.first { $0.url?.path == "/token" }!
        let form = String(data: token.httpBody ?? token.httpBodyStream.map { stream -> Data in
            stream.open(); defer { stream.close() }
            var data = Data(); var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable { let n = stream.read(&buffer, maxLength: buffer.count); if n <= 0 { break }; data.append(buffer, count: n) }
            return data
        } ?? Data(), encoding: .utf8) ?? ""
        XCTAssertTrue(form.contains("grant_type=authorization_code"))
        XCTAssertTrue(form.contains("code_verifier="))
        XCTAssertFalse(form.contains("client_secret"))
        XCTAssertNil(token.value(forHTTPHeaderField: "Idempotency-Key"))
        XCTAssertEqual(StubURLProtocol.requests.filter { $0.url?.path == "/.well-known/openid-configuration" }.count, 1)

        let session = try client.authenticatedSession()
        let (data, response) = try await session.data(for: URLRequest(url: URL(string: "https://api.example.com/api")!))
        XCTAssertEqual(response.statusCode, 200)
        XCTAssertEqual(String(decoding: data, as: UTF8.self), "ok")
        let api = StubURLProtocol.requests.last { $0.url?.path == "/api" }!
        XCTAssertEqual(api.value(forHTTPHeaderField: "Authorization"), "Bearer at")

        let userInfo = try await client.userInfo()
        XCTAssertEqual(userInfo.subject, "alice")

        let outcome = await client.logout()

        XCTAssertEqual(outcome, LogoutOutcome(sessionEnded: true, tokenRevoked: true))
        let after = await client.sessionState
        XCTAssertEqual(after, .unauthenticated)
        let endSession = await browser.opened.last!
        XCTAssertTrue(endSession.absoluteString.hasPrefix("\(Self.issuer)/logout?"))
        XCTAssertNotNil(AuthorizationResponseValidator.parseQuery(endSession)["id_token_hint"])
    }

    func testEphemeralBrowserReachesTheSessionAndIsOffByDefault() async throws {
        let client = try await client()
        try await client.login()
        _ = await client.logout()
        try await client.login(try LoginOptions(ephemeralBrowser: true))

        let options = await browser.options
        XCTAssertEqual(options.map(\.ephemeral), [false, false, true])
        XCTAssertEqual(options.first?.redirectURI?.absoluteString, Self.redirect)
    }

    func testCreateReturnsOneClientPerConfigurationAndRefusesADifferentOne() async throws {
        let first = try await client()
        let again = try await OAuthClient.create(configuration: try configuration(), browser: browser, credentialStore: InMemoryCredentialStore(), pendingStore: InMemoryPendingAuthorizationStore())
        XCTAssertTrue(first === again)
        do {
            _ = try await OAuthClient.create(configuration: try configuration(scopes: ["openid", "email"]), browser: browser, credentialStore: InMemoryCredentialStore(), pendingStore: InMemoryPendingAuthorizationStore())
            XCTFail("no error")
        } catch let error as OAuthError {
            guard case .configuration(.invalidConfiguration) = error else { return XCTFail("\(error)") }
        }
    }

    // MARK: - A redirect delivered to a cold-started process (scenario 12)

    private func coldStartedClient(
        redirect: String, logger: (any OAuthLogger)? = nil, failFirstPendingLoads: Int = 0
    ) async throws -> (OAuthClient, ColdStartBrowser) {
        let pendingStore = FlakyPendingStore(failFirstLoads: failFirstPendingLoads)
        try await pendingStore.save(PendingAuthorizationRequest(
            state: "cold-state", nonce: "cold-nonce", codeVerifier: String(repeating: "v", count: 43),
            scopes: ["openid"], redirectUri: Self.redirect, createdAt: Date().addingTimeInterval(-30)
        ))
        await browser.remember(nonce: "cold-nonce")
        let cold = ColdStartBrowser(.redirect(URL(string: redirect)!))
        let client = try await OAuthClient.create(configuration: try configuration(logger: logger ?? self.logger), browser: cold, credentialStore: InMemoryCredentialStore(), pendingStore: pendingStore)
        return (client, cold)
    }

    func testResumePendingAuthorizationCompletesTheSignInOfAColdStartedProcess() async throws {
        let (client, cold) = try await coldStartedClient(redirect: "\(Self.redirect)?code=the-code&state=cold-state&iss=\(Self.issuer)")
        let before = await client.sessionState
        XCTAssertEqual(before, .authorizing, "the app observes authorizing on cold start, never unauthenticated")

        // The app's call is optional now: `create` already started the same work, and this one
        // joins it, so the single-use code is exchanged once.
        let resume = Task { try await client.resumePendingAuthorization() }
        await cold.release()
        try await resume.value

        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
        let claims = await client.claims
        XCTAssertEqual(claims?.subject, "alice")
        let token = try await client.accessToken()
        XCTAssertEqual(token.value, "at")
        let awaited = cold.awaited
        XCTAssertEqual(awaited, 1)
        XCTAssertEqual(tokenRequests(), 1)
    }

    func testCreateAloneFinishesTheSignInOfAColdStartedProcess() async throws {
        let (client, cold) = try await coldStartedClient(redirect: "\(Self.redirect)?code=the-code&state=cold-state&iss=\(Self.issuer)")
        let before = await client.sessionState
        XCTAssertEqual(before, .authorizing, "the app observes authorizing on cold start, never unauthenticated")
        XCTAssertEqual(tokenRequests(), 0, "no redirect has arrived, so nothing is exchanged")

        // The app never calls resumePendingAuthorization(): the redirect is all it hands over.
        await cold.release()
        await waitForState(.authenticated, of: client)

        let claims = await client.claims
        XCTAssertEqual(claims?.subject, "alice")
        let token = try await client.accessToken()
        XCTAssertEqual(token.value, "at")
        let awaited = cold.awaited
        XCTAssertEqual(awaited, 1)
        XCTAssertEqual(tokenRequests(), 1)
    }

    func testResumePendingAuthorizationAfterTheBackgroundResumeFinishedDoesNotExchangeTheCodeAgain() async throws {
        let (client, cold) = try await coldStartedClient(redirect: "\(Self.redirect)?code=the-code&state=cold-state&iss=\(Self.issuer)")
        await cold.release()
        await waitForState(.authenticated, of: client)

        try await client.resumePendingAuthorization()

        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
        XCTAssertEqual(tokenRequests(), 1, "the code is single-use: the late call must not exchange it again")
        let awaited = cold.awaited
        XCTAssertEqual(awaited, 1)
    }

    func testResumePendingAuthorizationCalledTwiceWhileTheBackgroundResumeRunsExchangesTheCodeOnce() async throws {
        let (client, cold) = try await coldStartedClient(redirect: "\(Self.redirect)?code=the-code&state=cold-state&iss=\(Self.issuer)")

        let first = Task { try await client.resumePendingAuthorization() }
        let second = Task { try await client.resumePendingAuthorization() }
        await cold.release()
        try await first.value
        try await second.value

        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
        XCTAssertEqual(tokenRequests(), 1)
        let awaited = cold.awaited
        XCTAssertEqual(awaited, 1)
    }

    func testACancelledExplicitCallStopsWaitingAndLeavesTheBackgroundResumeRunning() async throws {
        let (client, cold) = try await coldStartedClient(redirect: "\(Self.redirect)?code=the-code&state=cold-state&iss=\(Self.issuer)")

        let explicit = Task { try await client.resumePendingAuthorization() }
        explicit.cancel()
        do {
            try await explicit.value
            XCTFail("expected a cancellation")
        } catch {
            XCTAssertTrue(error is CancellationError, "\(error)")
        }

        await cold.release()
        await waitForState(.authenticated, of: client)
        XCTAssertEqual(tokenRequests(), 1)
    }

    func testASecondCreateReturnsTheSameClientAndDoesNotStartAnotherResume() async throws {
        let (client, cold) = try await coldStartedClient(redirect: "\(Self.redirect)?code=the-code&state=cold-state&iss=\(Self.issuer)")

        let again = try await OAuthClient.create(configuration: try configuration(), browser: cold, credentialStore: InMemoryCredentialStore(), pendingStore: InMemoryPendingAuthorizationStore())
        XCTAssertTrue(again === client)
        await cold.release()
        await waitForState(.authenticated, of: client)

        let awaited = cold.awaited
        XCTAssertEqual(awaited, 1)
        XCTAssertEqual(tokenRequests(), 1)
    }

    func testCreateWithNothingPendingWaitsForNoRedirectAndMakesNoRequest() async throws {
        let cold = ColdStartBrowser(.redirect(URL(string: "\(Self.redirect)?code=the-code&state=cold-state")!))
        let client = try await OAuthClient.create(configuration: try configuration(), browser: cold, credentialStore: InMemoryCredentialStore(), pendingStore: InMemoryPendingAuthorizationStore())

        let state = await client.sessionState
        XCTAssertEqual(state, .unauthenticated)
        // `create` has finished restoring by the time it returns, so nothing can still be starting.
        let awaited = cold.awaited
        XCTAssertEqual(awaited, 0, "no authorization is pending, so nothing waits for a redirect")
        XCTAssertTrue(StubURLProtocol.requests.isEmpty)
    }

    func testAFailedBackgroundResumeSettlesTheStateAndIsLoggedWithoutTheRedirectsSecrets() async throws {
        let signal = SignalingLogger()
        let (client, cold) = try await coldStartedClient(redirect: "\(Self.redirect)?code=the-code&state=forged&iss=\(Self.issuer)", logger: signal)
        cold.release()

        var line: String?
        for await warning in signal.warnings where warning.contains("resuming the pending authorization failed") {
            line = warning
            break
        }

        let logged = try XCTUnwrap(line)
        for secret in ["the-code", "forged", "cold-state", "cold-nonce"] {
            XCTAssertFalse(logged.contains(secret), "the log line must not carry \(secret)")
        }
        await waitForState(.unauthenticated, of: client)
        XCTAssertEqual(tokenRequests(), 0)
    }

    func testARestoreThatFailedAtLaunchStartsTheResumeWhenALaterOneSucceeds() async throws {
        // The Keychain refuses the first read, as before the first unlock.
        let (client, cold) = try await coldStartedClient(
            redirect: "\(Self.redirect)?code=the-code&state=cold-state&iss=\(Self.issuer)", failFirstPendingLoads: 1
        )
        let waiting = cold.awaited
        XCTAssertEqual(waiting, 0, "nothing was restored, so nothing waits yet")

        // The next read succeeds, publishes `authorizing` and, with it, starts the resume.
        let state = await client.sessionState
        XCTAssertEqual(state, .authorizing)
        cold.release()
        await waitForState(.authenticated, of: client)

        XCTAssertEqual(tokenRequests(), 1)
        XCTAssertEqual(cold.awaited, 1)
    }

    func testLogoutDuringAResumeThatWaitsForItsRedirectDoesNotWaitForIt() async throws {
        let (client, cold) = try await coldStartedClient(redirect: "\(Self.redirect)?code=the-code&state=cold-state&iss=\(Self.issuer)")
        let before = await client.sessionState
        XCTAssertEqual(before, .authorizing)

        // The redirect never comes. Logout (with the provider's end-session step, which needs the
        // flow's gate) must return rather than wait out the request's ten minutes.
        let outcome = await client.logout(LogoutOptions(endSession: true, revoke: false))

        XCTAssertFalse(outcome.tokenRevoked)
        let after = await client.sessionState
        XCTAssertEqual(after, .unauthenticated)
        XCTAssertEqual(cold.cancelled, 1, "the waiting resume was ended, not abandoned")
        XCTAssertEqual(tokenRequests(), 0)
        // Nothing is left to resume: the pending request went with the wipe.
        try await client.resumePendingAuthorization()
        let still = await client.sessionState
        XCTAssertEqual(still, .unauthenticated)
    }

    func testForgettingAllClientsEndsTheResumesTheyStarted() async throws {
        let (_, cold) = try await coldStartedClient(redirect: "\(Self.redirect)?code=the-code&state=cold-state&iss=\(Self.issuer)")

        await OAuthClient.forgetAll()

        XCTAssertEqual(cold.cancelled, 1, "a waiting resume must not outlive the client that was forgotten")
    }

    func testResumePendingAuthorizationRefusesARedirectWithAnotherStateBeforeAnyTokenRequest() async throws {
        let (client, cold) = try await coldStartedClient(redirect: "\(Self.redirect)?code=the-code&state=forged&iss=\(Self.issuer)")

        await cold.release()
        do {
            try await client.resumePendingAuthorization()
            XCTFail("expected stateMismatch")
        } catch {
            XCTAssertEqual(error as? OAuthError, .configuration(.stateMismatch))
        }

        let state = await client.sessionState
        XCTAssertEqual(state, .unauthenticated)
        XCTAssertTrue(StubURLProtocol.requests.filter { $0.url?.path == "/token" }.isEmpty)
        let claims = await client.claims
        XCTAssertNil(claims)
    }

    func testResumePendingAuthorizationRefusesARedirectFromAnotherIssuerBeforeAnyTokenRequest() async throws {
        let (client, cold) = try await coldStartedClient(redirect: "\(Self.redirect)?code=the-code&state=cold-state&iss=https://evil.example.com")

        await cold.release()
        do {
            try await client.resumePendingAuthorization()
            XCTFail("expected issuerMismatch")
        } catch {
            XCTAssertEqual(error as? OAuthError, .configuration(.issuerMismatch(expected: Self.issuer, received: "https://evil.example.com")))
        }

        XCTAssertTrue(StubURLProtocol.requests.filter { $0.url?.path == "/token" }.isEmpty)
    }

    func testResumePendingAuthorizationRefusesAnIdTokenWithTheWrongNonceAndPersistsNothing() async throws {
        let (client, cold) = try await coldStartedClient(redirect: "\(Self.redirect)?code=the-code&state=cold-state&iss=\(Self.issuer)")
        await browser.remember(nonce: "not-the-one")

        await cold.release()
        do {
            try await client.resumePendingAuthorization()
            XCTFail("expected idTokenRejected")
        } catch {
            XCTAssertEqual(error as? OAuthError, .configuration(.idTokenRejected(.nonce)))
        }

        let state = await client.sessionState
        XCTAssertEqual(state, .unauthenticated)
        let claims = await client.claims
        XCTAssertNil(claims)
    }

    func testResumePendingAuthorizationWithNothingPendingIsANoOp() async throws {
        let client = try await client()

        try await client.resumePendingAuthorization()

        let state = await client.sessionState
        XCTAssertEqual(state, .unauthenticated)
        XCTAssertTrue(StubURLProtocol.requests.isEmpty)
    }

    func testTheAuthenticatedSessionNeedsAnOrigin() async throws {
        let client = try await client()
        XCTAssertThrowsError(try client.authenticatedSession(origins: []))
    }
}

private extension Data {
    var base64URL: String {
        base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
}
