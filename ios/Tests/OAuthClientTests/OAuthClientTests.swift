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
        /// One per release, in order; the last one repeats.
        private let outcomes: [BrowserOutcome]
        private let state = OSAllocatedUnfairLock(initialState: (awaited: 0, cancelled: 0))
        private let gate = AsyncStream.makeStream(of: Void.self)
        init(_ outcome: BrowserOutcome) { outcomes = [outcome] }
        init(_ outcomes: [BrowserOutcome]) { self.outcomes = outcomes }
        var awaited: Int { state.withLock { $0.awaited } }
        /// How many waits for the redirect ended because their task was cancelled.
        var cancelled: Int { state.withLock { $0.cancelled } }
        func authorize(_ uri: URL, options: BrowserSessionOptions) async throws -> BrowserOutcome {
            throw CancellationError()
        }
        func awaitPendingRedirect() async throws -> BrowserOutcome {
            let index = state.withLock { state -> Int in
                state.awaited += 1
                return state.awaited - 1
            }
            for await _ in gate.stream { break }
            if Task.isCancelled {
                state.withLock { $0.cancelled += 1 }
                throw CancellationError()
            }
            return outcomes[min(index, outcomes.count - 1)]
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
        // A response that fails validation (its state is the request's, its issuer is not): the
        // failure the resume logs. A redirect with another state would not fail it (scenario 15).
        let (client, cold) = try await coldStartedClient(redirect: "\(Self.redirect)?code=the-code&state=cold-state&iss=https://evil.example.com", logger: signal)
        cold.release()

        var line: String?
        for await warning in signal.warnings where warning.contains("resuming the pending authorization failed") {
            line = warning
            break
        }

        let logged = try XCTUnwrap(line)
        for secret in ["the-code", "cold-state", "cold-nonce"] {
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
        for _ in 0..<200_000 where cold.awaited == 0 { await Task.yield() }

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
        // Cancelled before it ever reached the browser, a resume never waits and `cancelled` stays 0:
        // the test must start from a resume that is waiting (a race this test had on its own).
        for _ in 0..<200_000 where cold.awaited == 0 { await Task.yield() }

        await OAuthClient.forgetAll()

        XCTAssertEqual(cold.cancelled, 1, "a waiting resume must not outlive the client that was forgotten")
    }

    /// The first sheet is torn down by the system while the app is in the background; the second
    /// answers like the ordinary fake.
    actor SystemCancelsOnce: BrowserAuthorizationSession {
        private let answering: FakeBrowser
        private var cancelled = false
        init(_ answering: FakeBrowser) { self.answering = answering }
        func authorize(_ uri: URL, options: BrowserSessionOptions) async throws -> BrowserOutcome {
            if !cancelled {
                cancelled = true
                return .systemCancelled
            }
            return try await answering.authorize(uri, options: options)
        }
        func awaitPendingRedirect() async throws -> BrowserOutcome { throw CancellationError() }
    }

    /// A system cancel keeps the pending request for a resume the app may never start. A new
    /// `login()` does not wait out its ten minutes: it supersedes it.
    func testLoginAfterASystemCancelSupersedesTheLeftoverRequestInsteadOfBeingRefusedForTenMinutes() async throws {
        let client = try await OAuthClient.create(configuration: try configuration(), browser: SystemCancelsOnce(browser), credentialStore: InMemoryCredentialStore(), pendingStore: InMemoryPendingAuthorizationStore())

        do {
            try await client.login()
            XCTFail("expected systemCancelled")
        } catch {
            XCTAssertEqual(error as? OAuthError, .recoverable(.systemCancelled))
        }
        let between = await client.sessionState
        XCTAssertEqual(between, .authorizing, "kept for a resume")

        try await client.login()

        let after = await client.sessionState
        XCTAssertEqual(after, .authenticated)
        let opened = await browser.opened
        XCTAssertEqual(opened.count, 1, "the second sheet opened and signed in")
    }

    // MARK: - login() over the resume a cold start began

    /// The browser of a process that was cold-started mid-browser and whose user then tapped
    /// "Sign in" instead of waiting for the old sheet's redirect: the resume `create` started
    /// waits for a redirect that will not come, and the live sheet answers like the ordinary fake.
    /// With `staleRedirectFirst` the live sheet's first answer is the old request's redirect, the
    /// one its abandoned tab would still deliver.
    final class ResumeWaitingThenLiveBrowser: BrowserAuthorizationSession, Sendable {
        private let live: FakeBrowser
        private let staleRedirectFirst: URL?
        private let state = OSAllocatedUnfairLock(initialState: (awaited: 0, cancelled: 0, afterStale: BrowserOutcome?.none))
        private let gate = AsyncStream.makeStream(of: Void.self)
        init(_ live: FakeBrowser, staleRedirectFirst: URL? = nil) {
            self.live = live
            self.staleRedirectFirst = staleRedirectFirst
        }
        var awaited: Int { state.withLock { $0.awaited } }
        var cancelled: Int { state.withLock { $0.cancelled } }
        func authorize(_ uri: URL, options: BrowserSessionOptions) async throws -> BrowserOutcome {
            let answer = try await live.authorize(uri, options: options)
            guard let stale = staleRedirectFirst else { return answer }
            state.withLock { $0.afterStale = answer }
            return .redirect(stale)
        }
        func awaitPendingRedirect() async throws -> BrowserOutcome {
            if let next = state.withLock({ s -> BrowserOutcome? in defer { s.afterStale = nil }; return s.afterStale }) { return next }
            state.withLock { $0.awaited += 1 }
            for await _ in gate.stream { break }
            state.withLock { $0.cancelled += 1 }
            throw CancellationError()
        }
    }

    private func awaitingColdStart(staleRedirectFirst: URL? = nil) async throws -> (OAuthClient, ResumeWaitingThenLiveBrowser) {
        let pendingStore = InMemoryPendingAuthorizationStore()
        try await pendingStore.save(PendingAuthorizationRequest(
            state: "cold-state", nonce: "cold-nonce", codeVerifier: String(repeating: "v", count: 43),
            scopes: ["openid"], redirectUri: Self.redirect, createdAt: Date().addingTimeInterval(-30)
        ))
        let cold = ResumeWaitingThenLiveBrowser(browser, staleRedirectFirst: staleRedirectFirst)
        let client = try await OAuthClient.create(configuration: try configuration(), browser: cold, credentialStore: InMemoryCredentialStore(), pendingStore: pendingStore)
        // The resume `create` started is waiting for its redirect.
        for _ in 0..<200_000 where cold.awaited == 0 { await Task.yield() }
        XCTAssertEqual(cold.awaited, 1, "the cold-start resume is waiting for a redirect")
        return (client, cold)
    }

    /// The redirect of a cold-started resume may never come (the user abandoned that sheet and
    /// came back to the app itself). `login()` ends that wait and supersedes the request instead
    /// of being refused for the rest of its ten minutes.
    func testLoginAfterAColdStartPreEmptsTheResumeThatOnlyWaitsForItsRedirect() async throws {
        let (client, cold) = try await awaitingColdStart()
        let before = await client.sessionState
        XCTAssertEqual(before, .authorizing)

        try await client.login()

        let after = await client.sessionState
        XCTAssertEqual(after, .authenticated)
        XCTAssertEqual(cold.cancelled, 1, "the waiting resume was ended, not left holding the gate")
        XCTAssertEqual(tokenRequests(), 1, "one exchange: the new login's")
        let opened = await browser.opened
        XCTAssertEqual(opened.count, 1)
    }

    func testStepUpAfterAColdStartPreEmptsTheWaitingResumeToo() async throws {
        let (client, cold) = try await awaitingColdStart()

        try await client.stepUp(acrValues: ["urn:example:acr"], maxAge: nil)

        XCTAssertEqual(cold.cancelled, 1)
        let after = await client.sessionState
        XCTAssertEqual(after, .authenticated)
    }

    func testARedirectTheSupersededColdStartRequestStillDeliversIsSteppedOverNotAMismatch() async throws {
        let late = URL(string: "\(Self.redirect)?code=the-old-code&state=cold-state&iss=\(Self.issuer)")!
        let (client, _) = try await awaitingColdStart(staleRedirectFirst: late)

        try await client.login()

        let after = await client.sessionState
        XCTAssertEqual(after, .authenticated, "the old request's redirect did not fail the new login as a state mismatch")
        XCTAssertEqual(tokenRequests(), 1)
    }

    /// The other half: a browser that is really open (not a resume waiting for a redirect) still
    /// refuses a second `login()`.
    func testALoginWhoseSheetIsOpenStillRefusesASecondLogin() async throws {
        let gated = GatedFakeBrowser(browser)
        let client = try await OAuthClient.create(configuration: try configuration(), browser: gated, credentialStore: InMemoryCredentialStore(), pendingStore: InMemoryPendingAuthorizationStore())
        let first = Task { try await client.login() }
        for _ in 0..<200_000 where await gated.opened == 0 { await Task.yield() }

        do {
            try await client.login()
            XCTFail("a second login was admitted over an open sheet")
        } catch let error as OAuthError {
            guard case .configuration(.invalidConfiguration) = error else { return XCTFail("\(error)") }
        }

        await gated.open()
        try await first.value
    }

    /// Holds the sheet open until the test lets it answer.
    actor GatedFakeBrowser: BrowserAuthorizationSession {
        private let live: FakeBrowser
        private(set) var opened = 0
        private var waiting: CheckedContinuation<Void, Never>?
        init(_ live: FakeBrowser) { self.live = live }
        func authorize(_ uri: URL, options: BrowserSessionOptions) async throws -> BrowserOutcome {
            opened += 1
            await withCheckedContinuation { waiting = $0 }
            return try await live.authorize(uri, options: options)
        }
        func awaitPendingRedirect() async throws -> BrowserOutcome { throw CancellationError() }
        func open() { waiting?.resume(); waiting = nil }
    }

    func testAForeignRedirectHandedToAColdStartedClientIsIgnoredAndTheGenuineOneStillCompletesTheSignIn() async throws {
        // Scenario 15 through the facade: `handleRedirect` hands every URL for the redirect URI to
        // the flow, and a redirect that is not the pending request's is not its response.
        let pendingStore = FlakyPendingStore(failFirstLoads: 0)
        try await pendingStore.save(PendingAuthorizationRequest(
            state: "cold-state", nonce: "cold-nonce", codeVerifier: String(repeating: "v", count: 43),
            scopes: ["openid"], redirectUri: Self.redirect, createdAt: Date().addingTimeInterval(-30)
        ))
        await browser.remember(nonce: "cold-nonce")
        let cold = ColdStartBrowser([
            .redirect(URL(string: "\(Self.redirect)?code=forged&state=forged&iss=\(Self.issuer)")!),
            .redirect(URL(string: "\(Self.redirect)?code=the-code&state=cold-state&iss=\(Self.issuer)")!),
        ])
        let client = try await OAuthClient.create(configuration: try configuration(), browser: cold, credentialStore: InMemoryCredentialStore(), pendingStore: pendingStore)

        await cold.release()
        for _ in 0..<200_000 where cold.awaited < 2 { await Task.yield() }
        XCTAssertEqual(cold.awaited, 2, "the foreign redirect was consumed and the resume went on waiting")
        let waiting = await client.sessionState
        XCTAssertEqual(waiting, .authorizing, "it neither failed the sign-in nor wiped the request")
        XCTAssertTrue(StubURLProtocol.requests.filter { $0.url?.path == "/token" }.isEmpty)
        let stored = try await pendingStore.load()
        XCTAssertNotNil(stored)

        let resume = Task { try await client.resumePendingAuthorization() }
        await cold.release()
        try await resume.value

        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
        XCTAssertEqual(tokenRequests(), 1, "only the genuine redirect's code was exchanged")
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
