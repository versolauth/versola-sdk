import Foundation
import OAuthCore
import os
import XCTest
@testable import OAuthClient

/// `12-process-death-browser` through the generic facade: the app is killed while the browser is
/// foreground, the user finishes signing in, and the redirect reaches a process that has to finish
/// the sign-in from what the first one persisted.
///
/// The process death is a second client over the same stores: the first client's login is left
/// suspended in its browser and never answered, as a killed process leaves it. What this proves
/// against a real provider is the exchange: the restored `code_verifier` and the restored `nonce`
/// are what the provider and the ID-token check accept. That `ASWebAuthenticationSession` cannot
/// deliver such a redirect (its sheet dies with the app) is why the real browser leg's half of this
/// scenario on iOS is the UI test of a terminated app (`ios/BrowserLegHost`), which can only
/// forge the redirect.
final class Scenario12ProcessDeathBrowserTest: ProviderConformance {
    /// The browser of the process that was killed: opened, never answered.
    private final class KilledBrowser: BrowserAuthorizationSession, Sendable {
        private let uris = OSAllocatedUnfairLock(initialState: [URL]())
        var opened: [URL] { uris.withLock { $0 } }
        func authorize(_ uri: URL, options: BrowserSessionOptions) async throws -> BrowserOutcome {
            uris.withLock { $0.append(uri) }
            try await Task.sleep(for: .seconds(3600))
            throw CancellationError()
        }
        func awaitPendingRedirect() async throws -> BrowserOutcome { throw CancellationError() }
    }

    /// The browser of the process the redirect started: nothing is opened, and what the user
    /// completed in the real browser arrives as the redirect the system hands over, once the test
    /// calls `deliver()` (on a device the redirect comes after the app has launched, so the app
    /// has observed `authorizing` by then).
    private final class ColdStartBrowser: BrowserAuthorizationSession, Sendable {
        let completedLogin: HttpLoginBrowser
        let uri: URL
        private let gate = AsyncStream.makeStream(of: Void.self)
        init(completedLogin: HttpLoginBrowser, uri: URL) {
            self.completedLogin = completedLogin
            self.uri = uri
        }
        func deliver() { gate.continuation.yield() }
        func authorize(_ uri: URL, options: BrowserSessionOptions) async throws -> BrowserOutcome {
            throw ConformanceFailure("a cold-started process opens no browser")
        }
        func awaitPendingRedirect() async throws -> BrowserOutcome {
            for await _ in gate.stream { break }
            try Task.checkCancellation()
            return try await completedLogin.authorize(uri, options: BrowserSessionOptions(redirectURI: URL(string: Provider.redirectUri)))
        }
    }

    private func process(browser: BrowserAuthorizationSession, credentials: InMemoryCredentialStore, pending: InMemoryPendingAuthorizationStore) async throws -> OAuthClient {
        await OAuthClient.forgetAll()
        return try await OAuthClient.create(
            configuration: try configuration(), browser: browser, credentialStore: credentials, pendingStore: pending,
            metadataCache: MemoryMetadataCache(), jwksCache: MemoryJwksCache()
        )
    }

    func testARedirectDeliveredToAColdStartedProcessCompletesTheSignInWithTheRestoredVerifier() async throws {
        let credentials = InMemoryCredentialStore()
        let pending = InMemoryPendingAuthorizationStore()

        // The first process: the browser opens, and the process dies there.
        let killed = KilledBrowser()
        let first = try await process(browser: killed, credentials: credentials, pending: pending)
        let login = Task { try await first.login() }
        defer { login.cancel() }
        await AuthzWait.until("the browser opened") { !killed.opened.isEmpty }
        let opened = try XCTUnwrap(killed.opened.first)
        let stored = try await pending.load()
        XCTAssertNotNil(stored, "the pending request was persisted before the browser opened")

        // The second process: the redirect cold-starts it.
        let cold = ColdStartBrowser(completedLogin: browser, uri: opened)
        let second = try await process(browser: cold, credentials: credentials, pending: pending)
        let restored = await second.sessionState
        XCTAssertEqual(restored, .authorizing, "the app observes authorizing on cold start, never unauthenticated")

        // The app does nothing more than hand over the redirect: `create` started finishing the
        // sign-in (`spec/oauth-sdk-api.md` section 4), as the Android `create` does.
        cold.deliver()
        // A real provider answers over a real network, so this waits on the clock, bounded at 30 s.
        var finished = false
        for _ in 0..<3_000 {
            if await second.sessionState == .authenticated { finished = true; break }
            try await Task.sleep(for: .milliseconds(10))
        }
        XCTAssertTrue(finished, "the cold-started process finished the sign-in on its own")

        let state = await second.sessionState
        XCTAssertEqual(state, .authenticated)
        let maybeClaims = await second.claims
        let claims = try XCTUnwrap(maybeClaims)
        XCTAssertFalse(claims.subject.isEmpty)
        // The restored verifier produced a successful exchange: the provider accepted it, once.
        let metadata = try await second.metadata()
        let token = try theRequest("POST", path(metadata.tokenEndpoint))
        XCTAssertEqual(token.status, 200)
        XCTAssertEqual(token.field("grant_type"), "authorization_code")
        XCTAssertNotNil(token.field("code_verifier"))
        // The pending request is wiped only after the grant is durably stored.
        let after = try await pending.load()
        XCTAssertNil(after)
        let hasGrant = try await credentials.hasGrant()
        XCTAssertTrue(hasGrant)

        // A third process restores the session without any browser.
        let third = try await process(browser: ConformanceFailureBrowser(), credentials: credentials, pending: pending)
        let thirdState = await third.sessionState
        XCTAssertEqual(thirdState, .authenticated)
    }

    /// A browser a test installs where nothing may be opened or awaited.
    private final class ConformanceFailureBrowser: BrowserAuthorizationSession, Sendable {
        func authorize(_ uri: URL, options: BrowserSessionOptions) async throws -> BrowserOutcome { throw ConformanceFailure("no browser expected") }
        func awaitPendingRedirect() async throws -> BrowserOutcome { throw ConformanceFailure("no browser expected") }
    }
}

private enum AuthzWait {
    /// Polls, yielding between looks; bounded, so a regression fails instead of hanging.
    static func until(_ message: String, file: StaticString = #filePath, line: UInt = #line, _ condition: @Sendable () -> Bool) async {
        for _ in 0..<2_000_000 {
            if condition() { return }
            await Task.yield()
        }
        XCTFail("timed out waiting for: \(message)", file: file, line: line)
    }
}
