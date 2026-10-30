import Foundation
import OAuthCore
import os
import XCTest
@testable import OAuthClient

/// `34-server-error-per-operation`, `35-retry-after` and `36-retry-after-cooldown`, through the
/// generic facade against the staged provider: what it does when the provider answers a request
/// with 500, 501, 503 or 429, with and without `Retry-After`, counted on the wire. The twin of the
/// Android driver's `Scenario34To36ServerErrorsTest`.
///
/// Runs through the driver's proxy: `intercept` answers a chosen path with a chosen status and
/// headers (the `respond-with-status` capability) while every other request goes to the provider.
/// Skipped, never failed, without a provider (`OAUTH_CONFORMANCE_ISSUER`).
///
/// A refresh here is repeated only when the provider provably did not process it, because this
/// facade sends no `Idempotency-Key`: 503, 429 and 408 are repeated, a 500, 502, 504 or 501 is one
/// request. Everything else in the table is idempotent and repeated on every transient status.
final class Scenario34To36ServerErrorsTest: ProviderConformance {
    private static let discovery = "/.well-known/openid-configuration"

    /// `respond-with-status`: answers requests to `pathSuffix`, the first `times` of them (all when
    /// nil), and forwards the rest. Counts every request that matched, answered or not.
    @discardableResult
    private func respondWith(_ pathSuffix: String, status: Int, headers: [String: String] = [:], times: Int? = nil) -> Stamps {
        let stamps = Stamps()
        network.intercept { request in
            guard request.url?.path.hasSuffix(pathSuffix) == true else { return nil }
            let index = stamps.record()
            if let times, index >= times { return nil }
            return VirtualNetwork.StubAnswer(status: status, headers: headers)
        }
        return stamps
    }

    final class Stamps: Sendable {
        private let times = OSAllocatedUnfairLock(initialState: [Date]())
        func record() -> Int { times.withLock { $0.append(Date()); return $0.count - 1 } }
        var all: [Date] { times.withLock { $0 } }
    }

    private func withoutEndSession() {
        network.rewriteJSON(Self.discovery) { document in
            var copy = document
            copy.removeValue(forKey: "end_session_endpoint")
            return copy
        }
    }

    private func signedIn(_ configuration: OAuthConfiguration? = nil) async throws -> (OAuthClient, ProviderMetadata) {
        withoutEndSession()
        let client = try await client(configuration)
        try await client.login()
        return (client, try await client.metadata())
    }

    private func tokenPath(_ metadata: ProviderMetadata) -> String { path(metadata.tokenEndpoint) }

    private func refreshes(_ metadata: ProviderMetadata) -> [TranscriptEntry] {
        network.matching("POST", tokenPath(metadata)).filter { $0.field("grant_type") == "refresh_token" }
    }

    private struct ServerCause {
        let status: Int
        let retryAfterMillis: Int64?
        let attempts: Int
    }

    private func serverCause(_ error: OAuthError?, file: StaticString = #filePath, line: UInt = #line) -> ServerCause? {
        guard case .recoverable(.server(let status, let retryAfter, let attempts, _))? = error else {
            XCTFail("expected recoverable(.server), got \(String(describing: error))", file: file, line: line)
            return nil
        }
        return ServerCause(status: status, retryAfterMillis: retryAfter, attempts: attempts)
    }

    private static func imfFixdate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        return formatter.string(from: date)
    }

    // MARK: 34

    func test34ARefreshAnswered503Or429IsRepeatedThreeTimesAndSurfacedWithItsStatusGrantIntact() async throws {
        let (client, metadata) = try await signedIn()
        for status in [503, 429] {
            let before = refreshes(metadata).count
            respondWith(tokenPath(metadata), status: status)

            let error = await oauthError { try await client.refresh() }

            let cause = serverCause(error)
            XCTAssertEqual(cause?.status, status)
            XCTAssertEqual(cause?.attempts, 3)
            XCTAssertNil(cause?.retryAfterMillis)
            XCTAssertEqual(refreshes(metadata).count - before, 3, "HTTP \(status)")
            let state = await client.sessionState
            XCTAssertEqual(state, .authenticated)
        }
        // The grant survived all of it: once the provider answers, the same session refreshes.
        network.clearRewrites()
        try await client.refresh()
        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
    }

    func test34ARefreshAnswered500502Or504IsOneRequestBecauseTheProviderMayHaveProcessedIt() async throws {
        let (client, metadata) = try await signedIn()
        for status in [500, 502, 504] {
            let before = refreshes(metadata).count
            respondWith(tokenPath(metadata), status: status)

            let error = await oauthError { try await client.refresh() }

            let cause = serverCause(error)
            XCTAssertEqual(cause?.status, status)
            XCTAssertEqual(cause?.attempts, 1)
            XCTAssertEqual(refreshes(metadata).count - before, 1, "HTTP \(status): a refresh that may have rotated the token is not replayed")
            let state = await client.sessionState
            XCTAssertEqual(state, .authenticated)
        }
        network.clearRewrites()
        try await client.refresh()
    }

    func test34ARefreshAnswered501IsExactlyOneRequestAndServer501() async throws {
        let (client, metadata) = try await signedIn()
        let before = refreshes(metadata).count
        respondWith(tokenPath(metadata), status: 501)

        let error = await oauthError { try await client.refresh() }

        XCTAssertEqual(error, .recoverable(.server(status: 501, retryAfterMillis: nil, attempts: 1, elapsedMillis: serverElapsed(error))))
        XCTAssertEqual(refreshes(metadata).count - before, 1)
        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
    }

    private func serverElapsed(_ error: OAuthError?) -> Int64 {
        if case .recoverable(.server(_, _, _, let elapsed))? = error { return elapsed }
        return -1
    }

    func test34DiscoveryAnswered500503Or429IsRepeatedThreeTimes() async throws {
        for status in [500, 503, 429] {
            await OAuthClient.forgetAll()
            let client = try await client()
            let before = network.matching("GET", Self.discovery).count
            respondWith(Self.discovery, status: status)

            let error = await oauthError { _ = try await client.metadata() }

            XCTAssertEqual(serverCause(error)?.status, status)
            XCTAssertEqual(network.matching("GET", Self.discovery).count - before, 3, "HTTP \(status)")
            network.clearRewrites()
        }
    }

    func test34APushedAuthorizationRequestAnswered503IsRepeatedThreeTimesAndTheBrowserNeverOpens() async throws {
        let client = try await client()
        guard let par = try await client.metadata().pushedAuthorizationRequestEndpoint else { throw XCTSkip("the provider advertises no PAR endpoint") }
        let parPath = path(par)
        respondWith(parPath, status: 503)

        let error = await oauthError { try await client.login() }

        XCTAssertEqual(serverCause(error)?.status, 503)
        XCTAssertEqual(network.matching("POST", parPath).count, 3)
        XCTAssertTrue(browser.opened.isEmpty)
        let state = await client.sessionState
        XCTAssertEqual(state, .unauthenticated)
    }

    func test34UserInfoAnswered503IsRepeatedThreeTimes() async throws {
        let (client, metadata) = try await signedIn()
        guard let endpoint = metadata.userinfoEndpoint else { throw XCTSkip("the provider advertises no userinfo_endpoint") }
        respondWith(path(endpoint), status: 503)

        let error = await oauthError { _ = try await client.userInfo() }

        XCTAssertEqual(serverCause(error)?.status, 503)
        XCTAssertEqual(network.matching("GET", path(endpoint)).count, 3)
    }

    func test34ACodeExchangeAnswered503IsMadeOnceTheLoginFailsAndTheNextLoginStartsFromTheBrowser() async throws {
        let client = try await client()
        let tokenPath = tokenPath(try await client.metadata())
        respondWith(tokenPath, status: 503, headers: ["Retry-After": "1"], times: 1)

        let error = await oauthError { try await client.login() }

        // A single-use code is never replayed, whatever the status and whatever the server asks.
        XCTAssertEqual(serverCause(error)?.status, 503)
        XCTAssertEqual(network.matching("POST", tokenPath).count, 1)
        var state = await client.sessionState
        XCTAssertEqual(state, .unauthenticated)

        // The one second the provider asked for is a cooldown on its origin, and a login that
        // finishes faster than that would be refused by it (nothing sent, attempts 0): wait it out.
        try await Task.sleep(nanoseconds: 1_300_000_000)
        try await client.login()
        XCTAssertEqual(browser.opened.count, 2)
        state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
    }

    func test34ARequestThroughTheAuthenticatedSessionAnswered503WithRetryAfterIsReturnedAsIsAfterOneRequest() async throws {
        let (client, metadata) = try await signedIn()
        let session = try client.authenticatedSession()
        network.resource(ResourceServer.origin) { _ in
            VirtualNetwork.StubAnswer(status: 503, headers: ["Retry-After": "7"])
        }
        let tokenRequests = network.matching("POST", tokenPath(metadata)).count

        let (_, response) = try await session.data(for: URLRequest(url: URL(string: ResourceServer.origin + "/api")!))

        XCTAssertEqual(response.statusCode, 503, "the application's own answer, not converted")
        XCTAssertEqual(response.value(forHTTPHeaderField: "Retry-After"), "7", "with its header intact")
        let sent = network.transcript.filter { $0.url.hasPrefix(ResourceServer.origin) }
        XCTAssertEqual(sent.count, 1, "and one request: the SDK does not know the call was safe to repeat")
        XCTAssertEqual(network.matching("POST", tokenPath(metadata)).count, tokenRequests, "nor was a refresh spent on it")
    }

    func test34AKeySetFetchThatFailsDuringIdTokenValidationAfterTheExchangeIsRepeatedAndTheLoginSucceeds() async throws {
        // A cold key cache per test (`client()` builds a fresh `MemoryJwksCache`): the key set is
        // fetched during validation, after the code was redeemed, which is the window that matters.
        let client = try await client()
        let jwksUri = try await client.metadata().jwksUri
        let jwksPath = path(try XCTUnwrap(jwksUri))
        let stamps = respondWith(jwksPath, status: 503, times: 2)

        try await client.login()

        XCTAssertEqual(stamps.all.count, 3, "two 503s were repeated, the third request was forwarded")
        XCTAssertEqual(network.matching("GET", jwksPath).count, 3)
        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
    }

    // MARK: 35

    func test35A429WithRetryAfterTwoIsWaitedOutBeforeTheSecondRequest() async throws {
        let (client, metadata) = try await signedIn()
        let before = refreshes(metadata).count
        respondWith(tokenPath(metadata), status: 429, headers: ["Retry-After": "2"], times: 1)

        try await client.refresh()

        let attempts = Array(refreshes(metadata).dropFirst(before))
        XCTAssertEqual(attempts.count, 2)
        let gap = attempts[1].at.timeIntervalSince(attempts[0].at)
        // Not the 500 ms backoff, and not past the two seconds plus a tenth of jitter.
        XCTAssertGreaterThanOrEqual(gap, 2.0)
        XCTAssertLessThanOrEqual(gap, 2.9)
        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
    }

    func test35AnHttpDateRetryAfterIsMeasuredAgainstTheResponsesDateNotTheDeviceClock() async throws {
        let (client, metadata) = try await signedIn()
        let before = refreshes(metadata).count
        // The server's clock an hour ahead of the device's: Date is now + 1 h and the Retry-After is
        // three seconds after that Date. Measured against the device clock it would be an hour.
        let serverNow = Date().addingTimeInterval(3600)
        respondWith(tokenPath(metadata), status: 503, headers: [
            "Date": Self.imfFixdate(serverNow),
            "Retry-After": Self.imfFixdate(serverNow.addingTimeInterval(3)),
        ], times: 1)

        try await client.refresh()

        let attempts = Array(refreshes(metadata).dropFirst(before))
        XCTAssertEqual(attempts.count, 2, "an hour-long wait would have ended the operation after one request")
        let gap = attempts[1].at.timeIntervalSince(attempts[0].at)
        XCTAssertGreaterThanOrEqual(gap, 2.0)
        XCTAssertLessThanOrEqual(gap, 3.9)
    }

    func test35ARetryAfterPastTheBudgetADayLongOrAbsurdStopsAtOnceWithTheValue() async throws {
        for (header, expected) in [("30", Int64(30_000)), ("86400", 86_400_000), ("999999999", 86_400_000)] {
            await OAuthClient.forgetAll()
            let (client, metadata) = try await signedIn()
            let before = refreshes(metadata).count
            respondWith(tokenPath(metadata), status: 429, headers: ["Retry-After": header])
            let started = Date()

            let error = await oauthError { try await client.refresh() }

            let cause = serverCause(error)
            XCTAssertEqual(cause?.status, 429)
            XCTAssertEqual(cause?.retryAfterMillis, expected, header)
            XCTAssertEqual(cause?.attempts, 1, header)
            // One request, no sleeping and no shortening of the wait.
            XCTAssertEqual(refreshes(metadata).count - before, 1, header)
            XCTAssertLessThan(Date().timeIntervalSince(started), 5, header)
            network.clearRewrites()
        }
    }

    func test35AMalformedRetryAfterIsTheOrdinaryBackoffThreeRequestsAndNoConfiguration() async throws {
        for junk in ["-1", "1.5", "soon", ""] {
            await OAuthClient.forgetAll()
            let (client, metadata) = try await signedIn()
            let before = refreshes(metadata).count
            respondWith(tokenPath(metadata), status: 503, headers: ["Retry-After": junk])

            let error = await oauthError { try await client.refresh() }

            let cause = serverCause(error)
            XCTAssertNil(cause?.retryAfterMillis, "'\(junk)'")
            XCTAssertEqual(refreshes(metadata).count - before, 3, "'\(junk)'")
            network.clearRewrites()
        }
    }

    func test35ARetryAfterOnA500IsIgnored() async throws {
        let (client, metadata) = try await signedIn()
        guard let endpoint = metadata.userinfoEndpoint else { throw XCTSkip("the provider advertises no userinfo_endpoint") }
        respondWith(path(endpoint), status: 500, headers: ["Retry-After": "86400"])

        let error = await oauthError { _ = try await client.userInfo() }

        let cause = serverCause(error)
        XCTAssertNil(cause?.retryAfterMillis)
        XCTAssertEqual(cause?.attempts, 3, "UserInfo is idempotent, so a 500 is repeated with the ordinary backoff")
    }

    // MARK: 36

    func test36AfterARetryAfterNothingIsSentToTheProviderUntilItPassesAndLogoutStillWipes() async throws {
        let (client, metadata) = try await signedIn()
        respondWith(tokenPath(metadata), status: 429, headers: ["Retry-After": "30"])
        let first = await oauthError { try await client.refresh() }
        XCTAssertEqual(serverCause(first)?.retryAfterMillis, 30_000)
        let sent = network.transcript.count

        // Inside the window: every one of these fails at once, and none sends a request.
        let refused: [OAuthError?] = [
            await oauthError { try await client.refresh() },
            await oauthError { _ = try await client.userInfo() },
        ]
        for error in refused {
            let cause = serverCause(error)
            XCTAssertEqual(cause?.status, 429)
            XCTAssertEqual(cause?.attempts, 0)
            XCTAssertTrue((1...30_000).contains(cause?.retryAfterMillis ?? 0), "left \(String(describing: cause?.retryAfterMillis))")
        }
        // accessToken() serves the live token from memory: no request to make, so none refused.
        _ = try await client.accessToken()
        XCTAssertEqual(network.transcript.count, sent)
        var state = await client.sessionState
        XCTAssertEqual(state, .authenticated)

        // The revocation is refused by the cooldown (same origin, nothing sent) and the local wipe happens regardless.
        let outcome = await client.logout()
        XCTAssertFalse(outcome.tokenRevoked)
        state = await client.sessionState
        XCTAssertEqual(state, .unauthenticated)
        XCTAssertEqual(refreshes(metadata).count, 1)
    }

    /// The cooldown ends: in real time, with a budget of one second and a `Retry-After` of two, so
    /// the first refresh stops at once and the window is short enough to wait out.
    func test36TheCooldownExpiresAndARefreshThenSucceedsAgainstTheForwardingProxy() async throws {
        let configuration = try configuration(retryPolicy: RetryPolicy(totalBudget: 1))
        let (client, metadata) = try await signedIn(configuration)
        respondWith(tokenPath(metadata), status: 429, headers: ["Retry-After": "2"])

        let first = await oauthError { try await client.refresh() }

        let cause = serverCause(first)
        XCTAssertEqual(cause?.retryAfterMillis, 2000)
        XCTAssertEqual(cause?.attempts, 1, "2 s does not fit the 1 s budget: one request, no waiting")
        XCTAssertEqual(refreshes(metadata).count, 1)
        let sent = network.transcript.count

        let refused: [OAuthError?] = [
            await oauthError { try await client.refresh() },
            await oauthError { _ = try await client.userInfo() },
        ]
        for error in refused { XCTAssertEqual(serverCause(error)?.attempts, 0) }
        XCTAssertEqual(network.transcript.count, sent, "and nothing was sent")

        // The provider recovers, and the window passes.
        network.clearRewrites()
        try await Task.sleep(nanoseconds: 2_300_000_000)
        try await client.refresh()

        XCTAssertEqual(refreshes(metadata).count, 2)
        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
    }

    /// A cold start forgets the cooldown: the new client for the same configuration, with the grant the
    /// old one stored, sends one request, and the server answers it as it likes.
    func test36AfterAColdStartTheNewClientSendsOneRequestAndIsNotRefusedByTheOldCooldown() async throws {
        withoutEndSession()
        let credentials = InMemoryCredentialStore()
        let first = try await client(credentials: credentials)
        try await first.login()
        let metadata = try await first.metadata()
        respondWith(tokenPath(metadata), status: 429, headers: ["Retry-After": "30"])
        let refused = await oauthError { try await first.refresh() }
        XCTAssertEqual(serverCause(refused)?.retryAfterMillis, 30_000)
        let before = refreshes(metadata).count

        // The app is killed and started again: same configuration, same stored grant, new process.
        await OAuthClient.forgetAll()
        let second = try await client(credentials: credentials)
        let error = await oauthError { try await second.refresh() }

        let cause = serverCause(error)
        XCTAssertEqual(cause?.status, 429)
        XCTAssertEqual(cause?.attempts, 1, "a request was sent: nothing carried the cooldown across the restart")
        XCTAssertEqual(refreshes(metadata).count - before, 1)
    }

    /// The application's own requests are not the SDK's to hold back: the cooldown covers what the SDK
    /// sends to the provider, never a request through the authenticated session.
    func test36ARequestThroughTheAuthenticatedSessionIsNotBlockedWhileTheCooldownRuns() async throws {
        let (client, metadata) = try await signedIn()
        let session = try client.authenticatedSession()
        respondWith(tokenPath(metadata), status: 429, headers: ["Retry-After": "30"])
        let refused = await oauthError { try await client.refresh() }
        XCTAssertEqual(serverCause(refused)?.retryAfterMillis, 30_000)

        let (_, response) = try await session.data(for: URLRequest(url: URL(string: ResourceServer.origin + "/api")!))

        XCTAssertEqual(response.statusCode, 200, "the live token is attached and the call goes through")
        let sent = network.transcript.filter { $0.url.hasPrefix(ResourceServer.origin) }
        XCTAssertEqual(sent.count, 1)
    }

    func test36ExhaustingTheBudgetOn503WithoutARetryAfterStartsNoCooldown() async throws {
        let (client, metadata) = try await signedIn()
        respondWith(tokenPath(metadata), status: 503)
        _ = await oauthError { try await client.refresh() }
        let afterFirst = refreshes(metadata).count

        _ = await oauthError { try await client.refresh() }

        // A second set of three: the SDK invents no provider policy; the retry loop above it is the app's.
        XCTAssertEqual(afterFirst, 3)
        XCTAssertEqual(refreshes(metadata).count, 6)
    }
}
