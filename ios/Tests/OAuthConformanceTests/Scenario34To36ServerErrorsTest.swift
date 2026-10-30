import Foundation
import OAuthCore
import os
import XCTest
@testable import OAuthClient

/// `34-server-error-per-operation`, `35-retry-after` and `36-retry-after-cooldown`: what the
/// generic facade does when the provider answers a repeatable request with 500, 503 or 429, with
/// and without `Retry-After`, counted on the wire. The twin of the Android driver's tests.
///
/// Runs through the driver's proxy: `intercept` answers a chosen path with a chosen status and
/// headers (the `respond-with-status` capability) while every other request goes to the provider.
/// Skipped, never failed, without a provider (`OAUTH_CONFORMANCE_ISSUER`). The revocation and
/// UserInfo rows are driven here; discovery, the key set, the push and the refresh are proven at
/// the unit tier (`OperationRetryTests`, `SessionCoordinatorTests`) and by the Android driver.
final class Scenario34To36ServerErrorsTest: ProviderConformance {
    private static let discovery = "/.well-known/openid-configuration"

    /// A stub that answers `statuses` in order on `pathSuffix`, then forwards; stamps each answer.
    private func answering(_ pathSuffix: String, _ statuses: [(Int, [String: String])], repeatingLast: Bool = false) -> Stamps {
        let stamps = Stamps()
        network.intercept { request in
            guard request.url?.path.hasSuffix(pathSuffix) == true else { return nil }
            let index = stamps.record()
            guard index < statuses.count || repeatingLast else { return nil }
            let (status, headers) = statuses[min(index, statuses.count - 1)]
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

    private func signedIn() async throws -> (OAuthClient, ProviderMetadata) {
        withoutEndSession()
        let client = try await client()
        try await client.login()
        return (client, try await client.metadata())
    }

    // MARK: 34

    func test34RevocationAnsweredWith500OnEveryAttemptMakesExactlyTheDefaultAllowanceAndStillWipes() async throws {
        let (client, metadata) = try await signedIn()
        let revocation = path(try XCTUnwrap(metadata.revocationEndpoint))
        let stamps = answering(revocation, [(500, [:])], repeatingLast: true)

        let outcome = await client.logout()

        XCTAssertFalse(outcome.tokenRevoked)
        XCTAssertEqual(stamps.all.count, client.configuration.retryPolicy.maxAttemptsPerOrigin, "revocation is repeated, and by no more than the allowance")
        let state = await client.sessionState
        XCTAssertEqual(state, .unauthenticated)
    }

    func test34UserInfoAnsweredWith503OnEveryAttemptSurfacesServerAfterTheDefaultAllowance() async throws {
        let (client, metadata) = try await signedIn()
        guard let endpoint = metadata.userinfoEndpoint else { throw XCTSkip("the provider advertises no userinfo_endpoint") }
        let stamps = answering(path(endpoint), [(503, [:])], repeatingLast: true)

        let error = await oauthError { _ = try await client.userInfo() }

        guard case .recoverable(.server(503, nil, let attempts, _))? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertEqual(attempts, client.configuration.retryPolicy.maxAttemptsPerOrigin)
        XCTAssertEqual(stamps.all.count, attempts)
    }

    func test34TheAuthorizationCodeExchangeAnsweredWith503IsMadeOnceAndTheLoginFails() async throws {
        let client = try await client()
        let metadata = try await client.metadata()
        let tokenPath = path(metadata.tokenEndpoint)
        let stamps = answering(tokenPath, [(503, [:])], repeatingLast: true)

        let error = await oauthError { try await client.login() }

        guard case .recoverable(.server(503, _, 1, _))? = error else { return XCTFail("\(String(describing: error))") }
        XCTAssertEqual(stamps.all.count, 1, "a spent code is not replayed")
        let state = await client.sessionState
        XCTAssertEqual(state, .unauthenticated)
    }

    // MARK: 35

    func test35ARetryAfterOfTwoSecondsIsWaitedInPreferenceToTheBackoff() async throws {
        let (client, metadata) = try await signedIn()
        let revocation = path(try XCTUnwrap(metadata.revocationEndpoint))
        let stamps = answering(revocation, [(429, ["Retry-After": "2"])])

        let outcome = await client.logout()

        XCTAssertTrue(outcome.tokenRevoked, "the second attempt is forwarded to the provider")
        XCTAssertEqual(stamps.all.count, 2)
        let gap = stamps.all[1].timeIntervalSince(stamps.all[0])
        XCTAssertGreaterThanOrEqual(gap, 2.0)
        XCTAssertLessThanOrEqual(gap, 3.0, "a tenth of the value in jitter, at most a second, and not the backoff")
    }

    func test35ARetryAfterBeyondTheBudgetSendsNoSecondRequestAndDoesNotWait() async throws {
        let (client, metadata) = try await signedIn()
        let revocation = path(try XCTUnwrap(metadata.revocationEndpoint))
        let stamps = answering(revocation, [(429, ["Retry-After": "90"])], repeatingLast: true)
        let started = Date()

        let outcome = await client.logout()

        XCTAssertFalse(outcome.tokenRevoked)
        XCTAssertEqual(stamps.all.count, 1, "the wait was not shortened to fit the budget")
        XCTAssertLessThan(Date().timeIntervalSince(started), 5)
    }

    func test35AMalformedRetryAfterIsTheBackoffAndNeverAFailureOfItsOwn() async throws {
        let (client, metadata) = try await signedIn()
        let revocation = path(try XCTUnwrap(metadata.revocationEndpoint))
        let stamps = answering(revocation, [(503, ["Retry-After": "soon"])])

        let outcome = await client.logout()

        XCTAssertTrue(outcome.tokenRevoked)
        XCTAssertEqual(stamps.all.count, 2)
    }

    // MARK: 36

    func test36AfterARetryAfterTheNextUserInfoSendsNothingAndTheCooldownShrinks() async throws {
        let (client, metadata) = try await signedIn()
        guard let endpoint = metadata.userinfoEndpoint else { throw XCTSkip("the provider advertises no userinfo_endpoint") }
        let stamps = answering(path(endpoint), [(429, ["Retry-After": "90"])], repeatingLast: true)

        let first = await oauthError { _ = try await client.userInfo() }
        guard case .recoverable(.server(429, 90_000?, 1, _))? = first else { return XCTFail("\(String(describing: first))") }
        let second = await oauthError { _ = try await client.userInfo() }

        guard case .recoverable(.server(429, let left?, 0, _))? = second else { return XCTFail("\(String(describing: second))") }
        XCTAssertLessThanOrEqual(left, 90_000)
        XCTAssertEqual(stamps.all.count, 1, "nothing was sent while the server asked for quiet")
    }
}
