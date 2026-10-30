import Foundation
import OAuthCore
import XCTest
@testable import OAuthClient

/// `30-logout-without-end-session`: sign-out revokes, wipes, and says what the server did.
/// The twin of the Android `Scenario30LogoutTest`.
final class Scenario30LogoutTest: ProviderConformance {
    private static let discovery = "/.well-known/openid-configuration"

    private func withoutEndSession() {
        network.rewriteJSON(Self.discovery) { document in
            var copy = document
            copy.removeValue(forKey: "end_session_endpoint")
            return copy
        }
    }

    private func assertWiped(_ client: OAuthClient, file: StaticString = #filePath, line: UInt = #line) async {
        let state = await client.sessionState
        XCTAssertEqual(state, .unauthenticated, file: file, line: line)
        let claims = await client.claims
        XCTAssertNil(claims, file: file, line: line)
        let error = await oauthError(file: file, line: line) { _ = try await client.accessToken() }
        guard case .reauthenticate? = error else { return XCTFail("expected reauthenticate, got \(String(describing: error))", file: file, line: line) }
    }

    private func assertRevocationRequest(_ entry: TranscriptEntry, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertNotNil(entry.form["token"], file: file, line: line)
        XCTAssertEqual(entry.field("token_type_hint"), "refresh_token", file: file, line: line)
        XCTAssertEqual(entry.field("client_id"), Provider.clientId, file: file, line: line)
        assertNoSecretOnTheWire(entry, file: file, line: line)
    }

    func test30WithoutAnEndSessionEndpointLogoutRevokesOpensNoBrowserAndReportsTheSessionNotEnded() async throws {
        withoutEndSession()
        let client = try await client()
        try await client.login()
        let metadata = try await client.metadata()

        let outcome = await client.logout()

        XCTAssertEqual(browser.opened.count, 1)
        XCTAssertFalse(outcome.sessionEnded)
        XCTAssertTrue(outcome.tokenRevoked)
        assertRevocationRequest(try theRequest("POST", path(try XCTUnwrap(metadata.revocationEndpoint))))
        await assertWiped(client)
    }

    func test30ARevocationEndpointAnswering503LeavesTokenRevokedFalseWithinTheRetryBudgetAndStillWipes() async throws {
        withoutEndSession()
        let client = try await client()
        try await client.login()
        let metadata = try await client.metadata()
        let revocationPath = path(try XCTUnwrap(metadata.revocationEndpoint))
        network.intercept { request in
            request.url?.path.hasSuffix(revocationPath) == true ? VirtualNetwork.StubAnswer(status: 503) : nil
        }

        let outcome = await client.logout()

        XCTAssertFalse(outcome.sessionEnded)
        XCTAssertFalse(outcome.tokenRevoked)
        let attempts = network.matching("POST", revocationPath)
        // Exactly the allowance: revocation is repeated (`spec/retry-policy.md`, operations), so one
        // request is a failure of this scenario, and more than the allowance is another.
        XCTAssertEqual(attempts.count, client.configuration.retryPolicy.maxAttemptsPerOrigin, "revocation attempts: \(attempts.count)")
        for attempt in attempts { assertRevocationRequest(attempt) }
        await assertWiped(client)
    }

    func test30TheUserDismissingTheEndSessionBrowserLeavesSessionEndedFalseAndStillWipes() async throws {
        let client = try await client()
        try await client.login()
        let metadata = try await client.metadata()
        guard let endSession = metadata.endSessionEndpoint else { throw XCTSkip("the provider advertises no end_session_endpoint") }
        browser.dismissNext()

        let outcome = await client.logout()

        XCTAssertEqual(browser.opened.count, 2)
        XCTAssertTrue(try XCTUnwrap(browser.opened.last).absoluteString.hasPrefix(endSession + "?"))
        XCTAssertFalse(outcome.sessionEnded)
        XCTAssertTrue(outcome.tokenRevoked)
        await assertWiped(client)
    }
}
