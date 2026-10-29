import Foundation
import OAuthCore
import XCTest
@testable import OAuthClient

/// `31-session-without-refresh-token`: a client the provider issues no refresh token for
/// (`conformance-app-norefresh`, ten-second access tokens). The scenario's clock step is real
/// time here, as it is on Android: the device clock cannot be moved from a test, so the realm
/// issues tokens short enough to expire within the test, and the wait is bounded (up to 40
/// polls, one real second apart), not fixed. This is the one place the suite sleeps.
///
/// Whichever path observes the expiry first (`accessToken()` or the authenticated session) gets
/// `SessionExpired`; the session is wiped by then, so a later ask in `unauthenticated` is
/// `Reauthenticate` too, with `GrantRejected` (nothing to refresh with). The scenario's "the
/// same Reauthenticate" is held to the category in the second test and to the reason in the first.
final class Scenario31SessionWithoutRefreshTokenTest: ProviderConformance {
    func test31TheSessionEndsAtAccessTokenExpiryWithReauthenticateSessionExpiredAndNoTokenRequest() async throws {
        let client = try await client(try configuration(clientId: Provider.noRefreshClientId, scopes: provider.noRefreshScopes))
        try await client.login()
        let metadata = try await client.metadata()
        let tokenPath = path(metadata.tokenEndpoint)

        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
        let issued = try XCTUnwrap(try theRequest("POST", tokenPath).responseJSON)
        XCTAssertNil(issued["refresh_token"], "the realm must issue no refresh token to this client")
        let session = try client.authenticatedSession()
        let resource = URLRequest(url: URL(string: ResourceServer.origin + "/api")!)
        let (_, first) = try await session.data(for: resource)
        XCTAssertEqual(first.statusCode, 200)
        let warnings = logger.warnings
        XCTAssertEqual(warnings.filter { $0.contains("issued no refresh token") }.count, 1, "\(warnings)")

        // Past the token's expiry (its lifetime minus the refresh skew): the next ask ends the session.
        let expiry = await oauthError {
            for _ in 0..<40 {
                _ = try await client.accessToken()
                try await Task.sleep(for: .seconds(1))
            }
        }
        XCTAssertEqual(expiry, .reauthenticate(.sessionExpired))
        XCTAssertEqual(network.matching("POST", tokenPath).count, 1, "token requests")
        let after = await client.sessionState
        XCTAssertEqual(after, .unauthenticated)
        let claims = await client.claims
        XCTAssertNil(claims)

        // The authenticated session makes no refresh attempt and surfaces Reauthenticate too.
        let call = await oauthError { _ = try await session.data(for: resource) }
        XCTAssertEqual(call, .reauthenticate(.grantRejected))
        XCTAssertEqual(network.matching("POST", tokenPath).count, 1)
        XCTAssertEqual(browser.opened.count, 1)
        XCTAssertFalse(network.transcript.contains { $0.url.hasPrefix(metadata.authorizationEndpoint) })
    }

    func test31TheAuthenticatedSessionObservingTheExpiryFirstSurfacesSessionExpiredWithoutARefreshAttempt() async throws {
        let client = try await client(try configuration(clientId: Provider.noRefreshClientId, scopes: provider.noRefreshScopes))
        try await client.login()
        let tokenPath = path(try await client.metadata().tokenEndpoint)
        let session = try client.authenticatedSession()
        let resource = URLRequest(url: URL(string: ResourceServer.origin + "/api")!)

        let expiry = await oauthError {
            for _ in 0..<40 {
                _ = try await session.data(for: resource)
                try await Task.sleep(for: .seconds(1))
            }
        }

        XCTAssertEqual(expiry, .reauthenticate(.sessionExpired))
        XCTAssertEqual(network.matching("POST", tokenPath).count, 1)
        let state = await client.sessionState
        XCTAssertEqual(state, .unauthenticated)
        let claims = await client.claims
        XCTAssertNil(claims)
        XCTAssertEqual(browser.opened.count, 1)
    }
}
