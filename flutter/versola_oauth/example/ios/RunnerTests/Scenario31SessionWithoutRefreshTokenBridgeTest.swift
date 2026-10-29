import Foundation
import OAuthCore
import XCTest
@testable import OAuthClient
@testable import versola_oauth

/// `31-session-without-refresh-token` through the bridge: a client the provider issues no refresh
/// token for (`conformance-app-norefresh`, ten-second access tokens). The scenario's clock step is
/// real time here, as in the native driver: the realm issues tokens short enough to expire within
/// the test, and the wait is bounded (up to 40 polls, one real second apart), not fixed
/// (`Scenario31SessionWithoutRefreshTokenTest`).
///
/// Flutter has no authenticated session to observe the expiry through, so the two paths that ask
/// the SDK for a live access token are the two that take its place: `accessToken()` in the first
/// test, `userInfo()` (which needs a live token as well) in the second.
final class Scenario31SessionWithoutRefreshTokenBridgeTest: BridgeConformance {
    /// Asks until the SDK answers with an error (the session expired); at most ~40 s, a second apart.
    private func expiryObservedBy(_ ask: () async throws -> ErrorMessage?) async throws -> ErrorMessage {
        for _ in 0..<40 {
            if let error = try await ask() { return error }
            try await Task.sleep(for: .seconds(1))
        }
        throw BridgeFailure("the session did not end within the access token's lifetime")
    }

    func test31TheSessionEndsAtAccessTokenExpiryWithReauthenticateSessionExpiredAndNoTokenRequest() async throws {
        let bridge = try await bridge(clientId: Provider.noRefreshClientId, scopes: provider.noRefreshScopes)
        try ok(await bridge.dart.login())
        let metadata = try await bridge.native.metadata()
        let tokenPath = path(metadata.tokenEndpoint)

        let state = try await bridge.dart.sessionState()
        XCTAssertEqual(state, .authenticated)
        let issued = try XCTUnwrap(try theRequest("POST", tokenPath).responseJSON)
        XCTAssertNil(issued["refresh_token"], "the realm must issue no refresh token to this client")
        let claims = try await bridge.dart.claims()
        try await assertTokenIsUsableAtTheResource(try token(await bridge.dart.accessToken()), subject: try XCTUnwrap(claims).subject)
        let warnings = logger.warnings
        XCTAssertEqual(warnings.filter { $0.contains("issued no refresh token") }.count, 1, "\(warnings)")

        // Past the token's expiry (its lifetime minus the refresh skew): the next ask ends the session.
        let dart = bridge.dart
        let expiry = try await expiryObservedBy { (try await dart.accessToken() as? AccessTokenFailure)?.error }
        assertError(expiry, .reauthenticate, "sessionExpired")
        XCTAssertEqual(network.matching("POST", tokenPath).count, 1, "token requests")
        let after = try await dart.sessionState()
        XCTAssertEqual(after, .unauthenticated)
        let claimsAfter = try await dart.claims()
        XCTAssertNil(claimsAfter)

        // A later ask makes no refresh attempt and surfaces Reauthenticate too: nothing to refresh with.
        let later = try failure(await dart.accessToken())
        assertError(later, .reauthenticate, "grantRejected")
        XCTAssertEqual(network.matching("POST", tokenPath).count, 1)
        XCTAssertEqual(browser.opened.count, 1)
        XCTAssertFalse(network.transcript.contains { $0.url.hasPrefix(metadata.authorizationEndpoint) })
    }

    func test31TheAuthenticatedSessionObservingTheExpiryFirstSurfacesSessionExpiredWithoutARefreshAttempt() async throws {
        let bridge = try await bridge(clientId: Provider.noRefreshClientId, scopes: provider.noRefreshScopes)
        try ok(await bridge.dart.login())
        let tokenPath = path(try await bridge.native.metadata().tokenEndpoint)
        let dart = bridge.dart

        let expiry = try await expiryObservedBy { (try await dart.userInfo() as? UserInfoFailure)?.error }

        assertError(expiry, .reauthenticate, "sessionExpired")
        XCTAssertEqual(network.matching("POST", tokenPath).count, 1)
        let state = try await dart.sessionState()
        XCTAssertEqual(state, .unauthenticated)
        let claims = try await dart.claims()
        XCTAssertNil(claims)
        XCTAssertEqual(browser.opened.count, 1)
    }
}
