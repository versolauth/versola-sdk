import Foundation
import OAuthCore
import XCTest
@testable import OAuthClient
@testable import versola_oauth

/// `30-logout-without-end-session` through the bridge: sign-out revokes, wipes, and says what the
/// server did, in `LogoutOutcomeMessage`. Source: `Scenario30LogoutTest`.
final class Scenario30LogoutBridgeTest: BridgeConformance {
    private static let discovery = "/.well-known/openid-configuration"

    private func withoutEndSession() {
        network.rewriteJSON(Self.discovery) { document in
            var copy = document
            copy.removeValue(forKey: "end_session_endpoint")
            return copy
        }
    }

    private func assertWiped(_ bridge: Bridge, file: StaticString = #filePath, line: UInt = #line) async throws {
        let state = try await bridge.dart.sessionState()
        XCTAssertEqual(state, .unauthenticated, file: file, line: line)
        let claims = try await bridge.dart.claims()
        XCTAssertNil(claims, file: file, line: line)
        let token = try await bridge.dart.accessToken()
        XCTAssertEqual(try failure(token).category, .reauthenticate, file: file, line: line)
    }

    private func assertRevocationRequest(_ entry: TranscriptEntry, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertNotNil(entry.form["token"], file: file, line: line)
        XCTAssertEqual(entry.field("token_type_hint"), "refresh_token", file: file, line: line)
        XCTAssertEqual(entry.field("client_id"), Provider.clientId, file: file, line: line)
        assertNoSecretOnTheWire(entry, file: file, line: line)
    }

    func test30WithoutAnEndSessionEndpointLogoutRevokesOpensNoBrowserAndReportsTheSessionNotEnded() async throws {
        withoutEndSession()
        let bridge = try await bridge()
        try ok(await bridge.dart.login())
        let metadata = try await bridge.native.metadata()

        let outcome = try await bridge.dart.logout()

        XCTAssertEqual(browser.opened.count, 1)
        XCTAssertFalse(outcome.sessionEnded)
        XCTAssertTrue(outcome.tokenRevoked)
        assertRevocationRequest(try theRequest("POST", path(try XCTUnwrap(metadata.revocationEndpoint))))
        try await assertWiped(bridge)
    }

    func test30ARevocationEndpointAnswering503LeavesTokenRevokedFalseWithinTheRetryBudgetAndStillWipes() async throws {
        withoutEndSession()
        let bridge = try await bridge()
        try ok(await bridge.dart.login())
        let metadata = try await bridge.native.metadata()
        let revocationPath = path(try XCTUnwrap(metadata.revocationEndpoint))
        network.intercept { request in
            request.url?.path.hasSuffix(revocationPath) == true ? VirtualNetwork.StubAnswer(status: 503) : nil
        }

        let outcome = try await bridge.dart.logout()

        XCTAssertFalse(outcome.sessionEnded)
        XCTAssertFalse(outcome.tokenRevoked)
        let attempts = network.matching("POST", revocationPath)
        XCTAssertFalse(attempts.isEmpty, "revocation attempts: \(attempts.count)")
        // The default policy: the configuration message carries no retry policy, so the bridge must not have invented one.
        XCTAssertLessThanOrEqual(attempts.count, bridge.native.configuration.retryPolicy.maxAttemptsPerOrigin, "revocation attempts: \(attempts.count)")
        for attempt in attempts { assertRevocationRequest(attempt) }
        try await assertWiped(bridge)
    }

    func test30TheUserDismissingTheEndSessionBrowserLeavesSessionEndedFalseAndStillWipes() async throws {
        let bridge = try await bridge()
        try ok(await bridge.dart.login())
        let metadata = try await bridge.native.metadata()
        guard let endSession = metadata.endSessionEndpoint else { throw XCTSkip("the provider advertises no end_session_endpoint") }
        browser.dismissNext()

        let outcome = try await bridge.dart.logout()

        XCTAssertEqual(browser.opened.count, 2)
        XCTAssertTrue(try XCTUnwrap(browser.opened.last).absoluteString.hasPrefix(endSession + "?"))
        XCTAssertFalse(outcome.sessionEnded)
        XCTAssertTrue(outcome.tokenRevoked)
        try await assertWiped(bridge)
    }
}
