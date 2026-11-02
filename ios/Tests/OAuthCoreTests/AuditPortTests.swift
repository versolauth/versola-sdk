import Foundation
import XCTest
@testable import OAuthCore

/// Behaviours ported from the Android audit fixes by `spec/` (C9, D12): logout and refresh, and the debug log level.
extension SessionCoordinatorTests {
    /// AUDIT C9: a refresh started while `logout()` is running is refused and leaves `loggingOut` alone: it would
    /// spend the token the logout is wiping, and publish its answer over the state.
    func testARefreshStartedWhileLogoutIsInProgressIsRefusedAndLeavesLoggingOutAlone() async throws {
        let gate = Gate()
        let store = MemoryCredentials()
        let browser = ScriptedBrowser { uri, _ in
            if uri.path.hasSuffix("/logout") {
                await gate.wait()
                return .userCancelled
            }
            return .redirect(AuthzKit.redirect(answering: uri))
        }
        let f = try fixture(answers: [.success(response(refresh: "rt-1")), .success(response(refresh: "rt-2"))], store: store, browser: browser)
        try await f.coordinator.login(scopes: ["openid"])

        let logout = Task { await f.coordinator.logout(revoke: false, endSession: true) }
        await AuthzKit.waitUntil("the logout is on its end-session page") { await browser.opened.contains { $0.path.hasSuffix("/logout") } }

        do {
            _ = try await f.coordinator.refresh()
            XCTFail("a refresh was admitted during the logout")
        } catch let error as OAuthError {
            XCTAssertEqual(error, .reauthenticate(.grantRejected))
        }
        let during = await f.flow.states.current
        XCTAssertEqual(during, .loggingOut)
        let refreshCalls = await f.tokens.calls.filter { if case .refresh = $0 { true } else { false } }
        XCTAssertTrue(refreshCalls.isEmpty)

        await gate.open()
        _ = await logout.value
        let after = await f.flow.states.current
        XCTAssertEqual(after, .unauthenticated)
    }

    /// AUDIT D12: a refresh joined onto one in flight is said at debug level, and nothing secret is.
    func testAJoinedRefreshIsLoggedAtDebugWithoutAnySecret() async throws {
        let logger = LoggedLines()
        let f = try fixture(answers: [.success(response(refresh: "rt-1", expiresIn: 60)), .success(response(refresh: "rt-2"))])
        let coordinator = SessionCoordinator(
            flow: f.flow, tokenClient: f.tokens, credentialStore: f.store, clock: Clock(now: { f.clock.peek() }, uptime: { f.clock.peekUptime() }),
            logger: logger, refreshTokens: .optional
        )
        try await coordinator.login(scopes: ["openid"])
        f.clock.advance(61)
        let gate = Gate()
        await f.tokens.hold(gate)

        async let first = coordinator.accessToken()
        async let second = coordinator.accessToken()
        await AuthzKit.waitUntil("both callers reached the token client") { await f.tokens.calls.count == 2 }
        await gate.open()
        _ = try await (first, second)

        XCTAssertTrue(logger.all.contains { $0.hasPrefix("debug: refresh: joined") }, "\(logger.all)")
        XCTAssertFalse(logger.all.contains { $0.contains("rt-1") || $0.contains("rt-2") || $0.contains("access-") })
    }
}

final class DebugLoggerTests: XCTestCase {
    /// AUDIT D12: `debug` has a default that does nothing, so a logger written against `info` and `warn` alone compiles.
    private struct WarningsOnly: OAuthLogger {
        func info(_ message: String) {}
        func warn(_ message: String) {}
    }

    func testALoggerWithoutDebugCompilesAndItsDebugDoesNothing() {
        WarningsOnly().debug("anything")
    }

    func testDiscoveryLogsTheHostFetchedAndNeverTheUrl() async throws {
        let logger = LoggedLines()
        let document = #"{"issuer":"https://id.example.com","authorization_endpoint":"https://id.example.com/authorize","token_endpoint":"https://id.example.com/token","jwks_uri":"https://id.example.com/jwks"}"#
        let service = DiscoveryService(
            issuer: "https://id.example.com", client: HTTPDiscoveryClient(httpClient: RecordingHTTP.json(200, document)),
            cache: MemoryMetadataCache(), logger: logger
        )

        _ = try await service.metadata()
        _ = try await service.metadata()

        XCTAssertTrue(logger.all.contains("debug: discovery: fetched from id.example.com"), "\(logger.all)")
        XCTAssertTrue(logger.all.contains { $0.hasPrefix("debug: discovery: served") })
        XCTAssertFalse(logger.all.contains { $0.contains("/.well-known") || $0.contains("https://") })
    }
}
