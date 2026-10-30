import Foundation
import OAuthCore
import XCTest
@testable import OAuthClient
@testable import versola_oauth

/// `34-server-error-per-operation`, `35-retry-after` and `36-retry-after-cooldown` through the
/// bridge: the typed `server` error reaches Dart with its status, `retryAfterMillis` and attempt
/// count, and a call the cooldown refused arrives with `attempts` 0. Source:
/// `Scenario34To36ServerErrorsTest` (the native driver, which proves the counts and the timing
/// against the provider; this proves what crosses the wire to Dart).
final class Scenario34To36ServerErrorsBridgeTest: BridgeConformance {
    private static let discovery = "/.well-known/openid-configuration"

    /// `respond-with-status`: answers requests to `pathSuffix` with `status` and `headers`, the
    /// first `times` of them (all when nil), and forwards the rest.
    private func respondWith(_ pathSuffix: String, status: Int, headers: [String: String] = [:], times: Int? = nil) {
        let count = ServerErrorsCounter()
        network.intercept { request in
            guard request.url?.path.hasSuffix(pathSuffix) == true else { return nil }
            let index = count.next()
            if let times, index >= times { return nil }
            return VirtualNetwork.StubAnswer(status: status, headers: headers)
        }
    }

    private func signedIn() async throws -> (Bridge, ProviderMetadata) {
        network.rewriteJSON(Self.discovery) { document in
            var copy = document
            copy.removeValue(forKey: "end_session_endpoint")
            return copy
        }
        let bridge = try await bridge()
        try ok(await bridge.dart.login())
        return (bridge, try await bridge.native.metadata())
    }

    private func refreshes(_ metadata: ProviderMetadata) -> Int {
        network.matching("POST", path(metadata.tokenEndpoint)).filter { $0.field("grant_type") == "refresh_token" }.count
    }

    func test34ARefreshAnswered503ArrivesInDartAsServerWithItsStatusAndThreeAttempts() async throws {
        let (bridge, metadata) = try await signedIn()
        respondWith(path(metadata.tokenEndpoint), status: 503)

        let error = try failure(try await bridge.dart.refresh())

        assertError(error, .recoverable, "server")
        XCTAssertEqual(error.status, 503)
        XCTAssertEqual(error.attempts, 3)
        XCTAssertNil(error.retryAfterMillis)
        XCTAssertEqual(refreshes(metadata), 3)
        let state = try await bridge.dart.sessionState()
        XCTAssertEqual(state, .authenticated)

        // The grant survived: once the provider answers, the same session refreshes through the bridge.
        network.clearRewrites()
        try ok(await bridge.dart.refresh())
    }

    func test34ARefreshAnswered500IsOneRequestBecauseTheFacadeSendsNoIdempotencyKey() async throws {
        let (bridge, metadata) = try await signedIn()
        respondWith(path(metadata.tokenEndpoint), status: 500)

        let error = try failure(try await bridge.dart.refresh())

        assertError(error, .recoverable, "server")
        XCTAssertEqual(error.status, 500)
        XCTAssertEqual(error.attempts, 1)
        XCTAssertEqual(refreshes(metadata), 1)
    }

    func test34UserInfoAnswered503ArrivesAsAServerErrorAfterThreeAttempts() async throws {
        let (bridge, metadata) = try await signedIn()
        guard let endpoint = metadata.userinfoEndpoint else { throw XCTSkip("the provider advertises no userinfo_endpoint") }
        respondWith(path(endpoint), status: 503)

        let error = try failure(try await bridge.dart.userInfo())

        assertError(error, .recoverable, "server")
        XCTAssertEqual(error.status, 503)
        XCTAssertEqual(error.attempts, 3)
        XCTAssertEqual(network.matching("GET", path(endpoint)).count, 3)
    }

    func test35ARetryAfterBeyondTheBudgetArrivesWithItsValueAndAfterwardsTheCooldownRefusalHasZeroAttempts() async throws {
        let (bridge, metadata) = try await signedIn()
        respondWith(path(metadata.tokenEndpoint), status: 429, headers: ["Retry-After": "30"])

        let first = try failure(try await bridge.dart.refresh())

        assertError(first, .recoverable, "server")
        XCTAssertEqual(first.status, 429)
        XCTAssertEqual(first.retryAfterMillis, 30_000)
        XCTAssertEqual(first.attempts, 1)
        XCTAssertEqual(refreshes(metadata), 1)
        let sent = network.transcript.count

        // Inside the window: refused at once, nothing sent, and the typed error says so.
        let second = try failure(try await bridge.dart.refresh())
        assertError(second, .recoverable, "server")
        XCTAssertEqual(second.status, 429)
        XCTAssertEqual(second.attempts, 0)
        XCTAssertTrue((1...30_000).contains(second.retryAfterMillis ?? 0), "left \(String(describing: second.retryAfterMillis))")
        let info = try failure(try await bridge.dart.userInfo())
        XCTAssertEqual(info.attempts, 0)
        XCTAssertEqual(network.transcript.count, sent, "nothing was sent while the server asked for quiet")
        let state = try await bridge.dart.sessionState()
        XCTAssertEqual(state, .authenticated)
    }

    func test35AMalformedRetryAfterArrivesAsAbsent() async throws {
        let (bridge, metadata) = try await signedIn()
        respondWith(path(metadata.tokenEndpoint), status: 503, headers: ["Retry-After": "soon"])

        let error = try failure(try await bridge.dart.refresh())

        assertError(error, .recoverable, "server")
        XCTAssertNil(error.retryAfterMillis)
        XCTAssertEqual(error.attempts, 3)
    }
}

/// A request counter the intercept closure, which is `@Sendable`, can share with the test.
private final class ServerErrorsCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var value = 0
    func next() -> Int {
        lock.lock()
        defer { lock.unlock() }
        defer { value += 1 }
        return value
    }
}
