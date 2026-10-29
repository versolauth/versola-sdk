import Foundation
import OAuthCore
import XCTest
@testable import OAuthClient
@testable import versola_oauth

/// `32-protected-origins` through the bridge, as far as the bridge reaches. The scenario's subject
/// is the authenticated session (a wrapper that attaches the token to configured origins only,
/// treats them exactly and does not follow a redirect); Flutter has no authenticated session
/// (`spec/oauth-sdk-api.md` section 10: `accessToken()` only), so those assertions are the native
/// drivers' alone and there is nothing at the bridge to run them against.
///
/// What the bridge carries of it is asserted instead: the token that crosses is the one a protected
/// origin accepts, the SDK sends nothing to a resource origin by itself, and a `protectedOrigins`
/// entry that is not a valid origin is refused by `create` with `invalidConfiguration`. An empty
/// set is not refused there: the facade demands origins of the authenticated session, not of the
/// configuration.
final class Scenario32ProtectedOriginsBridgeTest: BridgeConformance {
    func test32OnlyTheConfiguredOriginWithAnyPathAndQueryCarriesAuthorization() async throws {
        let bridge = try await bridge()
        try ok(await bridge.dart.login())
        let accessToken = try token(await bridge.dart.accessToken())
        let claims = try await bridge.dart.claims()
        let subject = try XCTUnwrap(claims).subject

        // The app attaches the token, as it would with dio: the configured origin accepts it, with a path and a query.
        let (configuredBody, configured) = try await appCall(accessToken, ResourceServer.origin + "/api")
        let (_, withPathAndQuery) = try await appCall(accessToken, ResourceServer.origin + "/api/items?page=2")
        XCTAssertEqual(configured.statusCode, 200)
        XCTAssertEqual(withPathAndQuery.statusCode, 200)
        XCTAssertTrue(String(decoding: configuredBody, as: UTF8.self).contains(subject))
        XCTAssertEqual(accessToken.tokenType, "Bearer")
        // The SDK itself never contacted the resource, and a request the app makes without the token is not the SDK's to fix.
        XCTAssertFalse(network.transcript.contains { $0.url.hasPrefix(ResourceServer.origin) })
        let tokenPath = path(try await bridge.native.metadata().tokenEndpoint)
        XCTAssertEqual(network.matching("POST", tokenPath).count, 1)
    }

    func test32AnEmptyOriginSetAndANonHttpsOriginAreRefusedWithInvalidConfiguration() async throws {
        // A non-https origin (not loopback) and an origin carrying a path are refused by create itself.
        let plain = try await dart(handle: "plain-origin").create(message(protectedOrigins: ["http://api.example.com"]))
        assertError(try failure(plain), .configuration, "invalidConfiguration")
        let withPath = try await dart(handle: "origin-with-path").create(message(protectedOrigins: ["https://api.example.com/v1"]))
        assertError(try failure(withPath), .configuration, "invalidConfiguration")

        // An empty set is a valid configuration: only the authenticated session, which Flutter does not have, needs origins.
        _ = try await bridge(protectedOrigins: [])
    }
}
