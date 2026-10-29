import Foundation
import OAuthCore
import XCTest
@testable import OAuthClient
@testable import versola_oauth

/// `28-explicit-endpoints` through the bridge: a provider without discovery, configured from the
/// explicit endpoints of `EndpointsMessage`. The refused configurations answer `create` itself with
/// the typed error, before any native client exists. Source: `Scenario28ExplicitEndpointsTest`.
final class Scenario28ExplicitEndpointsBridgeTest: BridgeConformance {
    private static let discovery = "/.well-known/openid-configuration"

    /// The provider's real endpoints, read from its own discovery once (not through the virtual
    /// network, whose discovery this scenario answers 404) and re-rooted at the proxy.
    private func endpoints() async throws -> ProviderEndpoints {
        let (data, _) = try await URLSession.shared.data(from: URL(string: provider.issuer + Self.discovery)!)
        let document = try XCTUnwrap(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        let origin = provider.origin
        func at(_ name: String) -> String? {
            (document[name] as? String)?.replacingOccurrences(of: origin, with: Provider.proxyOrigin)
        }
        return ProviderEndpoints(
            // As the provider announces it, trailing slash included (Hydra): with explicit
            // endpoints the ID token's iss is held to this value byte for byte.
            issuer: try XCTUnwrap(at("issuer")),
            authorizationEndpoint: try XCTUnwrap(at("authorization_endpoint")),
            tokenEndpoint: try XCTUnwrap(at("token_endpoint")),
            jwksUri: try XCTUnwrap(at("jwks_uri")),
            userinfoEndpoint: at("userinfo_endpoint"),
            revocationEndpoint: at("revocation_endpoint")
            // No end_session_endpoint and no PAR endpoint, by the scenario's precondition.
        )
    }

    func test28TheWholeFlowRunsWithoutEverRequestingDiscovery() async throws {
        // The discovery document only: a provider may serve its JWKS under /.well-known/ too
        // (Hydra's /.well-known/jwks.json), and that is a configured endpoint here.
        network.intercept { request in
            request.url?.path.hasSuffix(Self.discovery) == true ? VirtualNetwork.StubAnswer(status: 404) : nil
        }
        let endpoints = try await endpoints()
        let bridge = try await bridge(endpoints: endpoints)

        try ok(await bridge.dart.login())

        let state = try await bridge.dart.sessionState()
        XCTAssertEqual(state, .authenticated)
        XCTAssertFalse(network.transcript.contains { $0.url.hasSuffix(Self.discovery) })
        XCTAssertFalse(network.requests.contains { $0.url?.path.hasSuffix(Self.discovery) == true })
        // The ID token was validated against the configured jwksUri (the only one there is).
        XCTAssertEqual(network.matching("GET", path(endpoints.jwksUri)).count, 1)
        // PAR was not attempted: the first POST is the code exchange.
        let firstPost = try XCTUnwrap(network.transcript.first { $0.method == "POST" })
        XCTAssertEqual(firstPost.url, endpoints.tokenEndpoint)
        // iss was on the redirect (the provider sends it) and was checked: a login succeeded.
        XCTAssertEqual(browser.opened.count, 1)
        XCTAssertTrue(try XCTUnwrap(browser.opened.first).absoluteString.hasPrefix(endpoints.authorizationEndpoint + "?"))

        let claims = try await bridge.dart.claims()
        let accessToken = try token(await bridge.dart.accessToken())
        try await assertTokenIsUsableAtTheResource(accessToken, subject: try XCTUnwrap(claims).subject)

        let outcome = try await bridge.dart.logout()

        XCTAssertEqual(browser.opened.count, 1)
        XCTAssertFalse(outcome.sessionEnded)
        XCTAssertTrue(outcome.tokenRevoked)
        let revocation = try XCTUnwrap(endpoints.revocationEndpoint)
        XCTAssertEqual(network.matching("POST", path(revocation)).count, 1)
        let after = try await bridge.dart.sessionState()
        XCTAssertEqual(after, .unauthenticated)
        let claimsAfter = try await bridge.dart.claims()
        XCTAssertNil(claimsAfter)
        let next = try await bridge.dart.accessToken()
        XCTAssertEqual(try failure(next).category, .reauthenticate)
        XCTAssertFalse(network.transcript.contains { $0.url.hasSuffix(Self.discovery) })
    }

    func test28IssuerTogetherWithEndpointsOrAnEndpointThatIsNotHttpsIsRefusedAtConstruction() async throws {
        let endpoints = try await endpoints()
        let both = try await dart(handle: "issuer-and-endpoints").create(message(endpoints: endpoints, issuer: proxyIssuer))
        assertError(try failure(both), .configuration, "invalidConfiguration")

        let plain = message(
            endpoints: ProviderEndpoints(
                issuer: "http://provider.example.com",
                authorizationEndpoint: "http://provider.example.com/authorize",
                tokenEndpoint: "http://provider.example.com/token",
                jwksUri: "http://provider.example.com/jwks"
            ),
            protectedOrigins: []
        )
        let refused = try await dart(handle: "plain-endpoints").create(plain)
        assertError(try failure(refused), .configuration, "invalidConfiguration")
    }
}
