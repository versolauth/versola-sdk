import Foundation
import OAuthCore
import XCTest
@testable import OAuthClient

/// `32-protected-origins`: the authenticated session attaches a token only to configured
/// origins and treats them exactly. As on Android, two of the scenario's cases are not provable
/// on loopback, where the facade allows `http` (`spec/oauth-sdk-api.md` section 3): "the first
/// origin over http" is indistinguishable from the first origin here, and the DPoP case needs
/// the Secure Enclave (device tier). The non-https refusal is asserted with a non-loopback host
/// instead.
final class Scenario32ProtectedOriginsTest: ProviderConformance {
    /// The same server under another host name: the virtual network answers per origin string,
    /// so this origin gets its own copy of the resource.
    private static let otherHostOrigin = "http://127.0.0.1:18080"

    func test32OnlyTheConfiguredOriginWithAnyPathAndQueryCarriesAuthorization() async throws {
        ResourceServer.install(network, origin: ResourceServer.secondOrigin)
        ResourceServer.install(network, origin: Self.otherHostOrigin)
        let client = try await client()
        try await client.login()
        let tokenPath = path(try await client.metadata().tokenEndpoint)
        let session = try client.authenticatedSession()
        func get(_ url: String) async throws -> HTTPURLResponse {
            try await session.data(for: URLRequest(url: URL(string: url)!)).1
        }

        let configured = try await get(ResourceServer.origin + "/api")
        let withPathAndQuery = try await get(ResourceServer.origin + "/api/items?page=2")
        // The same host on another port, and the same server under another host name.
        let otherPort = try await get(ResourceServer.secondOrigin + "/api")
        let otherHost = try await get(Self.otherHostOrigin + "/api")

        XCTAssertEqual(configured.statusCode, 200)
        XCTAssertEqual(withPathAndQuery.statusCode, 200)
        XCTAssertEqual(otherPort.statusCode, 401)
        XCTAssertEqual(otherHost.statusCode, 401)
        let sent = network.transcript.filter { $0.url.contains("/api") }
        XCTAssertEqual(sent.count, 4)
        for entry in sent where entry.url.hasPrefix(ResourceServer.origin) {
            XCTAssertEqual(entry.header("Authorization")?.hasPrefix("Bearer "), true, entry.url)
        }
        for entry in sent where !entry.url.hasPrefix(ResourceServer.origin) {
            XCTAssertNil(entry.header("Authorization"), entry.url)
        }
        // A 401 from an origin that is not protected does not spend the refresh token.
        XCTAssertEqual(network.matching("POST", tokenPath).count, 1)

        // A redirect from the protected origin is returned, not followed.
        let redirected = try await get(ResourceServer.origin + "/redirect")
        XCTAssertEqual(redirected.statusCode, 302)
        XCTAssertFalse(network.transcript.contains { $0.url.contains("elsewhere.example.com") })
    }

    func test32AnEmptyOriginSetAndANonHttpsOriginAreRefusedWithInvalidConfiguration() async throws {
        let client = try await client()

        let empty = await oauthError { _ = try client.authenticatedSession(origins: []) }
        guard case .configuration(.invalidConfiguration)? = empty else { return XCTFail("expected invalidConfiguration, got \(String(describing: empty))") }
        let plain = await oauthError { _ = try client.authenticatedSession(origins: ["http://api.example.com"]) }
        guard case .configuration(.invalidConfiguration)? = plain else { return XCTFail("expected invalidConfiguration, got \(String(describing: plain))") }
    }
}
