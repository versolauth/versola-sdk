import Foundation
import XCTest
@testable import OAuthCore
@testable import VersolaEdge

/// What the core reads from metadata, stated from configuration with no network
/// (`spec/versola-sdk-api.md` sections 1 and 12). The Android `EdgeMetadataTest`'s twin.
final class EdgeMetadataTests: XCTestCase {
    private typealias F = EdgeFixture

    private func metadata(issuer: String = F.issuer, edge: String = "https://id.example.com") throws -> ProviderMetadata {
        try EdgeMetadata(issuer: issuer, edgeUrl: URL(string: edge)!, clientId: F.clientId).metadata
    }

    func testIssuerIsExactlyAsConfiguredAndEndpointsAreEdgesNativeUrls() throws {
        let document = try metadata()
        XCTAssertEqual(document.issuer, "https://id.example.com")
        XCTAssertEqual(document.tokenEndpoint, F.tokenUrl)
        XCTAssertEqual(document.revocationEndpoint, F.revokeUrl)
        XCTAssertEqual(document.authorizationEndpoint, "https://id.example.com/authorize")
        XCTAssertEqual(document.endSessionEndpoint, "https://id.example.com/logout")
    }

    func testTrailingSlashOfTheIssuerIsPreservedInTheIssuerAndNotDoubledInTheEndpoints() throws {
        let document = try metadata(issuer: "https://id.example.com/")
        XCTAssertEqual(document.issuer, "https://id.example.com/")
        XCTAssertEqual(document.authorizationEndpoint, "https://id.example.com/authorize")
        XCTAssertEqual(document.endSessionEndpoint, "https://id.example.com/logout")
    }

    func testAPartnersIssuerAndEdgeAreIndependent() throws {
        let document = try metadata(issuer: "https://operator.example.org", edge: "https://partner-edge.example.com")
        XCTAssertEqual(document.issuer, "https://operator.example.org")
        XCTAssertEqual(document.endSessionEndpoint, "https://operator.example.org/logout")
        XCTAssertEqual(document.tokenEndpoint, "https://partner-edge.example.com/native/token/mobile-app", "budgets and cooldowns are keyed by edge's origin")
    }

    func testDpopEs256AndTheIssParameterAreAdvertised() throws {
        let document = try metadata()
        XCTAssertEqual(document.dpopSigningAlgValuesSupported, ["ES256"])
        XCTAssertTrue(document.supportsDpop)
        XCTAssertTrue(document.authorizationResponseIssParameterSupported)
        XCTAssertNil(document.pushedAuthorizationRequestEndpoint, "edge pushes the request itself")
        XCTAssertNil(document.userinfoEndpoint)
        XCTAssertNil(document.jwksUri, "nothing a native app reaches serves a key set")
    }

    func testDiscoveryServiceServesItWithoutAnyRequestAndAcceptsATrailingSlashIssuer() async throws {
        let configured = "https://id.example.com/"
        let service = DiscoveryService(
            issuer: "https://id.example.com", client: try EdgeMetadata(issuer: configured, edgeUrl: F.edgeUrl, clientId: F.clientId), cache: MemoryMetadataCache()
        )
        let served = try await service.metadata()
        XCTAssertEqual(served.issuer, configured)
        XCTAssertEqual(served.tokenEndpoint, F.tokenUrl)
    }

    func testClientIdWithSpecialCharactersIsEncodedInTheNativeUrls() throws {
        let document = try EdgeMetadata(issuer: F.issuer, edgeUrl: F.edgeUrl, clientId: "a b/c").metadata
        XCTAssertEqual(document.tokenEndpoint, "https://id.example.com/native/token/a%20b%2Fc")
    }
}
