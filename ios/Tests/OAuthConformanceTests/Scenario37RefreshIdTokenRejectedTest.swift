import Foundation
@testable import OAuthCore
import XCTest
@testable import OAuthClient

/// `37-refresh-id-token-rejected-keeps-rotation`: the provider rotated the refresh token the
/// moment it answered, so an ID token the SDK then rejects must cost the app that ID token and
/// nothing else. Against a rotating provider (Hydra) a platform that dropped the new token fails
/// the second refresh with `invalid_grant`; against one that reuses the token (Keycloak's default)
/// the scenario passes without proving the point, which the scenario's last assertion says.
final class Scenario37RefreshIdTokenRejectedTest: ProviderConformance {
    func test37ARejectedIdTokenOnRefreshKeepsTheRotatedRefreshToken() async throws {
        let client = try await client()
        try await client.login()
        let claimsBefore = await client.claims
        let metadata = try await client.metadata()
        let tokenPath = path(metadata.tokenEndpoint)
        network.rewriteJSON(tokenPath) { response in
            guard let idToken = response["id_token"] as? String else { return response }
            let parts = idToken.split(separator: ".").map(String.init)
            guard parts.count == 3, var signature = Base64Url.decode(parts[2]), !signature.isEmpty else { return response }
            signature[signature.startIndex] ^= 0x55
            return HarnessSigner.withIdToken(response, "\(parts[0]).\(parts[1]).\(Base64Url.encode(signature))")
        }
        let refreshesBefore = network.matching("POST", tokenPath).filter { $0.field("grant_type") == "refresh_token" }

        let error = await oauthError { try await client.refresh() }

        XCTAssertEqual(error, .configuration(.idTokenRejected(.signature)))
        let first = network.matching("POST", tokenPath).filter { $0.field("grant_type") == "refresh_token" }.dropFirst(refreshesBefore.count)
        XCTAssertEqual(first.count, 1, "the rejection was not retried")
        let state = await client.sessionState
        XCTAssertEqual(state, .authenticated)
        let claimsAfter = await client.claims
        XCTAssertEqual(claimsAfter?.subject, claimsBefore?.subject)

        network.clearRewrites()
        try await client.refresh()

        let second = network.matching("POST", tokenPath).filter { $0.field("grant_type") == "refresh_token" }.last
        XCTAssertNotNil(second, "the second refresh reached the provider")
        let stateAfter = await client.sessionState
        XCTAssertEqual(stateAfter, .authenticated, "not invalid_grant: the token the first refresh was answered with was kept")
        if let rotatedTo = first.first?.responseJSON?["refresh_token"] as? String, rotatedTo != first.first?.field("refresh_token") {
            XCTAssertEqual(second?.field("refresh_token"), rotatedTo, "the rotated token was spent, not the one it replaced")
        }
    }
}
