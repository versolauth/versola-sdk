import OAuthClient
import XCTest

@testable import versola_oauth

/// The Swift half of the plugin is glue, and what is worth a unit test in it is the wire: every
/// `OAuthError` case keeps its category and payload, and nothing that is not an `OAuthError`
/// carries its text across. The scenarios run against a real provider are the native SDK's own
/// tier (`conformance/README.md`); `flutter test` proves the Dart half against a mocked channel.
final class WireMappingTests: XCTestCase {
    func testEveryCategoryKeepsItsKindAndPayload() {
        let network = OAuthError.recoverable(.network(detail: "timeout", attempts: 3, elapsedMillis: 1200)).toMessage()
        XCTAssertEqual(network.category, .recoverable)
        XCTAssertEqual(network.kind, "network")
        XCTAssertEqual(network.detail, "timeout")
        XCTAssertEqual(network.attempts, 3)
        XCTAssertEqual(network.elapsedMillis, 1200)

        let interaction = OAuthError.reauthenticate(.interactionRequired(code: "login_required")).toMessage()
        XCTAssertEqual(interaction.category, .reauthenticate)
        XCTAssertEqual(interaction.kind, "interactionRequired")
        XCTAssertEqual(interaction.code, "login_required")

        let stepUp = OAuthError.stepUp(acrValues: ["urn:acr:mfa"], maxAge: 300).toMessage()
        XCTAssertEqual(stepUp.category, .stepUp)
        XCTAssertEqual(stepUp.acrValues, ["urn:acr:mfa"])
        XCTAssertEqual(stepUp.maxAge, 300)

        let rejected = OAuthError.configuration(.tokenRequestRejected(code: "invalid_grant", description: "expired")).toMessage()
        XCTAssertEqual(rejected.category, .configuration)
        XCTAssertEqual(rejected.kind, "tokenRequestRejected")
        XCTAssertEqual(rejected.code, "invalid_grant")
        XCTAssertEqual(rejected.errorDescription, "expired")

        let idToken = OAuthError.configuration(.idTokenRejected(.accessTokenHash)).toMessage()
        XCTAssertEqual(idToken.kind, "idTokenRejected")
        XCTAssertEqual(idToken.idTokenRejection, "accessTokenHash")
    }

    func testAnErrorThatIsNotAnSdkErrorCrossesAsAConfigurationNamingOnlyItsType() {
        struct Leaky: Error, CustomStringConvertible {
            var description: String { "refresh_token=do-not-leak" }
        }
        let message = Leaky().toErrorMessage()
        XCTAssertEqual(message.category, .configuration)
        XCTAssertEqual(message.kind, "invalidConfiguration")
        XCTAssertEqual(message.detail, "unexpected Leaky")
        XCTAssertFalse(message.message.contains("do-not-leak"))

        let foundation = NSError(domain: "x", code: 1, userInfo: [NSLocalizedDescriptionKey: "do-not-leak"]).toErrorMessage()
        XCTAssertFalse(foundation.message.contains("do-not-leak"))
        XCTAssertFalse((foundation.detail ?? "").contains("do-not-leak"))
    }

    func testTheSevenSessionStatesMapOneToOneAndInOrder() {
        let states: [SessionState] = [.unauthenticated, .authorizing, .authenticated, .refreshing, .stepUpRequired, .locked, .loggingOut]
        XCTAssertEqual(states.map { $0.toMessage().rawValue }, Array(0..<7))
    }

    func testTheAuthorizationSchemeIsTheSpecsSpellingWhateverTheProviderSent() {
        XCTAssertEqual(VersolaOAuthPlugin.scheme(for: "bearer"), "Bearer")
        XCTAssertEqual(VersolaOAuthPlugin.scheme(for: "Bearer"), "Bearer")
        XCTAssertEqual(VersolaOAuthPlugin.scheme(for: "DPoP"), "DPoP")
        XCTAssertEqual(VersolaOAuthPlugin.scheme(for: "dpop"), "DPoP")
        // Anything else is Bearer: a DPoP-bound request answered with another type never gets this far.
        XCTAssertEqual(VersolaOAuthPlugin.scheme(for: "MAC"), "Bearer")
    }
}
