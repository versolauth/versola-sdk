import Flutter
import Foundation
import VersolaSDK
import XCTest

@testable import versola

/// The Swift half of the plugin is glue, and what is worth a unit test in it is the wire: every
/// `OAuthError` case keeps its category and payload, the Versola facade's own `edge_client_unknown`
/// crosses as `unknown` with its name and its stable code, and nothing that is not an `OAuthError`
/// carries its text across. The scenarios against a real edge are the native SDK's own tier
/// (`conformance/README.md`); `flutter test` proves the Dart half against a mocked channel. (The
/// file keeps the name of the template's, which the Xcode project already compiles.)
final class WireMappingTests: XCTestCase {
    func testEveryCategoryKeepsItsKindAndPayload() {
        let network = OAuthError.recoverable(.network(detail: "timeout", attempts: 3, elapsedMillis: 1200)).toMessage()
        XCTAssertEqual(network.category, .recoverable)
        XCTAssertEqual(network.kind, "network")
        XCTAssertEqual(network.detail, "timeout")
        XCTAssertEqual(network.attempts, 3)
        XCTAssertEqual(network.elapsedMillis, 1200)

        let limited = OAuthError.recoverable(.server(status: 429, retryAfterMillis: 7000, attempts: 1, elapsedMillis: 40)).toMessage()
        XCTAssertEqual(limited.kind, "server")
        XCTAssertEqual(limited.status, 429)
        XCTAssertEqual(limited.retryAfterMillis, 7000)
        let unavailable = OAuthError.recoverable(.server(status: 503, retryAfterMillis: nil, attempts: 3, elapsedMillis: 1750)).toMessage()
        XCTAssertNil(unavailable.retryAfterMillis, "no Retry-After stays absent across the bridge")

        let interaction = OAuthError.reauthenticate(.interactionRequired(code: "login_required")).toMessage()
        XCTAssertEqual(interaction.category, .reauthenticate)
        XCTAssertEqual(interaction.kind, "interactionRequired")
        XCTAssertEqual(interaction.code, "login_required")

        let stepUp = OAuthError.stepUp(acrValues: ["sensitive"], maxAge: 300).toMessage()
        XCTAssertEqual(stepUp.category, .stepUp)
        XCTAssertEqual(stepUp.acrValues, ["sensitive"])
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

    func testAccountMismatchIsItsOwnRecoverableCauseWithItsStableCode() {
        let message = OAuthError.recoverable(.accountMismatch).toMessage()
        XCTAssertEqual(message.category, .recoverable)
        XCTAssertEqual(message.kind, "accountMismatch")
        XCTAssertEqual(message.sdkCode, "recoverable.account_mismatch")
    }

    func testEdgeClientUnknownCrossesAsTheUnknownDetailNamedWithItsStableCodeAndWithoutThePayload() {
        let message = OAuthError.configuration(.facade(name: "edge_client_unknown", detail: "mobile-app")).toMessage()
        XCTAssertEqual(message.category, .configuration)
        XCTAssertEqual(message.kind, "unknown", "no Dart enum value exists for it: never a guessed real case")
        XCTAssertEqual(message.detail, "edge_client_unknown")
        XCTAssertEqual(message.sdkCode, "configuration.edge_client_unknown")
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

    func testEveryLoginOptionReachesTheSdkOptionsUntouched() {
        let claims = #"{"id_token":{"email":{"essential":true}}}"#
        let details = #"[{"type":"payment"}]"#
        let options = VersolaLoginOptionsMessage(
            scopes: ["profile", "email"], acrValues: ["sensitive"], maxAge: 300, prompt: .selectAccount,
            loginHint: "alice@example.com", uiLocales: ["de", "en"], resources: ["https://api.example.com"],
            claims: claims, authorizationDetails: details, ephemeralBrowser: true
        ).toLoginOptions()
        XCTAssertEqual(options.scopes, ["profile", "email"])
        XCTAssertEqual(options.acrValues, ["sensitive"])
        XCTAssertEqual(options.maxAge, 300)
        XCTAssertEqual(options.prompt, .selectAccount)
        XCTAssertEqual(options.loginHint, "alice@example.com")
        XCTAssertEqual(options.uiLocales, ["de", "en"])
        XCTAssertEqual(options.resources, ["https://api.example.com"])
        XCTAssertEqual(options.claims, claims)
        XCTAssertEqual(options.authorizationDetails, details)
        XCTAssertTrue(options.ephemeralBrowser)
        XCTAssertNil(VersolaLoginOptionsMessage(scopes: [], acrValues: [], uiLocales: [], resources: [], ephemeralBrowser: false).toLoginOptions().prompt)
    }

    func testTheConfigurationMessageBuildsTheSdkConfigurationAndAnAbsentIssuerIsTheEdge() throws {
        var message = VersolaConfigurationMessage(
            edgeUrl: "https://id.example.com", clientId: "app", redirectUri: "https://app.example.com/oauth",
            issuer: nil, postLogoutRedirectUri: nil, requireHardwareKey: true, unlockPolicy: .onAppUnlock,
            clockSkewToleranceSeconds: 30, retryPolicy: nil
        )
        let configuration = try message.toConfiguration()
        XCTAssertEqual(configuration.issuer, "https://id.example.com", "the SDK's default, not the glue's")
        XCTAssertTrue(configuration.requireHardwareKey)
        XCTAssertEqual(configuration.clockSkewTolerance, 30)

        message.issuer = "https://id.example.com/"
        XCTAssertEqual(try message.toConfiguration().issuer, "https://id.example.com/")

        message.redirectUri = "myapp://callback"
        XCTAssertThrowsError(try message.toConfiguration(), "a private-use scheme is refused by the SDK, not repaired here")
    }

    func testARequestKeepsItsMethodUrlHeadersAndBytesAndAMalformedHeaderIsRefusedWithoutQuotingIt() throws {
        let request = try VersolaHttpRequestMessage(
            method: "POST", url: "https://id.example.com/resources/items?page=2",
            headers: [VersolaHttpHeaderMessage(name: "X-Trace", value: "abc")],
            body: FlutterStandardTypedData(bytes: Data("payload".utf8))
        ).toURLRequest()
        XCTAssertEqual(request.httpMethod, "POST")
        XCTAssertEqual(request.url?.absoluteString, "https://id.example.com/resources/items?page=2")
        XCTAssertEqual(request.value(forHTTPHeaderField: "x-trace"), "abc")
        XCTAssertEqual(request.httpBody, Data("payload".utf8))
        XCTAssertNil(request.value(forHTTPHeaderField: "Authorization"))

        let bad = VersolaHttpRequestMessage(
            method: "GET", url: "https://id.example.com/",
            headers: [VersolaHttpHeaderMessage(name: "Authorization", value: "Bearer s3cr3t\u{e9}")], body: nil
        )
        XCTAssertThrowsError(try bad.toURLRequest()) { error in
            XCTAssertFalse(String(describing: error).contains("s3cr3t"))
        }
        let withBody = VersolaHttpRequestMessage(
            method: "GET", url: "https://id.example.com/", headers: [],
            body: FlutterStandardTypedData(bytes: Data([1]))
        )
        XCTAssertThrowsError(try withBody.toURLRequest(), "a body on GET is refused, not dropped")
    }
}
