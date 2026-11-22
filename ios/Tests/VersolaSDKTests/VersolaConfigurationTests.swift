import Foundation
import XCTest
@testable import OAuthClient
@testable import OAuthCore
@testable import VersolaSDK

/// `VersolaConfiguration`'s eager validation (`spec/versola-sdk-api.md` section 3) and the options
/// types around it. Every refusal is `configuration(.invalidConfiguration)`, at construction.
final class VersolaConfigurationTests: XCTestCase {
    private func make(
        edgeUrl: String = Sdk.edgeUrl, clientId: String = "mobile-app", redirectUri: String = Sdk.redirect, issuer: String? = nil,
        postLogoutRedirectUri: String? = nil, clockSkewTolerance: TimeInterval = 60
    ) throws -> VersolaConfiguration {
        try VersolaConfiguration(
            edgeUrl: edgeUrl, clientId: clientId, redirectUri: redirectUri, issuer: issuer,
            postLogoutRedirectUri: postLogoutRedirectUri, clockSkewTolerance: clockSkewTolerance
        )
    }

    private func assertInvalid(_ build: () throws -> VersolaConfiguration, _ message: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try build(), message, file: file, line: line) { error in
            guard case .configuration(.invalidConfiguration)? = error as? OAuthError else {
                return XCTFail("\(message): \(error)", file: file, line: line)
            }
        }
    }

    // MARK: defaults

    func testMinimalConfigurationTakesTheDocumentedDefaults() throws {
        let configuration = try make()
        XCTAssertEqual(configuration.issuer, Sdk.edgeUrl, "issuer defaults to edgeUrl as written")
        XCTAssertNil(configuration.postLogoutRedirectUri)
        XCTAssertFalse(configuration.requireHardwareKey)
        XCTAssertEqual(configuration.unlockPolicy, .none)
        XCTAssertEqual(configuration.retryPolicy, .default)
        XCTAssertEqual(configuration.clockSkewTolerance, 60)
        XCTAssertTrue(configuration.urlSession === URLSession.shared)
    }

    func testIssuerDefaultIsEdgeUrlAsWrittenTrailingSlashIncluded() throws {
        let configuration = try make(edgeUrl: "https://id.example.com/")
        XCTAssertEqual(configuration.issuer, "https://id.example.com/")
        XCTAssertEqual(configuration.edgeOrigin, "https://id.example.com")
    }

    func testAnExplicitIssuerIsKeptAsWritten() throws {
        let configuration = try make(edgeUrl: "https://partner-edge.example.com", issuer: "https://operator.example.org/")
        XCTAssertEqual(configuration.issuer, "https://operator.example.org/")
        XCTAssertEqual(configuration.core.issuer, "https://operator.example.org", "the core's copy drops the slash; checks use the configured one")
    }

    // MARK: edgeUrl

    func testEdgeUrlMustBeHttpsOrHttpOnALoopbackHost() throws {
        for edge in ["https://id.example.com", "https://id.example.com/", "https://id.example.com:8443", "http://localhost", "http://localhost:8080",
                     "http://127.0.0.1:8080", "http://[::1]:8080"] {
            XCTAssertNoThrow(try make(edgeUrl: edge), edge)
        }
        for edge in ["http://id.example.com", "http://10.0.2.2:8080", "http://192.168.1.5", "ftp://id.example.com", "id.example.com", "", "https://", "/path"] {
            assertInvalid({ try self.make(edgeUrl: edge) }, edge)
        }
    }

    func testEdgeUrlMustBeAnOriginAndNothingMore() {
        for edge in ["https://id.example.com/api", "https://id.example.com/native", "https://id.example.com?x=1", "https://id.example.com/#frag",
                     "https://id.example.com#frag", "https://user@id.example.com", "https://user:pw@id.example.com"] {
            assertInvalid({ try self.make(edgeUrl: edge) }, edge)
        }
    }

    // MARK: issuer

    func testIssuerMustBeHttpsWithoutQueryOrFragment() {
        for issuer in ["http://id.example.com", "https://id.example.com?x=1", "https://id.example.com#f", "id.example.com", ""] {
            assertInvalid({ try self.make(issuer: issuer) }, issuer)
        }
        XCTAssertNoThrow(try make(issuer: "https://id.example.com/tenant-a"))
        XCTAssertNoThrow(try make(edgeUrl: "http://localhost:8080", issuer: "http://localhost:8080"))
    }

    // MARK: client id

    func testClientIdMustNotBeBlank() {
        for clientId in ["", " ", "\n\t "] {
            assertInvalid({ try self.make(clientId: clientId) }, "client id \(clientId.debugDescription)")
        }
    }

    // MARK: redirect URIs

    func testRedirectUriMustBeAnHttpsLinkWithAHost() {
        XCTAssertNoThrow(try make(redirectUri: "https://app.example.com/callback"))
        XCTAssertNoThrow(try make(redirectUri: "https://app.example.com"))
        for redirect in ["com.example.app:/callback", "myapp://callback", "http://localhost/callback", "http://127.0.0.1:8080/cb",
                         "http://app.example.com/callback", "https:callback", "https://app.example.com/callback#frag", "callback", ""] {
            assertInvalid({ try self.make(redirectUri: redirect) }, redirect)
        }
    }

    func testPostLogoutRedirectUriFollowsTheSameRule() {
        XCTAssertNoThrow(try make(postLogoutRedirectUri: Sdk.postLogout))
        for redirect in ["com.example.app:/signed-out", "http://localhost/signed-out", "http://app.example.com/signed-out", "https:signed-out"] {
            assertInvalid({ try self.make(postLogoutRedirectUri: redirect) }, redirect)
        }
    }

    // MARK: clock skew

    func testClockSkewToleranceIsBetweenZeroAndFiveMinutes() {
        XCTAssertNoThrow(try make(clockSkewTolerance: 0))
        XCTAssertNoThrow(try make(clockSkewTolerance: 300))
        for value in [-1.0, 300.5, 301, .nan, .infinity] {
            assertInvalid({ try self.make(clockSkewTolerance: value) }, "\(value)")
        }
    }

    // MARK: storage

    func testStorageKeyIsAHashOfEdgeIssuerAndClientIdAndNothingElse() throws {
        let base = try make()
        XCTAssertEqual(base.storageKey, try make(redirectUri: "https://other.example.com/cb", postLogoutRedirectUri: Sdk.postLogout).storageKey, "redirects are not part of identity")
        XCTAssertEqual(base.storageKey, try make(edgeUrl: "https://id.example.com/", issuer: "https://id.example.com").storageKey, "the edge origin is without a trailing slash")
        XCTAssertNotEqual(base.storageKey, try make(edgeUrl: "https://id2.example.com", issuer: Sdk.issuer).storageKey)
        XCTAssertNotEqual(base.storageKey, try make(issuer: "https://operator.example.org").storageKey)
        XCTAssertNotEqual(base.storageKey, try make(clientId: "other").storageKey)
        XCTAssertEqual(base.storageKey.count, 16)
        XCTAssertFalse(base.storageKey.contains("example"), "neither a file name nor a Keychain account carries an address")
    }

    func testStorageKeyNeverCollidesWithTheGenericFacadesForTheSameAddressAndClient() throws {
        let versola = try make(clientId: "mobile-app")
        let generic = try OAuthConfiguration(issuer: Sdk.issuer, clientId: "mobile-app", redirectUri: Sdk.redirect)
        XCTAssertNotEqual(versola.storageKey, generic.storageKey, "Keychain service names and cache directories of the two facades are disjoint")
    }

    func testTwoConfigurationsAreTheSameClientWhenTheirFingerprintsAgree() throws {
        XCTAssertEqual(try make().fingerprint, try make().fingerprint)
        XCTAssertNotEqual(try make().fingerprint, try make(redirectUri: "https://other.example.com/cb").fingerprint)
        XCTAssertNotEqual(try make().fingerprint, try make(clockSkewTolerance: 30).fingerprint)
        XCTAssertNotEqual(try make().fingerprint, try make(postLogoutRedirectUri: Sdk.postLogout).fingerprint)
    }
}

/// `LoginOptions` and `Acr`: what is sent is typed, and what cannot be sent is refused by the call.
final class LoginOptionsTests: XCTestCase {
    func testOpenidIsAlwaysRequestedAndTheScopesAreSortedAndDeduplicated() throws {
        XCTAssertEqual(try LoginOptions().requestedScopes(), ["openid"])
        XCTAssertEqual(try LoginOptions(scopes: ["profile", "email", "openid"]).requestedScopes(), ["email", "openid", "profile"])
    }

    func testAScopeThatIsNotASingleTokenIsRefused() {
        for scope in ["", "two words", "tab\tbed", "new\nline"] {
            XCTAssertThrowsError(try LoginOptions(scopes: [scope]).requestedScopes(), scope.debugDescription) { error in
                guard case .configuration(.invalidConfiguration)? = error as? OAuthError else { return XCTFail("\(error)") }
            }
        }
    }

    func testANegativeMaxAgeIsRefusedAndZeroIsNot() {
        XCTAssertThrowsError(try LoginOptions().authorizationParameters(maxAge: -1)) { error in
            guard case .configuration(.invalidConfiguration)? = error as? OAuthError else { return XCTFail("\(error)") }
        }
        XCTAssertNoThrow(try LoginOptions().authorizationParameters(maxAge: 0))
    }

    func testClaimsAndAuthorizationDetailsTravelInTheExtraMapUnderTheirWireNamesAndNothingElseDoes() throws {
        let parameters = try LoginOptions(
            prompt: .consent, loginHint: "h", uiLocales: ["fr", "en"], resources: ["https://api.example.com"],
            claims: #"{"id_token":{}}"#, authorizationDetails: "[]"
        ).authorizationParameters(maxAge: nil)
        XCTAssertEqual(parameters.extra, ["claims": #"{"id_token":{}}"#, "authorization_details": "[]"])
        XCTAssertEqual(parameters.prompt, .consent)
        XCTAssertEqual(parameters.loginHint, "h")
        XCTAssertEqual(parameters.uiLocales, ["fr", "en"])
        XCTAssertEqual(parameters.resources, ["https://api.example.com"])
        XCTAssertEqual(try LoginOptions().authorizationParameters(maxAge: nil).extra, [:])
    }

    func testTheOptionsHaveNoFreeFormParameterMap() {
        // A parameter edge ignores would be a setting that silently does nothing: the type has no
        // member that could carry one.
        let names = Mirror(reflecting: LoginOptions()).children.compactMap(\.label).sorted()
        XCTAssertEqual(names, ["acrValues", "authorizationDetails", "claims", "ephemeralBrowser", "loginHint", "maxAge", "prompt", "resources", "scopes", "uiLocales"])
    }

    func testSensitiveIsTheBuiltInAcr() {
        XCTAssertEqual(Acr.sensitive, "sensitive")
    }

    func testDefaultOptionsDoNotUseTheEphemeralBrowser() {
        XCTAssertFalse(LoginOptions().ephemeralBrowser)
    }
}
