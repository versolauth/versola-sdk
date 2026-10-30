import XCTest
@testable import OAuthCore

/// `AccessToken.tokenType` is the scheme to write after `Authorization:`, in the spec's
/// spelling (`spec/oauth-sdk-api.md` section 13), not the provider's: Ory Hydra answers
/// `bearer`. Android exposes the same decision as `isDpopBound`.
final class AccessTokenTests: XCTestCase {
    func testBearerInAnySpellingIsBearer() {
        for spelling in ["Bearer", "bearer", "BEARER"] {
            XCTAssertEqual(AccessToken(value: "t", tokenType: spelling).tokenType, "Bearer", spelling)
        }
    }

    func testDpopInAnySpellingIsDPoP() {
        for spelling in ["DPoP", "dpop", "DPOP"] {
            XCTAssertEqual(AccessToken(value: "t", tokenType: spelling).tokenType, "DPoP", spelling)
        }
    }

    /// A type this SDK has no scheme for is `Bearer`, as Android derives it from `isDpopBound`.
    /// A DPoP-bound request answered with another type never reaches here: `TokenClient`
    /// refuses it (`hardwareBindingUnavailable`), so only a bearer-configured client can hold one.
    func testAnyOtherTypeIsBearer() {
        XCTAssertEqual(AccessToken(value: "t", tokenType: "MAC").tokenType, "Bearer")
        XCTAssertEqual(AccessToken(value: "t", tokenType: "").tokenType, "Bearer")
    }

    func testTheValueIsUntouchedAndTheDescriptionRedactsIt() {
        let token = AccessToken(value: "secret-value", tokenType: "bearer")
        XCTAssertEqual(token.value, "secret-value")
        XCTAssertFalse(token.description.contains("secret"))
        XCTAssertEqual(token, AccessToken(value: "secret-value", tokenType: "Bearer"))
    }
}
