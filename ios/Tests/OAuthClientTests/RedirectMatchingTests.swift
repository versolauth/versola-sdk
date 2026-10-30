import Foundation
import XCTest
@testable import OAuthClient

/// Which URLs `handleRedirect(_:)` takes as this client's redirect. A URL that does not match is
/// refused (false) and never reaches a pending authorization, so each negative case is a
/// security check, not a convenience.
final class RedirectMatchingTests: XCTestCase {
    private let redirect = URL(string: "https://app.example.com/oauth")!

    func testTheRedirectWithItsResponseParametersMatches() {
        let url = URL(string: "https://app.example.com/oauth?code=c&state=s&iss=https%3A%2F%2Fid.example.com")!
        XCTAssertTrue(OAuthClient.isRedirect(url, to: redirect))
    }

    func testAFragmentDoesNotChangeTheMatch() {
        XCTAssertTrue(OAuthClient.isRedirect(URL(string: "https://app.example.com/oauth#frag")!, to: redirect))
    }

    func testAnotherPathOnTheSameHostIsRefused() {
        XCTAssertFalse(OAuthClient.isRedirect(URL(string: "https://app.example.com/other?code=c")!, to: redirect))
    }

    func testATrailingSlashMatchesTodayBecauseFoundationDropsIt() {
        // Not a design decision: `URL.path` returns `/oauth` for `/oauth/`, so the comparison
        // cannot see the slash. The matching rule is looser than "path exact". Pinned so that
        // tightening it (comparing the raw path) is a deliberate change with its own test.
        XCTAssertTrue(OAuthClient.isRedirect(URL(string: "https://app.example.com/oauth/?code=c")!, to: redirect))
    }

    func testAnotherHostIsRefused() {
        XCTAssertFalse(OAuthClient.isRedirect(URL(string: "https://evil.example.com/oauth?code=c")!, to: redirect))
    }

    func testAnotherSchemeIsRefused() {
        XCTAssertFalse(OAuthClient.isRedirect(URL(string: "http://app.example.com/oauth?code=c")!, to: redirect))
    }

    func testACustomSchemeRedirectMatchesOnlyItsOwnScheme() {
        let custom = URL(string: "com.example.app:/oauth2redirect")!
        XCTAssertTrue(OAuthClient.isRedirect(URL(string: "com.example.app:/oauth2redirect?code=c")!, to: custom))
        XCTAssertFalse(OAuthClient.isRedirect(URL(string: "com.example.other:/oauth2redirect?code=c")!, to: custom))
    }
}
