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

    func testATrailingSlashIsADifferentPath() {
        XCTAssertFalse(OAuthClient.isRedirect(URL(string: "https://app.example.com/oauth/?code=c")!, to: redirect))
    }

    func testAPercentEncodedSlashIsNotAPathSeparator() {
        // `URL.path` decodes `%2F` to `/`, which would make these equal. The raw path must not.
        let nested = URL(string: "https://app.example.com/oauth/x")!
        XCTAssertFalse(OAuthClient.isRedirect(URL(string: "https://app.example.com/oauth%2Fx")!, to: nested))
        XCTAssertFalse(OAuthClient.isRedirect(URL(string: "https://app.example.com/oauth%2Fx")!, to: redirect))
    }

    func testAnEmptyPathIsTheRootPath() {
        // RFC 9110 section 4.2.3: `https://app.example.com` is `https://app.example.com/`.
        let root = URL(string: "https://app.example.com/")!
        XCTAssertTrue(OAuthClient.isRedirect(URL(string: "https://app.example.com?code=c")!, to: root))
        XCTAssertFalse(OAuthClient.isRedirect(URL(string: "https://app.example.com?code=c")!, to: redirect))
    }

    func testAnExplicitDefaultPortMatchesNoPort() {
        XCTAssertTrue(OAuthClient.isRedirect(URL(string: "https://app.example.com:443/oauth?code=c")!, to: redirect))
    }

    func testADifferentPortIsRefused() {
        XCTAssertFalse(OAuthClient.isRedirect(URL(string: "https://app.example.com:8443/oauth?code=c")!, to: redirect))
    }

    func testSchemeAndHostCompareCaseInsensitively() {
        // RFC 3986 section 3.1 and 3.2.2: a different case is the same address.
        XCTAssertTrue(OAuthClient.isRedirect(URL(string: "HTTPS://APP.example.COM/oauth?code=c")!, to: redirect))
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
