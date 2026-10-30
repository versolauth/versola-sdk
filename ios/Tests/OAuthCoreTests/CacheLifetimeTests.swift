import XCTest
@testable import OAuthCore

/// How long a fetched key set or discovery document is trusted (`spec/oauth-sdk-api.md` section 4):
/// the provider's `max-age`, held inside bounds the SDK chooses, and a day when it says nothing.
final class CacheLifetimeTests: XCTestCase {
    func testNoHeaderOrNoMaxAgeIsTheDefaultDay() {
        XCTAssertEqual(CacheLifetime.of(nil), 24 * 3600)
        XCTAssertEqual(CacheLifetime.of(""), 24 * 3600)
        XCTAssertEqual(CacheLifetime.of("public"), 24 * 3600)
        XCTAssertEqual(CacheLifetime.of("public, s-maxage=60"), 24 * 3600, "a shared-cache directive is not ours")
    }

    func testMaxAgeIsHonouredBetweenTheBounds() {
        XCTAssertEqual(CacheLifetime.of("max-age=3600"), 3600)
        XCTAssertEqual(CacheLifetime.of("public, max-age=7200, must-revalidate"), 7200)
        XCTAssertEqual(CacheLifetime.of("Max-Age=600"), 600, "directive names are case-insensitive")
        XCTAssertEqual(CacheLifetime.of("max-age=\"600\""), 600, "the quoted form RFC 9111 tolerates")
    }

    func testAMaxAgeBelowTheFloorOrAboveADayIsClamped() {
        XCTAssertEqual(CacheLifetime.of("max-age=0"), CacheLifetime.minimum, "a provider that says 0 is not a licence to refetch per call")
        XCTAssertEqual(CacheLifetime.of("max-age=30"), CacheLifetime.minimum)
        XCTAssertEqual(CacheLifetime.of("max-age=31536000"), CacheLifetime.maximum, "a year is not a trust period for keys")
        XCTAssertEqual(CacheLifetime.of("max-age=99999999999999999999"), CacheLifetime.maximum)
    }

    func testNoStoreAndNoCacheAreTheFloor() {
        XCTAssertEqual(CacheLifetime.of("no-store"), CacheLifetime.minimum)
        XCTAssertEqual(CacheLifetime.of("no-cache, max-age=3600"), CacheLifetime.minimum)
    }

    func testAMalformedMaxAgeIsTheDefaultNotAnError() {
        for header in ["max-age=abc", "max-age=", "max-age=-5", "max-age=1.5", "max-age"] {
            XCTAssertEqual(CacheLifetime.of(header), 24 * 3600, header)
        }
    }
}
