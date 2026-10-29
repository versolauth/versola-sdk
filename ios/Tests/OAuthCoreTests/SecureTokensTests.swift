import XCTest
@testable import OAuthCore

private struct ZeroRandom: RandomSource {
    func bytes(_ count: Int) -> [UInt8] { [UInt8](repeating: 0, count: count) }
}

final class SecureTokensTests: XCTestCase {
    func testConstantTimeEqualsAcceptsEqualStrings() {
        XCTAssertTrue(SecureTokens.constantTimeEquals("state-value", "state-value"))
        XCTAssertTrue(SecureTokens.constantTimeEquals("", ""))
        XCTAssertTrue(SecureTokens.constantTimeEquals("é-ü", "é-ü"))
    }

    func testConstantTimeEqualsRefusesSameLengthDifferenceAtAnyPosition() {
        XCTAssertFalse(SecureTokens.constantTimeEquals("state-value", "state-valuf"))
        XCTAssertFalse(SecureTokens.constantTimeEquals("state-value", "Xtate-value"))
        XCTAssertFalse(SecureTokens.constantTimeEquals("abc", "abd"))
    }

    func testConstantTimeEqualsRefusesAPrefixAndAnExtension() {
        XCTAssertFalse(SecureTokens.constantTimeEquals("state", "state-value"))
        XCTAssertFalse(SecureTokens.constantTimeEquals("state-value", "state"))
    }

    func testConstantTimeEqualsHandlesEmptySidesWithoutTrapping() {
        XCTAssertFalse(SecureTokens.constantTimeEquals("abc", ""))
        XCTAssertFalse(SecureTokens.constantTimeEquals("", "abc"))
        // A right-hand side of zero bytes must not match a left-hand side of NULs.
        XCTAssertFalse(SecureTokens.constantTimeEquals("\0", ""))
    }

    func testGenerateYieldsAtLeast128BitsAsBase64Url() {
        let token = SecureTokens.generate(SystemRandomSource())
        XCTAssertGreaterThanOrEqual(token.count, 43)
        XCTAssertNotNil(Base64Url.decode(token))
        XCTAssertFalse(token.contains("="))
    }

    func testGenerateYieldsADifferentValueEachTime() {
        let random = SystemRandomSource()
        XCTAssertNotEqual(SecureTokens.generate(random), SecureTokens.generate(random))
    }

    func testGenerateNeverReturnsLessThan128BitsWhateverIsAsked() {
        // 16 bytes is 22 base64url characters.
        XCTAssertEqual(SecureTokens.generate(ZeroRandom(), bytes: 4).count, 22)
        XCTAssertEqual(SecureTokens.generate(ZeroRandom(), bytes: 0).count, 22)
        XCTAssertEqual(SecureTokens.generate(ZeroRandom(), bytes: 32).count, 43)
    }
}
