import XCTest
@testable import OAuthCore

final class PkceTests: XCTestCase {
    func testChallengeMatchesTheRfc7636AppendixBVector() throws {
        let verifier = try CodeVerifier(value: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        XCTAssertEqual(verifier.challengeS256(), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    }

    func testGeneratedVerifierIs43UnreservedCharactersAndRoundTripsThroughValidation() throws {
        let verifier = CodeVerifier.generate(SystemRandomSource())
        XCTAssertEqual(verifier.value.count, 43)
        XCTAssertNoThrow(try CodeVerifier(value: verifier.value))
        XCTAssertEqual(try CodeVerifier(value: verifier.value), verifier)
    }

    func testGeneratedVerifiersDiffer() {
        let random = SystemRandomSource()
        XCTAssertNotEqual(CodeVerifier.generate(random), CodeVerifier.generate(random))
    }

    func testInitAcceptsTheLengthBounds() {
        XCTAssertNoThrow(try CodeVerifier(value: String(repeating: "a", count: 43)))
        XCTAssertNoThrow(try CodeVerifier(value: String(repeating: "a", count: 128)))
        XCTAssertNoThrow(try CodeVerifier(value: "aB3-._~" + String(repeating: "x", count: 36)))
    }

    func testInitRefusesAVerifierOutsideTheRfcBounds() {
        for bad in [String(repeating: "a", count: 42), String(repeating: "a", count: 129), ""] {
            XCTAssertThrowsError(try CodeVerifier(value: bad)) {
                XCTAssertEqual($0 as? OAuthError, .configuration(.invalidConfiguration(detail: "malformed PKCE code verifier")))
            }
        }
    }

    func testInitRefusesCharactersOutsideTheUnreservedSet() {
        let base = String(repeating: "a", count: 43)
        for bad in ["+", "/", "=", " ", "é", "%", "\n"] {
            XCTAssertThrowsError(try CodeVerifier(value: base + bad), "accepted \(bad.debugDescription)")
        }
    }

    func testDescriptionNeverShowsTheSecret() throws {
        let verifier = try CodeVerifier(value: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        XCTAssertEqual(verifier.description, "CodeVerifier(redacted)")
        XCTAssertFalse("\(verifier)".contains("dBjft"))
        XCTAssertFalse(String(reflecting: verifier).contains("dBjft"))
    }
}
