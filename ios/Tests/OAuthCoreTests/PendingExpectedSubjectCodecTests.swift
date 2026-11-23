import Foundation
import XCTest
@testable import OAuthCore

/// The `expectedSubject` member of a persisted pending request (the Android twin stores the same name):
/// it survives the codec, an absent member reads as nil, and it stays out of `description`.
final class PendingExpectedSubjectCodecTests: XCTestCase {
    func testExpectedSubjectSurvivesAnEncodeDecodeRoundTripUnderItsOwnMember() throws {
        let pending = AuthzKit.pending(expectedSubject: "alice")

        let data = try JSONEncoder().encode(pending)
        let decoded = try JSONDecoder().decode(PendingAuthorizationRequest.self, from: data)

        XCTAssertEqual(decoded, pending)
        XCTAssertEqual(decoded.expectedSubject, "alice")
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(object["expectedSubject"] as? String, "alice")
    }

    func testRecordWrittenBeforeTheFieldExistedDecodesWithNoExpectedSubject() throws {
        let data = try JSONEncoder().encode(AuthzKit.pending(expectedSubject: "alice"))
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        object.removeValue(forKey: "expectedSubject")
        let old = try JSONSerialization.data(withJSONObject: object)

        let decoded = try JSONDecoder().decode(PendingAuthorizationRequest.self, from: old)

        XCTAssertNil(decoded.expectedSubject)
    }

    func testTheValidatedGrantCarriesTheExpectedSubjectOfThePendingRequest() throws {
        let pending = AuthzKit.pending(state: "s", expectedSubject: "alice")
        let redirect = AuthzKit.redirect(answering: URL(string: "https://x.example.com/?state=s")!)

        let grant = try AuthorizationResponseValidator.validate(
            redirect: redirect, pending: pending, issuer: AuthzKit.issuer, issParameterSupported: false
        )

        XCTAssertEqual(grant.expectedSubject, "alice")
    }

    func testRequiringASubjectChangesNothingElseOfTheRequest() {
        let base = AuthzKit.pending(state: "s", maxAge: 60)
        let required = base.requiring(subject: "bob")
        XCTAssertEqual(required.expectedSubject, "bob")
        XCTAssertEqual(required.requiring(subject: nil), base)
    }

    func testTheExpectedSubjectIsNotInTheDescription() {
        XCTAssertFalse(String(describing: AuthzKit.pending(expectedSubject: "alice-sub")).contains("alice-sub"))
    }
}
