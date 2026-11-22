import XCTest
@testable import OAuthCore

/// The two cases the Versola facade added to the shared error type (`spec/errors.md`).
final class FacadeErrorTests: XCTestCase {
    func testAccountMismatchHasItsStableCodeAndASafeDescription() {
        let error = OAuthError.recoverable(.accountMismatch)
        XCTAssertEqual(error.code, "recoverable.account_mismatch")
        XCTAssertEqual(error.localizedDescription, "recoverable: accountMismatch")
    }

    func testFacadeDetailCodeIsConfigurationDotItsName() {
        let error = OAuthError.configuration(.facade(name: "edge_client_unknown", detail: "mobile-1"))
        XCTAssertEqual(error.code, "configuration.edge_client_unknown")
        XCTAssertEqual(error, .configuration(.facade(name: "edge_client_unknown", detail: "mobile-1")))
        XCTAssertNotEqual(error, .configuration(.facade(name: "edge_client_unknown", detail: "mobile-2")))
    }
}
