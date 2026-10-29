import XCTest
@testable import OAuthClient

final class ClientSkeletonTests: XCTestCase {
    func testModuleLinks() {
        XCTAssertEqual(SessionState.allCases.count, 7)
    }
}
