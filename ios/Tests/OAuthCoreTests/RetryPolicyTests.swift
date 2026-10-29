import XCTest
@testable import OAuthCore

/// The defaults and ceilings are the table in `spec/retry-policy.md`; Android reads the same
/// numbers, so a drift here is a drift between platforms, not a tuning choice.
final class RetryPolicyTests: XCTestCase {
    func testDefaultsAreTheSpecTable() {
        let policy = RetryPolicy.default
        XCTAssertEqual(policy.maxAttemptsPerOrigin, 3)
        XCTAssertEqual(policy.maxTotalAttempts, 4)
        XCTAssertEqual(policy.initialBackoff, 0.5)
        XCTAssertEqual(policy.backoffMultiplier, 2)
        XCTAssertEqual(policy.maxBackoff, 8)
        XCTAssertEqual(policy.totalBudget, 20)
    }

    func testCeilingsAreTheSpecTable() throws {
        XCTAssertEqual(RetryPolicy.maxAttemptsPerOriginCeiling, 5)
        XCTAssertEqual(RetryPolicy.maxTotalAttemptsCeiling, 8)
        XCTAssertEqual(RetryPolicy.totalBudgetCeiling, 60)
        XCTAssertThrowsError(try RetryPolicy(totalBudget: 61))
        XCTAssertNoThrow(try RetryPolicy(totalBudget: 60))
    }
}
