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
        XCTAssertEqual(RetryPolicy.backoffMultiplierCeiling, 4)
        XCTAssertEqual(RetryPolicy.maxBackoffCeiling, 30)
        XCTAssertThrowsError(try RetryPolicy(totalBudget: 61))
        XCTAssertNoThrow(try RetryPolicy(totalBudget: 60))
        XCTAssertThrowsError(try RetryPolicy(maxAttemptsPerOrigin: 6, maxTotalAttempts: 8))
        XCTAssertThrowsError(try RetryPolicy(maxTotalAttempts: 9))
    }

    /// The five hard maxima are one rule: a value above one is `invalidConfiguration`, never a
    /// clamp, and the same value is refused by Android's `RetryPolicy`.
    func testAValuePastAHardMaximumIsRefusedNotClamped() throws {
        for policy in [
            { try RetryPolicy(maxBackoff: 31) },
            { try RetryPolicy(initialBackoff: 31, maxBackoff: 31) },
            { try RetryPolicy(backoffMultiplier: 4.1) },
            { try RetryPolicy(backoffMultiplier: 100) },
        ] {
            XCTAssertThrowsError(try policy()) { error in
                guard case .configuration(.invalidConfiguration) = error as? OAuthError else {
                    return XCTFail("expected invalidConfiguration, got \(error)")
                }
            }
        }
        XCTAssertNoThrow(try RetryPolicy(initialBackoff: 30, backoffMultiplier: 4, maxBackoff: 30))
    }

    /// NaN fails every comparison, so a range check written with `<` and `>` accepts it, and a
    /// NaN backoff then traps in `Duration.seconds` on the first retry.
    func testNaNIsOutsideEveryBound() {
        XCTAssertThrowsError(try RetryPolicy(initialBackoff: .nan))
        XCTAssertThrowsError(try RetryPolicy(backoffMultiplier: .nan))
        XCTAssertThrowsError(try RetryPolicy(maxBackoff: .nan))
        XCTAssertThrowsError(try RetryPolicy(totalBudget: .nan))
        XCTAssertThrowsError(try RetryPolicy(backoffMultiplier: .infinity))
    }

    func testAPolicyThatCannotMakeARequestIsRefusedToo() {
        XCTAssertThrowsError(try RetryPolicy(maxAttemptsPerOrigin: 0))
        XCTAssertThrowsError(try RetryPolicy(maxTotalAttempts: 0))
        XCTAssertThrowsError(try RetryPolicy(backoffMultiplier: 0.9))
        XCTAssertThrowsError(try RetryPolicy(totalBudget: 0))
    }

    func testAPerOriginAllowanceAboveTheTotalAllowanceIsRefused() {
        XCTAssertThrowsError(try RetryPolicy(maxAttemptsPerOrigin: 4, maxTotalAttempts: 2))
        XCTAssertNoThrow(try RetryPolicy(maxAttemptsPerOrigin: 2, maxTotalAttempts: 2))
    }
}
