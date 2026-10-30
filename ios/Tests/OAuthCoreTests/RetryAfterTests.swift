import XCTest
@testable import OAuthCore

/// `Retry-After` and the classification of a server-side answer (`spec/retry-policy.md`,
/// "Classification" and "`Retry-After`"; scenarios 34 and 35). Read on 429 and 503 only, as
/// seconds or an HTTP-date measured against the response's own `Date`; anything else is absent.
final class RetryAfterTests: XCTestCase {
    private let device = Date(timeIntervalSince1970: 1_700_000_000)

    private func parse(_ value: String?, responseDate: Date? = nil) -> Int64? {
        RetryAfter.parse(value, responseDate: responseDate, deviceNow: device)
    }

    // MARK: delta-seconds

    func testDeltaSecondsAreReadAsMilliseconds() {
        XCTAssertEqual(parse("0"), 0)
        XCTAssertEqual(parse("2"), 2000)
        XCTAssertEqual(parse("120"), 120_000)
        XCTAssertEqual(parse(" 7 "), 7000, "surrounding whitespace is not part of the value")
        XCTAssertEqual(parse("007"), 7000)
    }

    func testLeadingZerosAreNotMagnitude() {
        XCTAssertEqual(parse("0000000030"), 30_000)
        XCTAssertEqual(parse("0000000000000000000000030"), 30_000, "more than fifteen characters, thirty seconds")
        XCTAssertEqual(parse("0000000000000000000000000"), 0)
        XCTAssertEqual(parse("00"), 0)
        XCTAssertEqual(parse("000086400"), 86_400_000)
        XCTAssertEqual(parse("0000000000099999999999999999"), 86_400_000)
    }

    func testAValueAboveADaySaturatesAtADayWithoutOverflowing() {
        XCTAssertEqual(parse("86400"), 86_400_000)
        XCTAssertEqual(parse("86401"), 86_400_000)
        XCTAssertEqual(parse("999999999999"), 86_400_000)
        // More digits than an Int64 holds is still a valid, enormous, delta-seconds.
        XCTAssertEqual(parse(String(repeating: "9", count: 40)), 86_400_000)
        XCTAssertEqual(parse(String(repeating: "9", count: 19)), 86_400_000)
    }

    func testEverythingThatIsNotDeltaSecondsOrADateIsAbsent() {
        for malformed in [nil, "", "   ", "-1", "-0", "+5", "1.5", "1e3", "0x10", "5s", "soon", "5, 7", "5 7", "NaN", "∞", "١٢"] {
            XCTAssertNil(parse(malformed), "\(String(describing: malformed)) is not a delay")
        }
    }

    // MARK: HTTP-date

    func testAnHttpDateIsMeasuredAgainstTheResponsesDateNotTheDeviceClock() {
        let server = Date(timeIntervalSince1970: 1_700_000_000)
        let target = HTTPDate.format(server.addingTimeInterval(4))
        // A device an hour ahead of the server: the wait is still the four seconds the server meant.
        XCTAssertEqual(RetryAfter.parse(target, responseDate: server, deviceNow: server.addingTimeInterval(3600)), 4000)
        // A device an hour behind: the same.
        XCTAssertEqual(RetryAfter.parse(target, responseDate: server, deviceNow: server.addingTimeInterval(-3600)), 4000)
    }

    func testWithoutAResponseDateTheDeviceClockIsTheFallback() {
        let target = HTTPDate.format(device.addingTimeInterval(9))
        XCTAssertEqual(parse(target), 9000)
    }

    func testAnHttpDateInThePastOrNowIsAbsentNotZero() {
        XCTAssertNil(parse(HTTPDate.format(device.addingTimeInterval(-60))))
        XCTAssertNil(parse(HTTPDate.format(device)))
    }

    func testAnHttpDateFarAheadSaturatesAtADay() {
        XCTAssertEqual(parse(HTTPDate.format(device.addingTimeInterval(30 * 86400))), 86_400_000)
    }

    func testTheTwoObsoleteDateFormsAreReadToo() {
        // RFC 9110 section 5.6.7: a recipient reads all three. 1700000010 is
        // Tue, 14 Nov 2023 22:13:30 GMT.
        let base = Date(timeIntervalSince1970: 1_700_000_000)
        XCTAssertEqual(RetryAfter.parse("Tuesday, 14-Nov-23 22:13:30 GMT", responseDate: base, deviceNow: base), 10_000)
        XCTAssertEqual(RetryAfter.parse("Tue Nov 14 22:13:30 2023", responseDate: base, deviceNow: base), 10_000)
        XCTAssertEqual(RetryAfter.parse("Tue, 14 Nov 2023 22:13:30 GMT", responseDate: base, deviceNow: base), 10_000)
    }

    func testAnHttpDateWithTrailingJunkOrAnotherCalendarIsAbsent() {
        XCTAssertNil(parse("Tue, 14 Nov 2023 22:13:30 GMT, Tue, 14 Nov 2023 22:13:40 GMT"))
        XCTAssertNil(parse("2023-11-14T22:13:30Z"))
        XCTAssertNil(parse("Tue, 31 Feb 2023 22:13:30 GMT"))
    }

    // MARK: the header on a response

    private func response(_ status: Int, _ headers: [String: String]) -> HTTPResponse {
        HTTPResponse(statusCode: status, headers: headers)
    }

    func testTheHeaderIsReadOn429And503Only() {
        XCTAssertEqual(RetryAfter.millis(for: response(429, ["Retry-After": "3"]), now: device), 3000)
        XCTAssertEqual(RetryAfter.millis(for: response(503, ["retry-after": "3"]), now: device), 3000)
        for status in [408, 500, 502, 504, 501, 301, 400, 401, 403, 404] {
            XCTAssertNil(RetryAfter.millis(for: response(status, ["Retry-After": "3"]), now: device), "HTTP \(status) ignores it")
        }
    }

    func testARepeatedHeaderIsAbsentBecauseTheClientJoinsThemWithACommaAndThatIsNotAValue() {
        // `HTTPURLResponse` folds a repeated header into "5, 7".
        XCTAssertNil(RetryAfter.millis(for: response(429, ["Retry-After": "5, 7"]), now: device))
    }

    func testTheResponseDateHeaderIsUsedForAnHttpDate() {
        let server = Date(timeIntervalSince1970: 1_700_000_000)
        let answer = response(503, ["Date": HTTPDate.format(server), "Retry-After": HTTPDate.format(server.addingTimeInterval(4))])
        XCTAssertEqual(RetryAfter.millis(for: answer, now: server.addingTimeInterval(86_400)), 4000)
    }

    // MARK: classification

    func testTheTransientStatusesAreTheSpecsSix() {
        for status in [408, 429, 500, 502, 503, 504] { XCTAssertTrue(ServerFailure.isTransient(status), "\(status)") }
        for status in [200, 301, 400, 401, 403, 404, 501, 505, 506, 507, 508, 510, 511] {
            XCTAssertFalse(ServerFailure.isTransient(status), "\(status)")
        }
    }

    func testEveryFiveHundredAnd408And429AreServerSide() {
        for status in [408, 429] + Array(500..<600) { XCTAssertTrue(ServerFailure.isServerSide(status), "\(status)") }
        for status in [200, 204, 301, 400, 401, 403, 404, 409, 499] { XCTAssertFalse(ServerFailure.isServerSide(status), "\(status)") }
    }

    func testAServerSideAnswerBecomesServerCarryingItsStatusAndTheDelayTheServerAsked() {
        XCTAssertEqual(
            ServerFailure.error(for: response(429, ["Retry-After": "30"]), now: device),
            .recoverable(.server(status: 429, retryAfterMillis: 30_000, attempts: 1, elapsedMillis: 0))
        )
        XCTAssertEqual(
            ServerFailure.error(for: response(500, ["Retry-After": "30"]), now: device),
            .recoverable(.server(status: 500, retryAfterMillis: nil, attempts: 1, elapsedMillis: 0)),
            "a Retry-After on a 500 is ignored"
        )
        XCTAssertNil(ServerFailure.error(for: response(400, [:]), now: device))
        XCTAssertNil(ServerFailure.error(for: response(200, [:]), now: device))
    }

    func testOnlyATransportFailureOrATransientServerAnswerIsRepeatable() {
        XCTAssertNotNil(ServerFailure.repeatable(.recoverable(.network(detail: "x", attempts: 1, elapsedMillis: 0))))
        XCTAssertNotNil(ServerFailure.repeatable(.recoverable(.server(status: 503, retryAfterMillis: 5, attempts: 1, elapsedMillis: 0))))
        XCTAssertNil(ServerFailure.repeatable(.recoverable(.server(status: 501, retryAfterMillis: nil, attempts: 1, elapsedMillis: 0))))
        XCTAssertNil(ServerFailure.repeatable(.recoverable(.server(status: 505, retryAfterMillis: nil, attempts: 1, elapsedMillis: 0))))
        XCTAssertNil(ServerFailure.repeatable(.recoverable(.nonceLoop(origin: "https://id.example.com"))))
        XCTAssertNil(ServerFailure.repeatable(.recoverable(.unlockRequired)))
        XCTAssertNil(ServerFailure.repeatable(.reauthenticate(.grantRejected)))
        XCTAssertNil(ServerFailure.repeatable(.configuration(.stateMismatch)))
    }
}
