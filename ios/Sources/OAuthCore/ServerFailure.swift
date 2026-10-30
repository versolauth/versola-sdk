import Foundation

/// What an HTTP answer that is not a success means to the retry policy (`spec/retry-policy.md`,
/// "Classification"), and the one place that says so: every request the SDK originates reads its
/// status through here, so a status cannot be transient to one client and final to another.
package enum ServerFailure {
    /// 408, 429, 500, 502, 503 and 504: the provider is busy or briefly broken, and a repeat can
    /// help. Any other 5xx (501, 505, ...) is a fault no repeat fixes and is surfaced at once.
    package static func isTransient(_ status: Int) -> Bool {
        switch status {
        case 408, 429, 500, 502, 503, 504: return true
        default: return false
        }
    }

    /// Whether `status` is an answer this classification owns at all: 408, 429 and every 5xx.
    package static func isServerSide(_ status: Int) -> Bool {
        status == 408 || status == 429 || (500..<600).contains(status)
    }

    /// `recoverable(.server)` for a 408, a 429 or a 5xx, nil for anything else. The attempt
    /// count and elapsed time are those of one request; the retry budget rewrites them when it
    /// ends the operation.
    package static func error(for response: HTTPResponse, now: Date = Date()) -> OAuthError? {
        guard isServerSide(response.statusCode) else { return nil }
        return .recoverable(.server(
            status: response.statusCode,
            retryAfterMillis: RetryAfter.millis(for: response, now: now),
            attempts: 1,
            elapsedMillis: 0
        ))
    }

    /// The failure a retry budget may repeat: a transport failure, or a transient `server`
    /// answer, with the delay the server asked for.
    package struct Repeatable {
        package let retryAfterMillis: Int64?
        package let status: Int?
    }

    package static func repeatable(_ error: OAuthError) -> Repeatable? {
        switch error {
        case .recoverable(.network): return Repeatable(retryAfterMillis: nil, status: nil)
        case .recoverable(.server(let status, let retryAfter, _, _)) where isTransient(status):
            return Repeatable(retryAfterMillis: retryAfter, status: status)
        default: return nil
        }
    }
}

/// `Retry-After` (RFC 9110 section 10.2.3), read on 429 and 503 only.
///
/// A value is either `delta-seconds` (a non-negative integer) or an HTTP-date. An HTTP-date is
/// measured against the response's own `Date` header when it has a readable one and against the
/// device clock otherwise, so a skewed device clock neither stretches nor shrinks the wait.
/// Anything else (negative, fractional, empty, repeated, unparseable, a date that has passed) is
/// absent, and the policy's own backoff applies: a malformed header never fails a request.
package enum RetryAfter {
    /// A day. What the parser saturates at, so arithmetic on the value cannot overflow and an
    /// app is not handed a number it cannot sensibly schedule.
    package static let ceilingMillis: Int64 = 24 * 3600 * 1000

    package static func millis(for response: HTTPResponse, now: Date = Date()) -> Int64? {
        guard response.statusCode == 429 || response.statusCode == 503 else { return nil }
        return parse(response.header("Retry-After"), responseDate: response.header("Date").flatMap(HTTPDate.parse), deviceNow: now)
    }

    package static func parse(_ value: String?, responseDate: Date?, deviceNow: Date) -> Int64? {
        guard let value else { return nil }
        let text = value.trimmingCharacters(in: CharacterSet(charactersIn: " \t"))
        if text.isEmpty { return nil }
        // delta-seconds is ASCII digits and nothing else: no sign, no fraction, no exponent.
        if text.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) {
            // More digits than an Int64 holds is still a valid, enormous, delta-seconds.
            guard text.utf8.count <= 15, let seconds = Int64(text) else { return ceilingMillis }
            return min(seconds * 1000, ceilingMillis)
        }
        guard let date = HTTPDate.parseAny(text) else { return nil }
        let ahead = date.timeIntervalSince(responseDate ?? deviceNow)
        // A date that has passed is "no delay asked", which is the header being absent, not zero.
        guard ahead > 0, ahead.isFinite else { return nil }
        return min(Int64((ahead * 1000).rounded(.up)), ceilingMillis)
    }
}

extension HTTPDate {
    /// The three HTTP-date forms RFC 9110 section 5.6.7 obliges a recipient to read: IMF-fixdate,
    /// the obsolete RFC 850 form and asctime. A sender should only produce the first.
    static func parseAny(_ text: String) -> Date? {
        if let imf = parse(text) { return imf }
        for format in ["EEEE, dd-MMM-yy HH:mm:ss zzz", "EEE MMM d HH:mm:ss yyyy"] {
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.timeZone = TimeZone(secondsFromGMT: 0)
            formatter.dateFormat = format
            if let date = formatter.date(from: text) { return date }
        }
        return nil
    }
}

/// What the servers asked for, remembered (`spec/retry-policy.md`, "Cooldown"): per origin, in
/// memory, the moment a `Retry-After` said requests would be accepted again.
///
/// Until then a request the SDK originates to that origin is refused here, before anything is
/// sent, with the same `recoverable(.server)` and what is left of the wait, so an app that calls
/// `accessToken()` in a loop does not send a request per call to a server that asked for quiet.
/// Memory only: a cold start forgets it, and the server still enforces its limit. Started only
/// by a `Retry-After` the server sent, never by the SDK's own idea of a good pause. The app's
/// own requests through the authenticated session do not pass through it.
package actor RetryCooldown {
    private struct Entry {
        let until: TimeInterval
        let status: Int
    }

    private let uptime: @Sendable () -> TimeInterval
    private var entries: [String: Entry] = [:]

    package init(clock: Clock = .system) {
        self.uptime = clock.uptime
    }

    /// Throws `recoverable(.server)` with `attempts` 0 while `origin` is cooling down.
    package func check(_ origin: String) throws {
        guard let entry = entries[origin] else { return }
        let left = entry.until - uptime()
        if left <= 0 {
            entries[origin] = nil
            return
        }
        throw OAuthError.recoverable(.server(
            status: entry.status,
            retryAfterMillis: Int64((left * 1000).rounded(.up)),
            attempts: 0,
            elapsedMillis: 0
        ))
    }

    /// Starts (or extends, never shortens) the cooldown of `origin`.
    package func record(origin: String, status: Int, retryAfterMillis: Int64) {
        let until = uptime() + Double(retryAfterMillis) / 1000
        if let existing = entries[origin], existing.until >= until { return }
        entries[origin] = Entry(until: until, status: status)
    }
}

/// The retry budget of the application-visible operation that is running, found by the leaf
/// clients (discovery, the key set, PAR, revocation, UserInfo) without each being handed one.
///
/// A task-local rather than a parameter on every client: the operation is the unit the policy
/// bounds (`spec/retry-policy.md`, "What counts as one operation"), and a refresh a call triggers
/// or a discovery a login needs must draw on the allowance of the call that caused it. Child
/// tasks and the flights an operation starts inherit it; outside an operation there is none, and
/// a leaf client then makes its single attempt, as it always did.
package enum OperationBudget {
    @TaskLocal package static var current: RetryBudget?

    /// Runs `call` as one repeatable request to `origin` under the current budget, or once when
    /// there is no operation.
    package static func run<T: Sendable>(origin: String, _ call: @Sendable () async throws -> T) async throws -> T {
        guard let budget = current else { return try await call() }
        return try await budget.execute(origin: origin, call)
    }

    /// Runs `call` once, with no retry, but subject to the cooldown and starting it: the code
    /// exchange, which a repeat would replay.
    package static func runOnce<T: Sendable>(origin: String, _ call: @Sendable () async throws -> T) async throws -> T {
        guard let budget = current else { return try await call() }
        return try await budget.executeOnce(origin: origin, call)
    }
}
