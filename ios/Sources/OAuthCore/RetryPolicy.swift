import Foundation

/// The bounds of `spec/retry-policy.md`: how many attempts an operation may spend on transient
/// failures, per origin and in total, with capped exponential backoff. A value above a maximum
/// is `invalidConfiguration` at construction; the maxima are hard bounds, not defaults.
public struct RetryPolicy: Sendable, Equatable {
    public let maxAttemptsPerOrigin: Int
    public let maxTotalAttempts: Int
    public let initialBackoff: TimeInterval
    public let backoffMultiplier: Double
    public let maxBackoff: TimeInterval
    public let totalBudget: TimeInterval

    public static let maxAttemptsPerOriginCeiling = 5
    public static let maxTotalAttemptsCeiling = 8
    public static let totalBudgetCeiling: TimeInterval = 60
    public static let backoffMultiplierCeiling = 4.0
    public static let maxBackoffCeiling: TimeInterval = 30

    public init(
        maxAttemptsPerOrigin: Int = 3, maxTotalAttempts: Int = 4, initialBackoff: TimeInterval = 0.5,
        backoffMultiplier: Double = 2, maxBackoff: TimeInterval = 8, totalBudget: TimeInterval = 20
    ) throws {
        func invalid(_ detail: String) -> OAuthError {
            OAuthError.configuration(.invalidConfiguration(detail: detail))
        }
        func bounded(_ name: String, _ value: Int, _ lower: Int, _ upper: Int) throws {
            if value < lower || value > upper {
                throw invalid("\(name) must be between \(lower) and \(upper): \(value)")
            }
        }
        // Written as a negated `contains` so a NaN, which fails every comparison, is outside
        // the range rather than inside it: `value < lower || value > upper` accepts it, and a
        // NaN backoff then traps in `Duration.seconds` on the first retry (spec/retry-policy.md,
        // "not a silent clamp"; Android's `bounded` refuses it the same way).
        func bounded(_ name: String, _ value: Double, _ range: ClosedRange<Double>) throws {
            if !range.contains(value) {
                throw invalid("\(name) must be between \(range.lowerBound) and \(range.upperBound): \(value)")
            }
        }
        try bounded("maxAttemptsPerOrigin", maxAttemptsPerOrigin, 1, Self.maxAttemptsPerOriginCeiling)
        try bounded("maxTotalAttempts", maxTotalAttempts, 1, Self.maxTotalAttemptsCeiling)
        try bounded("backoffMultiplier", backoffMultiplier, 1...Self.backoffMultiplierCeiling)
        try bounded("initialBackoff", initialBackoff, 0...Self.maxBackoffCeiling)
        try bounded("maxBackoff", maxBackoff, 0...Self.maxBackoffCeiling)
        if maxBackoff < initialBackoff {
            throw invalid("maxBackoff (\(maxBackoff)) must not be below initialBackoff (\(initialBackoff))")
        }
        if !(0...Self.totalBudgetCeiling).contains(totalBudget) || totalBudget == 0 {
            throw invalid("totalBudget must be above 0 and at most \(Self.totalBudgetCeiling) s: \(totalBudget)")
        }
        // Two different promises, of which the smaller silently wins; say so here, where it
        // is one line to fix.
        if maxAttemptsPerOrigin > maxTotalAttempts {
            throw invalid("maxAttemptsPerOrigin (\(maxAttemptsPerOrigin)) exceeds maxTotalAttempts (\(maxTotalAttempts)), so the per-origin allowance can never be reached")
        }
        self.maxAttemptsPerOrigin = maxAttemptsPerOrigin
        self.maxTotalAttempts = maxTotalAttempts
        self.initialBackoff = initialBackoff
        self.backoffMultiplier = backoffMultiplier
        self.maxBackoff = maxBackoff
        self.totalBudget = totalBudget
    }

    public static let `default` = try! RetryPolicy()

    /// The delay before attempt `attempt` (1-based; the first attempt has none), capped.
    public func backoff(beforeAttempt attempt: Int) -> TimeInterval {
        guard attempt > 1 else { return 0 }
        return min(maxBackoff, initialBackoff * pow(backoffMultiplier, Double(attempt - 2)))
    }
}

extension RetryPolicy {
    /// A budget for one operation (`spec/retry-policy.md`): repeats transport failures and
    /// transient `server` answers, per origin and in total, with jittered exponential backoff or
    /// the delay a `Retry-After` asked for, within the wall-clock budget.
    ///
    /// - Parameter cooldown: where a `Retry-After` that ended an operation is remembered, and
    ///   consulted before every request. nil leaves the operation without one (a test, or a
    ///   caller outside a client).
    package func newBudget(clock: Clock = .system, random: RandomSource = SystemRandomSource(), cooldown: RetryCooldown? = nil, sleep: @escaping @Sendable (TimeInterval) async throws -> Void = { try await Task.sleep(for: .seconds($0)) }) -> RetryBudget {
        RetryBudget(policy: self, clock: clock, random: random, cooldown: cooldown, sleep: sleep)
    }
}

/// The retries of one operation (`spec/retry-policy.md`). Everything that is not a transport
/// failure or a transient server answer is final: a nonce loop, a locked store, a 501 and every
/// other category pass through untouched.
///
/// The allowances count **failed** requests. A request that succeeded does not spend the
/// allowance of the ones after it: a `login()` that discovered, then pushed, must still be able
/// to repeat the push `maxAttemptsPerOrigin` times in all, although discovery lives on the same
/// origin. For one call that fails every time the two readings are the same number (that many
/// requests, original included), which is the case the ceilings exist for.
package actor RetryBudget {
    private let policy: RetryPolicy
    private let clock: Clock
    private let random: RandomSource
    private let cooldown: RetryCooldown?
    private let sleep: @Sendable (TimeInterval) async throws -> Void
    private let startedAt: TimeInterval
    /// Time the operation spent where the SDK's retrying does not run (the user in the browser),
    /// left out of what the wall-clock budget counts: see `beginPause`.
    private var pausedFor: TimeInterval = 0
    private var pauseDepth = 0
    private var pauseStartedAt: TimeInterval = 0
    private var failuresPerOrigin: [String: Int] = [:]
    private var totalFailures = 0
    private var callsStarted = 0
    private var lastFailure: OAuthError?

    init(policy: RetryPolicy, clock: Clock, random: RandomSource, cooldown: RetryCooldown? = nil, sleep: @escaping @Sendable (TimeInterval) async throws -> Void) {
        self.policy = policy
        self.clock = clock
        self.random = random
        self.cooldown = cooldown
        self.sleep = sleep
        self.startedAt = clock.uptime()
    }

    /// Runs `call` against `origin`, repeating it while the failure, the allowances and the
    /// wall-clock budget all permit.
    ///
    /// - Parameter mayRepeat: asked of a failure that is otherwise repeatable, and a `false` ends
    ///   the call with that failure after the request that produced it, no delay and no count
    ///   against the allowances. It is how a request that cannot be repeated safely after an
    ///   *ambiguous* failure (the provider may have processed it) is kept from being repeated,
    ///   while the failures that prove it was not processed still are.
    package func execute<T: Sendable>(origin: String, mayRepeat: (@Sendable (OAuthError) -> Bool)? = nil, _ call: @Sendable () async throws -> T) async throws -> T {
        var callAttempts = 0
        while true {
            // The cooldown first: a request the server asked us not to send is not a request.
            try await cooldown?.check(origin)
            try refuseIfSpent(origin)
            callsStarted += 1
            callAttempts += 1
            do {
                return try await call()
            } catch let error as OAuthError {
                guard let repeatable = ServerFailure.repeatable(error) else { throw error }
                if let mayRepeat, !mayRepeat(error) { throw error }
                failuresPerOrigin[origin, default: 0] += 1
                totalFailures += 1
                lastFailure = error
                let delay: TimeInterval
                if let retryAfter = repeatable.retryAfterMillis {
                    // In preference to the backoff: the server has said when it will accept the
                    // request, and an earlier one is a request it said it would refuse. Never
                    // shortened to fit: a value the budget cannot hold ends the operation now
                    // and is handed to the app, which can schedule what the SDK may not wait for.
                    let room = Int64(max(0, policy.totalBudget - elapsed()) * 1000)
                    if retryAfter > room { throw await ended(error, repeatable, origin, callAttempts) }
                    // Jitter keeps clients that were told the same moment from arriving together;
                    // it may not push a wait that fits past the budget.
                    let jitterCeiling = min(retryAfter / 10, 1000, room - retryAfter)
                    delay = Double(retryAfter + jitter(upTo: jitterCeiling)) / 1000
                } else {
                    // Computed before the caps are consulted: a delay that would outlast the
                    // wall-clock ceiling ends the operation here rather than sleeping the budget
                    // away and failing afterwards.
                    delay = backoffAfter(callAttempts)
                    if elapsed() + delay > policy.totalBudget { throw await ended(error, repeatable, origin, callAttempts) }
                }
                if !hasAttemptLeft(origin) { throw await ended(error, repeatable, origin, callAttempts) }
                try await sleep(delay)
            }
        }
    }

    /// Runs `call` once and never repeats it, remembering a `Retry-After` it is answered with: the
    /// authorization code exchange, which a repeat would replay (`spec/retry-policy.md`, "Never
    /// retried"). It is **not** refused by a cooldown: `login()` checks that before the browser
    /// opens, where a refusal costs the user nothing, and a request that has got this far is sent
    /// and answered by the server.
    package func executeOnce<T: Sendable>(origin: String, _ call: @Sendable () async throws -> T) async throws -> T {
        callsStarted += 1
        do {
            return try await call()
        } catch let error as OAuthError {
            if case .recoverable(.server(let status, let retryAfter?, _, _)) = error {
                await cooldown?.record(origin: origin, status: status, retryAfterMillis: retryAfter)
            }
            throw error
        }
    }

    /// Ends the operation on `failure`: the cooldown is started when the server named a time,
    /// and the error carries what this call and this operation spent.
    private func ended(_ failure: OAuthError, _ repeatable: ServerFailure.Repeatable, _ origin: String, _ callAttempts: Int) async -> OAuthError {
        if let retryAfter = repeatable.retryAfterMillis, let status = repeatable.status {
            await cooldown?.record(origin: origin, status: status, retryAfterMillis: retryAfter)
        }
        return surfaced(failure, attempts: callAttempts)
    }

    private func refuseIfSpent(_ origin: String) throws {
        // A call that follows only successes is never pre-empted: the budget bounds the retries
        // of a failing call, and a call that was never made cannot be one.
        guard let last = lastFailure else { return }
        if hasAttemptLeft(origin) && elapsed() < policy.totalBudget { return }
        throw surfaced(last, attempts: 0)
    }

    private func hasAttemptLeft(_ origin: String) -> Bool {
        totalFailures < policy.maxTotalAttempts && failuresPerOrigin[origin, default: 0] < policy.maxAttemptsPerOrigin
    }

    private func backoffAfter(_ attempts: Int) -> TimeInterval {
        let exponential = policy.initialBackoff * pow(policy.backoffMultiplier, Double(attempts - 1))
        let capped = min(exponential, policy.maxBackoff)
        // Full jitter: uniform in [0, capped].
        return capped * fraction()
    }

    private func jitter(upTo ceiling: Int64) -> Int64 {
        guard ceiling > 0 else { return 0 }
        return Int64(Double(ceiling) * fraction())
    }

    private func fraction() -> Double {
        let bytes = random.bytes(8)
        return Double(bytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) } % 1_000_000) / 1_000_000
    }

    private func surfaced(_ failure: OAuthError, attempts: Int) -> OAuthError {
        let elapsedMillis = Int64(elapsed() * 1000)
        switch failure {
        case .recoverable(.network(let detail, _, _)):
            return .recoverable(.network(detail: detail, attempts: attempts, elapsedMillis: elapsedMillis))
        case .recoverable(.server(let status, let retryAfter, _, _)):
            return .recoverable(.server(status: status, retryAfterMillis: retryAfter, attempts: attempts, elapsedMillis: elapsedMillis))
        default:
            return failure
        }
    }

    /// The user's time in the browser is not the SDK's retrying (`spec/retry-policy.md`, "Order of
    /// work"): it is left out of the wall-clock budget, so one budget serves the whole `login()`
    /// and the allowances are shared across the browser. Pauses may overlap; the time counts once.
    package func beginPause() {
        if pauseDepth == 0 { pauseStartedAt = clock.uptime() }
        pauseDepth += 1
    }

    package func endPause() {
        pauseDepth -= 1
        if pauseDepth == 0 { pausedFor += clock.uptime() - pauseStartedAt }
    }

    private func elapsed() -> TimeInterval {
        let now = clock.uptime()
        let pausedNow = pauseDepth > 0 ? now - pauseStartedAt : 0
        return max(0, now - startedAt - pausedFor - pausedNow)
    }
}
