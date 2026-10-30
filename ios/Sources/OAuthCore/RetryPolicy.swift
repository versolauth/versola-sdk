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
    /// A budget for one operation: retries `recoverable(.network)` failures only, per origin
    /// and in total, with jittered exponential backoff, within the wall-clock budget.
    package func newBudget(clock: Clock = .system, random: RandomSource = SystemRandomSource(), sleep: @escaping @Sendable (TimeInterval) async throws -> Void = { try await Task.sleep(for: .seconds($0)) }) -> RetryBudget {
        RetryBudget(policy: self, clock: clock, random: random, sleep: sleep)
    }
}

/// The retries of one operation (`spec/retry-policy.md`). Everything but a network failure
/// is final: a nonce loop, a locked store and every other category pass through untouched.
package actor RetryBudget {
    private let policy: RetryPolicy
    private let clock: Clock
    private let random: RandomSource
    private let sleep: @Sendable (TimeInterval) async throws -> Void
    private let startedAt: Date
    private var attemptsPerOrigin: [String: Int] = [:]
    private var totalAttempts = 0
    private var lastFailure: OAuthError?

    init(policy: RetryPolicy, clock: Clock, random: RandomSource, sleep: @escaping @Sendable (TimeInterval) async throws -> Void) {
        self.policy = policy
        self.clock = clock
        self.random = random
        self.sleep = sleep
        self.startedAt = clock.now()
    }

    package func execute<T: Sendable>(origin: String, _ call: @Sendable () async throws -> T) async throws -> T {
        while true {
            try refuseIfSpent(origin)
            attemptsPerOrigin[origin, default: 0] += 1
            totalAttempts += 1
            do {
                return try await call()
            } catch let error as OAuthError {
                guard case .recoverable(.network) = error else { throw error }
                lastFailure = error
                // Computed before the caps are consulted: a delay that would outlast the
                // wall-clock ceiling ends the operation here rather than sleeping the budget
                // away and failing afterwards.
                let backoff = backoffAfter(totalAttempts)
                if !hasAttemptLeft(origin) || elapsed() + backoff > policy.totalBudget {
                    throw exhausted(error)
                }
                try await sleep(backoff)
            }
        }
    }

    private func refuseIfSpent(_ origin: String) throws {
        // The first request of an operation is never pre-empted.
        if totalAttempts == 0 { return }
        if hasAttemptLeft(origin) && elapsed() < policy.totalBudget { return }
        guard let last = lastFailure else {
            throw OAuthError.recoverable(.network(detail: "the retry budget for this operation was already spent", attempts: totalAttempts, elapsedMillis: Int64(elapsed() * 1000)))
        }
        throw exhausted(last)
    }

    private func hasAttemptLeft(_ origin: String) -> Bool {
        totalAttempts < policy.maxTotalAttempts && attemptsPerOrigin[origin, default: 0] < policy.maxAttemptsPerOrigin
    }

    private func backoffAfter(_ attempts: Int) -> TimeInterval {
        let exponential = policy.initialBackoff * pow(policy.backoffMultiplier, Double(attempts - 1))
        let capped = min(exponential, policy.maxBackoff)
        // Full jitter: uniform in [0, capped].
        let bytes = random.bytes(8)
        let fraction = Double(bytes.reduce(UInt64(0)) { ($0 << 8) | UInt64($1) } % 1_000_000) / 1_000_000
        return capped * fraction
    }

    private func exhausted(_ failure: OAuthError) -> OAuthError {
        guard case .recoverable(.network(let detail, _, _)) = failure else { return failure }
        return .recoverable(.network(detail: detail, attempts: totalAttempts, elapsedMillis: Int64(elapsed() * 1000)))
    }

    private func elapsed() -> TimeInterval { clock.now().timeIntervalSince(startedAt) }
}
