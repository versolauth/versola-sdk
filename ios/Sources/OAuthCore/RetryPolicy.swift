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

    public init(
        maxAttemptsPerOrigin: Int = 3, maxTotalAttempts: Int = 4, initialBackoff: TimeInterval = 0.5,
        backoffMultiplier: Double = 2, maxBackoff: TimeInterval = 8, totalBudget: TimeInterval = 30
    ) throws {
        func bounded(_ name: String, _ value: Int, _ lower: Int, _ upper: Int) throws {
            if value < lower || value > upper {
                throw OAuthError.configuration(.invalidConfiguration(detail: "\(name) must be between \(lower) and \(upper): \(value)"))
            }
        }
        try bounded("maxAttemptsPerOrigin", maxAttemptsPerOrigin, 1, Self.maxAttemptsPerOriginCeiling)
        try bounded("maxTotalAttempts", maxTotalAttempts, 1, Self.maxTotalAttemptsCeiling)
        if initialBackoff < 0 || maxBackoff < initialBackoff || backoffMultiplier < 1 {
            throw OAuthError.configuration(.invalidConfiguration(detail: "backoff must be non-negative, non-decreasing, multiplier at least 1"))
        }
        if totalBudget <= 0 || totalBudget > Self.totalBudgetCeiling {
            throw OAuthError.configuration(.invalidConfiguration(detail: "totalBudget must be between 0 and \(Self.totalBudgetCeiling) s: \(totalBudget)"))
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
