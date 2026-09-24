package kz.versola.sdk.core

import kotlin.math.pow
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.delay

/**
 * How patient the SDK is with a failure it may retry, within bounds an integrator cannot
 * raise. `spec/retry-policy.md` is normative for every platform: same field names, same
 * defaults, same maxima.
 *
 * The bound is the point. A retry loop in a shipped app cannot be recalled — it keeps running
 * on every installed device until the next release reaches them — so whether the client stops
 * on its own has to be decided here rather than by whatever the server does about it.
 *
 * A value past a maximum is refused rather than clamped: silently accepting it teaches an
 * integrator that the knob works.
 */
public class RetryPolicy(
    /** Requests to one origin per operation, the original included. */
    public val maxAttemptsPerOrigin: Int = 3,
    /** Requests across all origins per operation. A refresh plus the replayed call is two. */
    public val maxTotalAttempts: Int = 4,
    /** Delay before the second attempt. */
    public val initialBackoff: Duration = 500.milliseconds,
    /** Applied per attempt. */
    public val backoffMultiplier: Double = 2.0,
    /** Ceiling on any single delay. */
    public val maxBackoff: Duration = 8.seconds,
    /** Wall-clock ceiling for one operation, delays included. */
    public val totalBudget: Duration = 20.seconds,
) {

    init {
        bounded("maxAttemptsPerOrigin", maxAttemptsPerOrigin, 1, MAX_ATTEMPTS_PER_ORIGIN_CEILING)
        bounded("maxTotalAttempts", maxTotalAttempts, 1, MAX_TOTAL_ATTEMPTS_CEILING)
        bounded("backoffMultiplier", backoffMultiplier, 1.0, BACKOFF_MULTIPLIER_CEILING)
        bounded("initialBackoff", initialBackoff, Duration.ZERO, MAX_BACKOFF_CEILING)
        bounded("maxBackoff", maxBackoff, Duration.ZERO, MAX_BACKOFF_CEILING)
        bounded("totalBudget", totalBudget, Duration.ZERO, TOTAL_BUDGET_CEILING)
        // An operation whose per-origin allowance exceeds its total allowance reads as two
        // different promises, and the smaller one silently wins. Say so at configuration
        // time instead, where it is one line to fix.
        if (maxAttemptsPerOrigin > maxTotalAttempts) {
            throw invalid(
                "maxAttemptsPerOrigin ($maxAttemptsPerOrigin) exceeds maxTotalAttempts " +
                    "($maxTotalAttempts), so the per-origin allowance can never be reached",
            )
        }
    }

    /**
     * A fresh budget for one operation. Never shared: the counters are the operation.
     *
     * The default clock is [System.nanoTime], not wall-clock time: `totalBudget` bounds how
     * long an operation is allowed to keep retrying, and a wall clock that a user or NTP can
     * step backwards while the operation is in flight would let it keep retrying past that
     * ceiling by exactly the size of the step. `nanoTime` is monotonic within one JVM run,
     * which is all an elapsed-time measurement ever needs.
     */
    internal fun newBudget(
        clock: () -> Long = { System.nanoTime() / NANOS_PER_MILLI },
        random: Random = Random.Default,
    ): RetryBudget = RetryBudget(this, clock, random)

    public companion object {
        private const val MAX_ATTEMPTS_PER_ORIGIN_CEILING = 5
        private const val MAX_TOTAL_ATTEMPTS_CEILING = 8
        private const val BACKOFF_MULTIPLIER_CEILING = 4.0
        private val MAX_BACKOFF_CEILING = 30.seconds
        private val TOTAL_BUDGET_CEILING = 60.seconds
        private const val NANOS_PER_MILLI = 1_000_000L

        /** The defaults of `spec/retry-policy.md`, and what `configure()` uses unasked. */
        public val Default: RetryPolicy = RetryPolicy()

        /**
         * Fewer attempts and a shorter ceiling, for a foreground call where a user is
         * watching a spinner and a fast failure beats a late success.
         */
        public val Conservative: RetryPolicy = RetryPolicy(
            maxAttemptsPerOrigin = 2,
            maxTotalAttempts = 2,
            initialBackoff = 250.milliseconds,
            maxBackoff = 2.seconds,
            totalBudget = 5.seconds,
        )

        /** The maxima themselves, for background work on a network that drops responses. */
        public val Patient: RetryPolicy = RetryPolicy(
            maxAttemptsPerOrigin = MAX_ATTEMPTS_PER_ORIGIN_CEILING,
            maxTotalAttempts = MAX_TOTAL_ATTEMPTS_CEILING,
            maxBackoff = MAX_BACKOFF_CEILING,
            totalBudget = TOTAL_BUDGET_CEILING,
        )

        // Written as .compareTo() rather than < and > so this stays correct independently of
        // the Kotlin rule that makes it correct today: `T` here is a type parameter, not the
        // concrete `Double`, so `<`/`>` already resolve to `Comparable.compareTo` rather than
        // the IEEE 754 float comparison that treats every comparison with NaN as false — under
        // Double.compareTo, NaN sorts above every other value including +Infinity, so
        // `backoffMultiplier = Double.NaN` is already rejected by the upper-bound check.
        // Spelling out .compareTo() says so without asking a future reader to know that.
        private fun <T : Comparable<T>> bounded(name: String, value: T, floor: T, ceiling: T) {
            if (value.compareTo(floor) < 0) throw invalid("$name must be at least $floor, was $value")
            if (value.compareTo(ceiling) > 0) throw invalid("$name must be at most $ceiling, was $value")
        }

        private fun invalid(detail: String) = VersolaError.Configuration(
            VersolaError.Configuration.Detail.InvalidConfiguration(detail),
        )
    }
}

/**
 * One operation's allowance, spent across every request that operation makes.
 *
 * One application-visible call is one operation: a `login()`, one request through the SDK's
 * HTTP client, one refresh. The steps taken to satisfy it — a refresh triggered by a 401, the
 * replay of the original call afterwards — run on *this* budget rather than opening budgets of
 * their own. That is what stops the compounding failure where a call with three attempts
 * triggers a refresh with three attempts and the pair emits nine requests.
 *
 * What is retried is decided by the error taxonomy rather than by a list kept here:
 * [VersolaError.Recoverable.Cause.Network] is the SDK's name for a failure the next attempt
 * might not have — transport, timeout, DNS, 5xx, 408 — and everything else propagates on the
 * first failure. `invalid_grant`, a step-up, a nonce loop, a cancel and every `Configuration`
 * fault are terminal by construction, so none of them can be retried by omission.
 *
 * The two protocol-shaped retries — `use_dpop_nonce` and `invalid_dpop_proof` — are not here.
 * Each is an answer to a challenge rather than to a failure, each is fixed at exactly one, and
 * both live inside [HttpTokenClient], which is also the only place holding what the retry
 * needs.
 */
internal class RetryBudget(
    private val policy: RetryPolicy,
    private val clock: () -> Long,
    private val random: Random,
) {

    private val startedAt = clock()
    private val attemptsPerOrigin = mutableMapOf<String, Int>()
    private var totalAttempts = 0
    private var lastFailure: VersolaError.Recoverable? = null

    /**
     * Runs [call] against [origin], retrying it while the allowance and the taxonomy both
     * permit one.
     *
     * [origin] is a scheme-and-authority the per-origin cap is counted against; requests to
     * two different hosts within one operation do not spend each other's allowance, though
     * they do share [RetryPolicy.maxTotalAttempts].
     *
     * [RetryPolicy.totalBudget] bounds the gaps *between* attempts, not an attempt already in
     * flight: the time [call] itself takes counts against the budget once it returns or
     * throws — which is why a slow attempt leaves less room for the next one — but this
     * method does not cancel [call] partway through. Bounding how long a single request may
     * run is the HTTP client's job (a connect/read/call timeout on the `OkHttpClient` an
     * integrator configures), because only the client knows which phase of the request is
     * slow; a budget that cannot see inside [call] would have to guess.
     */
    suspend fun <T> execute(origin: String, call: suspend () -> T): T {
        while (true) {
            refuseIfSpent(origin)
            attemptsPerOrigin[origin] = (attemptsPerOrigin[origin] ?: 0) + 1
            totalAttempts++
            try {
                return call()
            } catch (e: VersolaError.Recoverable) {
                if (e.reason !is VersolaError.Recoverable.Cause.Network) throw e
                lastFailure = e
                // Computed before the caps are consulted, because a delay that would outlast
                // the wall-clock ceiling ends the operation here rather than sleeping the
                // budget away and failing afterwards — the caller is waiting either way, and
                // the late failure costs it the whole ceiling to learn the same thing.
                val backoff = backoffAfter(totalAttempts)
                if (!hasAttemptLeft(origin) || elapsed() + backoff.inWholeMilliseconds > budgetMillis()) {
                    throw exhausted(e)
                }
                delay(backoff)
            }
        }
    }

    /**
     * Refuses to start a request the allowance no longer covers.
     *
     * Reached at the top of a later [execute] in the same operation — a replay after a
     * refresh, say — where the budget was spent by the earlier steps and nothing has failed
     * yet in this one.
     */
    private fun refuseIfSpent(origin: String) {
        // The first request of an operation is never pre-empted: the budget bounds the
        // retries of a call, and a call that was never made cannot be one.
        if (totalAttempts == 0) return
        if (hasAttemptLeft(origin) && elapsed() < budgetMillis()) return
        val last = lastFailure ?: throw VersolaError.Recoverable(
            VersolaError.Recoverable.Cause.Network(
                detail = "the retry budget for this operation was already spent",
                attempts = totalAttempts,
                elapsedMillis = elapsed(),
            ),
        )
        throw exhausted(last)
    }

    private fun hasAttemptLeft(origin: String): Boolean =
        totalAttempts < policy.maxTotalAttempts &&
            (attemptsPerOrigin[origin] ?: 0) < policy.maxAttemptsPerOrigin

    /**
     * Full jitter: uniform over `[0, capped]` rather than the capped delay itself. Not
     * configurable, because the failure it prevents is collective — every device that saw the
     * same outage retrying on the same schedule is a thundering herd, and no single app's
     * configuration can see it.
     */
    private fun backoffAfter(attempts: Int): Duration {
        val exponential = policy.initialBackoff * policy.backoffMultiplier.pow(attempts - 1)
        val capped = minOf(exponential, policy.maxBackoff)
        return random.nextLong(capped.inWholeMilliseconds + 1).milliseconds
    }

    /**
     * The failure that ended the operation, re-raised with the count and the elapsed time on
     * it. An integrator seeing "3 attempts over 4.2 s" knows the ceiling was reached; the
     * same message without them is indistinguishable from a single failed request.
     */
    private fun exhausted(failure: VersolaError.Recoverable): VersolaError.Recoverable {
        val reason = failure.reason as VersolaError.Recoverable.Cause.Network
        return VersolaError.Recoverable(
            VersolaError.Recoverable.Cause.Network(
                detail = reason.detail,
                attempts = totalAttempts,
                elapsedMillis = elapsed(),
            ),
            failure.cause ?: failure,
        )
    }

    private fun elapsed(): Long = clock() - startedAt

    private fun budgetMillis(): Long = policy.totalBudget.inWholeMilliseconds
}
