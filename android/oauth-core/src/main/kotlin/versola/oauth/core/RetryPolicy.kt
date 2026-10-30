package versola.oauth.core

import kotlin.math.pow
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.coroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

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
        cooldown: RetryCooldown = RetryCooldown(clock),
    ): RetryBudget = RetryBudget(this, clock, random, cooldown)

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
 * might not have — transport, timeout, DNS — and [VersolaError.Recoverable.Cause.Server] for an
 * HTTP answer, repeated only for the statuses [ServerFault.isRepeatable] names (408, 429, 500,
 * 502, 503, 504); everything else propagates on the first failure. `invalid_grant`, a step-up, a nonce loop, a cancel and every `Configuration`
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
    private val cooldown: RetryCooldown = RetryCooldown(clock),
) {

    private val startedAt = clock()
    /**
     * What the operation has spent is its *failed* requests, not every request it made. One
     * application call now covers several repeatable requests (a `login()` discovers, pushes and
     * fetches keys), and a success is not a retry: counting it would leave the push two attempts
     * after a successful discovery on the same origin. For a request that fails every time the
     * two counts are the same, which is the number `spec/retry-policy.md` fixes.
     */
    private val failuresPerOrigin = mutableMapOf<String, Int>()
    private var totalFailures = 0
    private var lastFailure: VersolaError.Recoverable? = null
    private var lastCallFailures = 0

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
    suspend fun <T> execute(
        origin: String,
        mayRepeat: (VersolaError.Recoverable) -> Boolean = { true },
        call: suspend () -> T,
    ): T {
        // The failed requests of THIS call: what `attempts` reports, so the number an app reads is
        // the call's own whatever else the operation did before it. The caps below are counted
        // operation-wide.
        var callFailures = 0
        while (true) {
            // Nothing is sent to an origin that said when it would be ready until then; this
            // is the one place a request that was never made fails with `attempts` zero.
            cooldown.refuse(origin)
            refuseIfSpent(origin)
            try {
                return call()
            } catch (e: VersolaError.Recoverable) {
                val cause = e.reason
                val retryAfter = (cause as? VersolaError.Recoverable.Cause.Server)?.retryAfterMillis
                val repeatable = when (cause) {
                    is VersolaError.Recoverable.Cause.Network -> true
                    is VersolaError.Recoverable.Cause.Server -> ServerFault.isRepeatable(cause.status)
                    else -> false
                }
                // A cause this class does not count (a cancel, a nonce loop, an unlock) is the
                // caller's as it stands. A status a repeat cannot help (501, a 404 where a
                // document was expected) is counted and surfaced at once, with no delay.
                if (cause !is VersolaError.Recoverable.Cause.Network &&
                    cause !is VersolaError.Recoverable.Cause.Server
                ) {
                    throw e
                }
                lastFailure = e
                callFailures++
                lastCallFailures = callFailures
                failuresPerOrigin[origin] = (failuresPerOrigin[origin] ?: 0) + 1
                totalFailures++
                // `mayRepeat` is the caller's say on top of the classification: a refresh sent
                // without an `Idempotency-Key` is repeated only when it provably was not processed.
                if (!repeatable || !mayRepeat(e)) throw ended(origin, e, callFailures)
                // Computed before the caps are consulted, because a delay that would outlast
                // the wall-clock ceiling ends the operation here rather than sleeping the
                // budget away and failing afterwards — the caller is waiting either way, and
                // the late failure costs it the whole ceiling to learn the same thing.
                //
                // A `Retry-After` is the server saying when it will accept the request, so it
                // replaces the backoff, and one that does not fit is not shortened to fit: an
                // earlier request is one the server said it would refuse. The operation stops
                // here and the value goes to the app (`spec/retry-policy.md`).
                //
                // The jitter is capped by what the budget has left after the `Retry-After`, so a
                // value that fits on its own is never turned into one that does not by its jitter.
                val room = budgetMillis() - elapsed()
                val wait = if (retryAfter != null) {
                    retryAfter.milliseconds + retryAfterJitter(retryAfter, room - retryAfter)
                } else {
                    backoffAfter(totalFailures)
                }
                if (!hasAttemptLeft(origin) || wait.inWholeMilliseconds > room) {
                    throw ended(origin, e, callFailures)
                }
                delay(wait)
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
        // Nothing has failed yet, so nothing is spent: the budget bounds the retries of a call,
        // and a request that follows only successes is not one.
        val last = lastFailure ?: return
        if (hasAttemptLeft(origin) && elapsed() < budgetMillis()) return
        // Not a new ending: the operation's real ending already started any cooldown.
        throw exhausted(last, lastCallFailures)
    }

    private fun hasAttemptLeft(origin: String): Boolean =
        totalFailures < policy.maxTotalAttempts &&
            (failuresPerOrigin[origin] ?: 0) < policy.maxAttemptsPerOrigin

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
     * Up to a tenth of the server's `Retry-After`, never more than a second, added on top of it:
     * every device that was told the same time would otherwise come back in the same instant.
     */
    private fun retryAfterJitter(retryAfterMillis: Long, roomAfterIt: Long): Duration {
        val ceiling = minOf(retryAfterMillis / RETRY_AFTER_JITTER_DIVISOR, MAX_RETRY_AFTER_JITTER_MILLIS, roomAfterIt)
        return random.nextLong(maxOf(ceiling, 0L) + 1).milliseconds
    }

    /**
     * The operation ends here: the failure goes to the caller, and a `Retry-After` it carried
     * becomes the origin's cooldown. Started at the end and not at the first failure, because a
     * wait that fits and is followed by a success is no reason to refuse another call, and
     * `spec/retry-policy.md` says "when an operation ends because of a `Retry-After`".
     */
    private fun ended(origin: String, failure: VersolaError.Recoverable, callFailures: Int): VersolaError.Recoverable {
        (failure.reason as? VersolaError.Recoverable.Cause.Server)?.let { cause ->
            cause.retryAfterMillis?.let { cooldown.start(origin, cause.status, it) }
        }
        return exhausted(failure, callFailures)
    }

    /**
     * The failure that ended the operation, re-raised with the count of this call's failed
     * requests and the elapsed time on it. An integrator seeing "3 attempts over 4.2 s" knows the ceiling was reached; the
     * same message without them is indistinguishable from a single failed request.
     */
    private fun exhausted(failure: VersolaError.Recoverable, attempts: Int): VersolaError.Recoverable {
        val counted = when (val reason = failure.reason) {
            is VersolaError.Recoverable.Cause.Network ->
                reason.copy(attempts = attempts, elapsedMillis = elapsed())
            is VersolaError.Recoverable.Cause.Server ->
                reason.copy(attempts = attempts, elapsedMillis = elapsed())
            else -> return failure
        }
        return VersolaError.Recoverable(counted, failure.cause ?: failure)
    }

    private var pausedMillis = 0L

    /**
     * Runs [block] without its duration counting against `totalBudget`. The one caller is the
     * browser: a user reading a consent screen for two minutes has spent none of the SDK's
     * patience, and a `login()` is a single operation that discovers, pushes, waits for the
     * user and then validates — the budget would otherwise be spent before the validation
     * started.
     */
    suspend fun <T> paused(block: suspend () -> T): T {
        val started = clock()
        try {
            return block()
        } finally {
            pausedMillis += clock() - started
        }
    }

    private fun elapsed(): Long = clock() - startedAt - pausedMillis

    private fun budgetMillis(): Long = policy.totalBudget.inWholeMilliseconds
}

private const val RETRY_AFTER_JITTER_DIVISOR = 10L
private const val MAX_RETRY_AFTER_JITTER_MILLIS = 1_000L

/**
 * What a server said about when it will accept requests again, per origin, in memory.
 *
 * Set when a 429 or 503 carried a readable `Retry-After`; until it passes, [refuse] fails every
 * SDK-originated request to that origin at once, without sending one. Without this an app that
 * calls `accessToken()` in a loop, or fifty screens that each retry, would send a new request per
 * call to a server that asked for quiet. Not persisted, because a cold start costing one request
 * is the price of not storing a deadline, and nothing starts it but the server's own words: the
 * SDK does not invent a provider's policy (`spec/retry-policy.md`, "Cooldown").
 */
internal class RetryCooldown(private val clock: () -> Long) {

    private class Hold(val untilMillis: Long, val status: Int)

    private val holds = java.util.concurrent.ConcurrentHashMap<String, Hold>()

    fun start(origin: String, status: Int, retryAfterMillis: Long) {
        val until = clock() + retryAfterMillis
        holds.merge(origin, Hold(until, status)) { old, new -> if (new.untilMillis >= old.untilMillis) new else old }
    }

    /** Throws the cooldown's `Server` failure while [origin] is held, with what is left as `retryAfterMillis`. */
    fun refuse(origin: String) {
        val hold = holds[origin] ?: return
        val left = hold.untilMillis - clock()
        if (left <= 0) {
            holds.remove(origin, hold)
            return
        }
        throw VersolaError.Recoverable(
            VersolaError.Recoverable.Cause.Server(
                status = hold.status,
                retryAfterMillis = left,
                attempts = 0,
                elapsedMillis = 0,
            ),
        )
    }
}

/**
 * Carries the operation's [RetryBudget] down the coroutine tree, so a client reaches it without a
 * parameter.
 */
internal class RetryBudgetElement(val budget: RetryBudget) : AbstractCoroutineContextElement(Key) {
    companion object Key : CoroutineContext.Key<RetryBudgetElement>
}

/** Runs [block] with its duration left out of the current operation's budget, if there is one. */
internal suspend fun <T> outsideRetryBudget(block: suspend () -> T): T {
    val budget = coroutineContext[RetryBudgetElement]?.budget ?: return block()
    return budget.paused(block)
}

/**
 * Runs [call] under the current operation's budget, or once when there is none.
 *
 * "None" is a client used on its own, outside an application-visible operation (a unit test, an
 * integrator's own wiring): one request, as before the budget reached every client, because a
 * retry with no operation to bound it is exactly the unbounded loop the policy exists to prevent.
 */
internal suspend fun <T> retrying(
    origin: String,
    mayRepeat: (VersolaError.Recoverable) -> Boolean = { true },
    call: suspend () -> T,
): T {
    val budget = coroutineContext[RetryBudgetElement]?.budget ?: return call()
    return budget.execute(origin, mayRepeat, call)
}

/**
 * Where one application-visible operation gets its one [RetryBudget], and where the cooldown
 * outlives it. The facades wrap each public call in [operation]; a call nested inside another
 * (a refresh inside a `userInfo()`, discovery inside a `login()`) runs on the outer budget rather
 * than opening its own, which is what stops three attempts times three attempts.
 */
@VersolaInternalApi
public class RetryScope internal constructor(
    private val policy: RetryPolicy,
    private val clock: () -> Long,
    private val random: Random,
) {

    public constructor(policy: RetryPolicy) : this(
        policy,
        { System.nanoTime() / 1_000_000L },
        Random.Default,
    )

    private val cooldown = RetryCooldown(clock)

    /** Fails at once, sending nothing, while [origin] is held by a `Retry-After` (`attempts` 0). */
    internal fun refuseIfCoolingDown(origin: String) = cooldown.refuse(origin)

    /**
     * Records the cooldown of a call that is made once and so never reaches the budget (the code
     * exchange): its `Retry-After`, if it had a readable one, quiets the origin like any other
     * operation's ending.
     */
    internal fun endedBy(origin: String, failure: VersolaError.Recoverable) {
        (failure.reason as? VersolaError.Recoverable.Cause.Server)?.let { cause ->
            cause.retryAfterMillis?.let { cooldown.start(origin, cause.status, it) }
        }
    }

    /** Runs [block] as one operation: under the budget already in force, or under a fresh one. */
    public suspend fun <T> operation(block: suspend () -> T): T {
        if (coroutineContext[RetryBudgetElement] != null) return block()
        return withContext(RetryBudgetElement(policy.newBudget(clock, random, cooldown))) { block() }
    }

}
