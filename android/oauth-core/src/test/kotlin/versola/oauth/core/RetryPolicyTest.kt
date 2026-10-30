package versola.oauth.core

import kotlin.random.Random
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RetryPolicyTest {

    @Test
    fun `the defaults are the ones the spec fixes for every platform`() {
        val policy = RetryPolicy()

        assertEquals(3, policy.maxAttemptsPerOrigin)
        assertEquals(4, policy.maxTotalAttempts)
        assertEquals(500.milliseconds, policy.initialBackoff)
        assertEquals(2.0, policy.backoffMultiplier, 0.0)
        assertEquals(8.seconds, policy.maxBackoff)
        assertEquals(20.seconds, policy.totalBudget)
    }

    @Test
    fun `a value past a hard maximum is refused rather than clamped`() {
        // Clamping teaches an integrator that the knob works, and the app ships believing
        // something about its own retry behaviour that is not true.
        assertRefuses { RetryPolicy(maxAttemptsPerOrigin = 6, maxTotalAttempts = 8) }
        assertRefuses { RetryPolicy(maxTotalAttempts = 9) }
        assertRefuses { RetryPolicy(backoffMultiplier = 4.1) }
        assertRefuses { RetryPolicy(maxBackoff = 31.seconds) }
        assertRefuses { RetryPolicy(totalBudget = 61.seconds) }
    }

    @Test
    fun `NaN is outside every bound`() {
        // Regression guard for the generic-dispatch reasoning documented on `bounded`: this
        // must keep throwing even if the check is ever rewritten in a way that resolves to
        // the primitive IEEE 754 comparison, under which every comparison with NaN is false.
        assertRefuses { RetryPolicy(backoffMultiplier = Double.NaN) }
    }

    @Test
    fun `a policy that cannot make a request is refused too`() {
        // Zero attempts is not "no retries", it is no request at all, and the call it was
        // meant to govern would fail without ever reaching the network.
        assertRefuses { RetryPolicy(maxAttemptsPerOrigin = 0) }
        assertRefuses { RetryPolicy(maxTotalAttempts = 0) }
        assertRefuses { RetryPolicy(backoffMultiplier = 0.9) }
    }

    @Test
    fun `a per-origin allowance above the total allowance is refused`() {
        // Two different promises, of which the smaller silently wins.
        assertRefuses { RetryPolicy(maxAttemptsPerOrigin = 4, maxTotalAttempts = 2) }
    }

    @Test
    fun `the presets stay inside the bounds they are presets of`() {
        assertEquals(5, RetryPolicy.Patient.maxAttemptsPerOrigin)
        assertEquals(8, RetryPolicy.Patient.maxTotalAttempts)
        assertEquals(30.seconds, RetryPolicy.Patient.maxBackoff)
        assertEquals(60.seconds, RetryPolicy.Patient.totalBudget)
        assertTrue(RetryPolicy.Conservative.maxTotalAttempts < RetryPolicy.Default.maxTotalAttempts)
        assertTrue(RetryPolicy.Conservative.totalBudget < RetryPolicy.Default.totalBudget)
    }

    @Test
    fun `a transport failure is retried up to the per-origin ceiling`() = runTest {
        var attempts = 0

        val failure = failure {
            budget(RetryPolicy(maxAttemptsPerOrigin = 3, maxTotalAttempts = 4)).execute(ORIGIN) {
                attempts++
                throw network()
            }
        }

        assertEquals(3, attempts)
        val reason = (failure as VersolaError.Recoverable).reason as VersolaError.Recoverable.Cause.Network
        // The count and the elapsed time are what tell a reached ceiling apart from one
        // request that failed.
        assertEquals(3, reason.attempts)
        assertTrue(reason.elapsedMillis > 0)
        assertEquals("connection reset", reason.detail)
    }

    @Test
    fun `an attempt that succeeds ends the operation with its value`() = runTest {
        var attempts = 0

        val result = budget().execute(ORIGIN) {
            attempts++
            if (attempts < 3) throw network()
            "issued"
        }

        assertEquals("issued", result)
        assertEquals(3, attempts)
    }

    @Test
    fun `everything the taxonomy calls terminal is terminal on the first failure`() = runTest {
        // Retryability is read off the error category rather than off a list kept here, so a
        // cause added later cannot become retryable by being forgotten.
        for (terminal in terminalFailures()) {
            var attempts = 0
            failure {
                budget().execute(ORIGIN) {
                    attempts++
                    throw terminal
                }
            }
            assertEquals("${terminal::class.simpleName} was retried", 1, attempts)
        }
    }

    @Test
    fun `two origins share one total allowance`() = runTest {
        // A refresh at the token endpoint and the call it was triggered by are one operation.
        val budget = budget(RetryPolicy(maxAttemptsPerOrigin = 3, maxTotalAttempts = 4))
        var atToken = 0
        var atEdge = 0

        failure { budget.execute(ORIGIN) { atToken++; throw network() } }
        failure { budget.execute(OTHER_ORIGIN) { atEdge++; throw network() } }

        assertEquals(3, atToken)
        // Its own ceiling is three, and one attempt is what the operation had left.
        assertEquals(1, atEdge)
    }

    @Test
    fun `a spent budget refuses the next request rather than making it`() = runTest {
        val budget = budget(RetryPolicy(maxAttemptsPerOrigin = 2, maxTotalAttempts = 2))
        var called = false
        failure { budget.execute(ORIGIN) { throw network() } }

        val failure = failure { budget.execute(OTHER_ORIGIN) { called = true; "issued" } }

        assertFalse(called)
        val reason = (failure as VersolaError.Recoverable).reason as VersolaError.Recoverable.Cause.Network
        assertEquals(2, reason.attempts)
    }

    @Test
    fun `a delay that would outlast the wall-clock ceiling ends the operation instead`() = runTest {
        // Sleeping the ceiling away and failing afterwards costs the caller the whole budget
        // to learn what is already known at the moment the delay is computed.
        val scheduler = testScheduler
        var attempts = 0

        failure {
            budget(
                RetryPolicy(
                    maxAttemptsPerOrigin = 3,
                    maxTotalAttempts = 3,
                    initialBackoff = 5.seconds,
                    maxBackoff = 8.seconds,
                    totalBudget = 2.seconds,
                ),
                random = NO_JITTER,
            ).execute(ORIGIN) {
                attempts++
                throw network()
            }
        }

        assertEquals(1, attempts)
        assertTrue("slept past the ceiling: ${scheduler.currentTime}ms", scheduler.currentTime < 2_000)
    }

    @Test
    fun `the backoff grows per attempt and stops at its ceiling`() = runTest {
        val scheduler = testScheduler
        val delays = mutableListOf<Long>()
        var previous = 0L

        failure {
            budget(
                RetryPolicy(
                    maxAttemptsPerOrigin = 4,
                    maxTotalAttempts = 4,
                    initialBackoff = 1.seconds,
                    backoffMultiplier = 2.0,
                    maxBackoff = 3.seconds,
                    totalBudget = 60.seconds,
                ),
                random = NO_JITTER,
            ).execute(ORIGIN) {
                delays += scheduler.currentTime - previous
                previous = scheduler.currentTime
                throw network()
            }
        }

        // The first attempt is immediate; then 1 s, 2 s, and 4 s clamped to the 3 s ceiling.
        assertEquals(listOf(0L, 1_000L, 2_000L, 3_000L), delays)
    }

    @Test
    fun `jitter keeps every delay inside the computed backoff`() = runTest {
        // Full jitter is uniform over [0, capped]: the point is that two devices that saw the
        // same outage do not come back at the same moment.
        val scheduler = testScheduler
        val delays = mutableListOf<Long>()
        var previous = 0L

        failure {
            budget(
                RetryPolicy(
                    maxAttemptsPerOrigin = 5,
                    maxTotalAttempts = 5,
                    initialBackoff = 1.seconds,
                    backoffMultiplier = 1.0,
                    maxBackoff = 1.seconds,
                    totalBudget = 60.seconds,
                ),
                random = Random(20260924),
            ).execute(ORIGIN) {
                delays += scheduler.currentTime - previous
                previous = scheduler.currentTime
                throw network()
            }
        }

        assertEquals(5, delays.size)
        assertTrue("delays outside [0, 1000]: $delays", delays.all { it in 0..1_000 })
        assertTrue("no jitter was applied: $delays", delays.drop(1).toSet().size > 1)
    }

    // ---- Retry-After and the other server statuses -------------------------------------------

    private fun server(status: Int, retryAfterMillis: Long? = null) = VersolaError.Recoverable(
        VersolaError.Recoverable.Cause.Server(status, retryAfterMillis),
    )

    @Test
    fun `a Retry-After replaces the backoff, with up to a tenth of it as jitter`() = runTest {
        val scheduler = testScheduler
        var attempts = 0
        var secondAt = -1L

        budget(RetryPolicy(totalBudget = 60.seconds), random = Random(7)).execute(ORIGIN) {
            attempts++
            if (attempts == 1) throw server(429, 2_000)
            secondAt = scheduler.currentTime
        }

        assertEquals(2, attempts)
        // Not before the server said, and not past the tenth the jitter may add (200 ms).
        assertTrue("waited ${secondAt}ms", secondAt in 2_000..2_200)
    }

    @Test
    fun `a Retry-After of zero retries at once but still counts as an attempt`() = runTest {
        var attempts = 0

        val failure = failure { budget().execute(ORIGIN) { attempts++; throw server(503, 0) } }

        assertEquals(3, attempts)
        val reason = (failure as VersolaError.Recoverable).reason as VersolaError.Recoverable.Cause.Server
        assertEquals(3, reason.attempts)
        assertEquals(0L, reason.retryAfterMillis)
        assertEquals(0L, testScheduler.currentTime)
    }

    @Test
    fun `a Retry-After that does not fit the budget stops at once, neither sleeping nor shortening the wait`() = runTest {
        var attempts = 0

        val failure = failure { budget().execute(ORIGIN) { attempts++; throw server(429, 30_000) } }

        assertEquals(1, attempts)
        // Retrying earlier than the server asked would be sending a request it said it would refuse.
        assertEquals(0L, testScheduler.currentTime)
        val reason = (failure as VersolaError.Recoverable).reason as VersolaError.Recoverable.Cause.Server
        assertEquals(429, reason.status)
        assertEquals(30_000L, reason.retryAfterMillis)
        assertEquals(1, reason.attempts)
    }

    @Test
    fun `a day-long Retry-After costs no waiting and no second request`() = runTest {
        var attempts = 0

        val failure = failure { budget(RetryPolicy.Patient).execute(ORIGIN) { attempts++; throw server(503, 86_400_000) } }

        assertEquals(1, attempts)
        assertEquals(0L, testScheduler.currentTime)
        assertEquals(
            86_400_000L,
            ((failure as VersolaError.Recoverable).reason as VersolaError.Recoverable.Cause.Server).retryAfterMillis,
        )
    }

    @Test
    fun `a Retry-After on a status the SDK does not repeat is not waited for`() = runTest {
        var attempts = 0

        failure { budget().execute(ORIGIN) { attempts++; throw server(501, 2_000) } }

        assertEquals(1, attempts)
        assertEquals(0L, testScheduler.currentTime)
    }

    @Test
    fun `500 502 503 504 408 and 429 are repeated with the backoff when no Retry-After came`() = runTest {
        for (status in listOf(500, 502, 503, 504, 408, 429)) {
            var attempts = 0
            val failure = failure { budget().execute(ORIGIN) { attempts++; throw server(status) } }
            assertEquals("$status", 3, attempts)
            val reason = (failure as VersolaError.Recoverable).reason as VersolaError.Recoverable.Cause.Server
            assertEquals(status, reason.status)
            assertEquals(3, reason.attempts)
            assertNull(reason.retryAfterMillis)
        }
    }

    @Test
    fun `501, 505 and a status no operation expected are surfaced after one request with no delay`() = runTest {
        for (status in listOf(501, 505, 404, 302)) {
            var attempts = 0
            val failure = failure { budget().execute(ORIGIN) { attempts++; throw server(status) } }
            assertEquals("$status", 1, attempts)
            val reason = (failure as VersolaError.Recoverable).reason as VersolaError.Recoverable.Cause.Server
            assertEquals(1, reason.attempts)
        }
        assertEquals(0L, testScheduler.currentTime)
    }

    @Test
    fun `a Server failure also stops at the per-origin ceiling`() = runTest {
        var attempts = 0

        failure { budget(RetryPolicy(maxAttemptsPerOrigin = 2, maxTotalAttempts = 4)).execute(ORIGIN) { attempts++; throw server(500) } }

        assertEquals(2, attempts)
    }

    @Test
    fun `a request that succeeded spends nothing, so a later one on the same origin keeps its allowance`() = runTest {
        // A login discovers, then pushes, on one origin: the push is not left with two attempts
        // because the discovery before it worked.
        val budget = budget(RetryPolicy(maxAttemptsPerOrigin = 3, maxTotalAttempts = 4))
        var pushes = 0

        assertEquals("discovered", budget.execute(ORIGIN) { "discovered" })
        assertEquals("keys", budget.execute(ORIGIN) { "keys" })
        val failure = failure { budget.execute(ORIGIN) { pushes++; throw server(500) } }

        assertEquals(3, pushes)
        assertEquals(3, ((failure as VersolaError.Recoverable).reason as VersolaError.Recoverable.Cause.Server).attempts)
    }

    @Test
    fun `failures in two steps of one operation share the allowance`() = runTest {
        // The compounding guard: a call that fails and the refresh it triggers are one operation.
        val budget = budget(RetryPolicy(maxAttemptsPerOrigin = 3, maxTotalAttempts = 4))
        var first = 0
        var second = 0

        failure { budget.execute(ORIGIN) { first++; throw server(500) } }
        failure { budget.execute(OTHER_ORIGIN) { second++; throw server(500) } }

        assertEquals(3, first)
        assertEquals(1, second)
    }

    // ---- the cooldown -------------------------------------------------------------------------

    @Test
    fun `after a Retry-After nothing is sent to that origin until it has passed`() = runTest {
        var now = 0L
        val cooldown = RetryCooldown { now }
        val policy = RetryPolicy()
        var sent = 0

        failure { policy.newBudget({ now }, Random(1), cooldown).execute(ORIGIN) { sent++; throw server(429, 30_000) } }
        assertEquals(1, sent)

        // Inside the window: refused without a request, with what is left and attempts 0.
        now = 12_000
        val refused = failure { policy.newBudget({ now }, Random(1), cooldown).execute(ORIGIN) { sent++ } }
        assertEquals(1, sent)
        val cause = (refused as VersolaError.Recoverable).reason as VersolaError.Recoverable.Cause.Server
        assertEquals(429, cause.status)
        assertEquals(18_000L, cause.retryAfterMillis)
        assertEquals(0, cause.attempts)

        // After it: sent.
        now = 30_000
        val result = policy.newBudget({ now }, Random(1), cooldown).execute(ORIGIN) { sent++; "ok" }
        assertEquals("ok", result)
        assertEquals(2, sent)
    }

    @Test
    fun `a cooldown holds one origin and leaves the others alone`() = runTest {
        var now = 0L
        val cooldown = RetryCooldown { now }
        val policy = RetryPolicy()

        failure { policy.newBudget({ now }, Random(1), cooldown).execute(ORIGIN) { throw server(503, 30_000) } }

        assertEquals("ok", policy.newBudget({ now }, Random(1), cooldown).execute(OTHER_ORIGIN) { "ok" })
    }

    @Test
    fun `exhausting the budget on 5xx without a Retry-After starts no cooldown`() = runTest {
        val now = 0L
        val cooldown = RetryCooldown { now }
        val policy = RetryPolicy()
        var sent = 0

        failure { policy.newBudget({ now }, Random(1), cooldown).execute(ORIGIN) { sent++; throw server(500) } }
        failure { policy.newBudget({ now }, Random(1), cooldown).execute(ORIGIN) { sent++; throw server(500) } }

        // A second set of three: the SDK invents no provider policy; the app owns the retry loop.
        assertEquals(6, sent)
    }

    // ---- what counts against the budget, and where it applies ---------------------------------

    @Test
    fun `time spent outside the budget is not spent from it`() = runTest {
        var now = 0L
        val budget = RetryPolicy(totalBudget = 20.seconds).newBudget({ now }, Random(1))
        var attempts = 0

        budget.execute(ORIGIN) { attempts++; "first" }
        // Two minutes in the browser.
        budget.paused { now += 120_000 }
        val result = budget.execute(ORIGIN) { attempts++; "second" }

        assertEquals("second", result)
        assertEquals(2, attempts)
    }

    @Test
    fun `a client used outside any operation makes one request`() = runTest {
        var attempts = 0

        failure { retrying(ORIGIN) { attempts++; throw server(503) } }

        assertEquals(1, attempts)
    }

    @Test
    fun `a nested operation runs on the outer budget instead of opening its own`() = runTest {
        val scope = RetryScope(RetryPolicy(maxAttemptsPerOrigin = 3, maxTotalAttempts = 3), { testScheduler.currentTime }, Random(1))
        var attempts = 0

        failure {
            scope.operation {
                failure { retrying(ORIGIN) { attempts++; throw server(500) } }
                // The inner call finds the outer budget spent; a fresh one would make three more.
                scope.operation { retrying(ORIGIN) { attempts++; throw server(500) } }
            }
        }

        assertEquals(3, attempts)
    }

    private fun TestScope.budget(
        policy: RetryPolicy = RetryPolicy(),
        random: Random = Random(1),
    ): RetryBudget = policy.newBudget(clock = { testScheduler.currentTime }, random = random)

    private fun network(detail: String = "connection reset") =
        VersolaError.Recoverable(VersolaError.Recoverable.Cause.Network(detail))

    private fun terminalFailures(): List<VersolaError> = listOf(
        VersolaError.Recoverable(VersolaError.Recoverable.Cause.NonceLoop("https://id.example")),
        VersolaError.Recoverable(VersolaError.Recoverable.Cause.UnlockRequired),
        VersolaError.Recoverable(VersolaError.Recoverable.Cause.UserCancelled),
        VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.GrantRejected),
        VersolaError.StepUp(listOf("urn:mace:incommon:iap:silver"), null),
        VersolaError.Configuration(
            VersolaError.Configuration.Detail.TokenRequestRejected("invalid_client", null),
        ),
    )

    private suspend fun failure(block: suspend () -> Unit): VersolaError = try {
        block()
        throw AssertionError("expected a VersolaError")
    } catch (e: VersolaError) {
        e
    }

    private fun assertRefuses(block: () -> RetryPolicy) {
        val failure = try {
            block()
            throw AssertionError("expected a Configuration error")
        } catch (e: VersolaError.Configuration) {
            e
        }
        assertTrue(failure.detail is VersolaError.Configuration.Detail.InvalidConfiguration)
    }

    private companion object {
        private const val ORIGIN = "https://id.example"
        private const val OTHER_ORIGIN = "https://edge.example"

        /** The full backoff every time, so a test asserts the schedule rather than a sample. */
        private val NO_JITTER = object : Random() {
            override fun nextBits(bitCount: Int): Int = 0
            override fun nextLong(until: Long): Long = until - 1
        }
    }
}
