package versola.oauth.core

import java.util.concurrent.CompletableFuture
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlin.concurrent.thread
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking

/**
 * An app that keeps every thread of `Dispatchers.IO` busy: more blocked callers than the
 * dispatcher's default view has threads, each parked the way a blocking `execute()` parks its
 * thread. While it is open, anything that is dispatched to the default view of `Dispatchers.IO`
 * waits for a caller to leave, and the callers leave only when [close] releases them.
 *
 * The SDK's own blocking work has to make progress regardless; [whileSaturated] runs it on a thread
 * the saturation does not touch and gives it a hard deadline, because a coroutine timeout cannot
 * cancel work that is waiting for a thread that never comes, and a hang here would take the whole
 * test JVM with it instead of failing one test.
 */
internal class IoSaturation private constructor() : AutoCloseable {

    private val release = CountDownLatch(1)
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private fun start() {
        val parked = CountDownLatch(IO_THREADS)
        repeat(CALLERS) {
            scope.launch {
                parked.countDown()
                release.await()
            }
        }
        // Every thread of the default view is now held; the rest of the callers queue behind them.
        check(parked.await(30, TimeUnit.SECONDS)) { "the saturating callers never all started" }
    }

    /** [block] on a thread of its own, which must finish within [seconds] although IO is saturated. */
    fun <T> whileSaturated(seconds: Long = 20, block: suspend () -> T): T {
        val outcome = CompletableFuture<Result<T>>()
        thread(isDaemon = true, name = "sdk-under-test") {
            outcome.complete(runCatching { runBlocking { block() } })
        }
        val result = try {
            outcome.get(seconds, TimeUnit.SECONDS)
        } catch (e: TimeoutException) {
            throw AssertionError(
                "the SDK's blocking work did not finish in ${seconds}s while $CALLERS callers held `Dispatchers.IO`: " +
                    "it was starved of a thread",
            )
        }
        return result.getOrThrow()
    }

    override fun close() {
        release.countDown()
        scope.cancel()
    }

    companion object {
        /** The size of `Dispatchers.IO`'s default view: 64, or the core count when that is larger. */
        val IO_THREADS: Int = maxOf(64, Runtime.getRuntime().availableProcessors())

        /** More callers than threads, so that some of them are queued and the view is truly full. */
        val CALLERS: Int = IO_THREADS + 16

        fun start(): IoSaturation = IoSaturation().also { it.start() }
    }
}
