package versola.oauth.flutter.conformance

import android.os.Looper
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Future
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.LockSupport
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import org.robolectric.Shadows.shadowOf

/**
 * How a test thread waits for the plugin. The Pigeon handlers answer from `Dispatchers.Main`,
 * which under Robolectric is the test thread's own looper, paused: a task posted to it runs only
 * when the test thread lets it. So a wait on the main thread drains the looper while it polls, and
 * a wait on any other thread (a proxy hook, the browser leg) simply blocks on the answer. Every
 * wait is bounded; nothing here is a fixed delay.
 */
object Waiting {
    private val onMainThread: Boolean get() = Looper.myLooper() == Looper.getMainLooper()

    fun <T> await(future: Future<T>, what: String, timeout: Duration = 60.seconds): T {
        if (!onMainThread) {
            return try {
                future.get(timeout.inWholeMilliseconds, TimeUnit.MILLISECONDS)
            } catch (e: java.util.concurrent.TimeoutException) {
                throw AssertionError("timed out after $timeout waiting for $what", e)
            } catch (e: java.util.concurrent.ExecutionException) {
                throw e.cause ?: e
            }
        }
        val deadline = System.nanoTime() + timeout.inWholeNanoseconds
        while (!future.isDone) {
            shadowOf(Looper.getMainLooper()).idle()
            if (future.isDone) break
            if (System.nanoTime() > deadline) throw AssertionError("timed out after $timeout waiting for $what")
            LockSupport.parkNanos(500_000)
        }
        return try {
            future.get()
        } catch (e: java.util.concurrent.ExecutionException) {
            throw e.cause ?: e
        }
    }

    /** Waits until [condition] holds, draining the main looper meanwhile. */
    fun until(what: String, timeout: Duration = 30.seconds, condition: () -> Boolean) {
        val deadline = System.nanoTime() + timeout.inWholeNanoseconds
        while (!condition()) {
            if (onMainThread) shadowOf(Looper.getMainLooper()).idle()
            if (condition()) break
            if (System.nanoTime() > deadline) throw AssertionError("timed out after $timeout waiting until $what")
            LockSupport.parkNanos(500_000)
        }
    }

    /**
     * Runs a suspending call of the native client on a worker, for what the test observes on the
     * SDK's own instance (its discovery document, its configuration), which the bridge does not carry.
     */
    fun <T> blocking(what: String, block: suspend () -> T): T {
        val future = CompletableFuture<T>()
        CoroutineScope(Dispatchers.Default).launch {
            try {
                future.complete(block())
            } catch (e: Throwable) {
                future.completeExceptionally(e)
            }
        }
        return await(future, what)
    }
}
