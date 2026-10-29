package versola.sdk.browser

import kotlinx.coroutines.channels.Channel
import versola.oauth.core.BrowserOutcome
import versola.oauth.core.VersolaError

/**
 * The hand-off from [VersolaRedirectActivity] and [VersolaAuthTabActivity] — which the OS
 * starts, with no reference to whatever coroutine is waiting — to the suspending call that
 * launched the browser.
 *
 * Process-wide, because that is the only scope both ends share. A buffered channel rather
 * than a `SharedFlow` with replay: a redirect delivered to a cold-started process arrives
 * before anything is collecting, and must wait for the receiver rather than being dropped or
 * replayed into a later, unrelated session.
 */
internal object RedirectDispatcher {

    /** An outcome, or the error the browser leg ended in ([fail]), thrown to the waiter. */
    private val outcomes = Channel<Result<BrowserOutcome>>(capacity = Channel.BUFFERED)

    /**
     * Set by the redirect activity before it resumes, and read by [ForegroundReturnDetector]
     * so that the app returning to the foreground *because of* a redirect is not mistaken for
     * the user dismissing the browser.
     */
    @Volatile
    var redirectDelivered: Boolean = false
        private set

    fun deliver(uri: String) {
        redirectDelivered = true
        outcomes.trySend(Result.success(BrowserOutcome.Redirect(uri)))
    }

    fun deliverUserCancelled() {
        outcomes.trySend(Result.success(BrowserOutcome.UserCancelled))
    }

    /**
     * The browser leg failed in a way that is neither a redirect nor a dismissal: an Auth Tab
     * that could not verify the redirect host. Surfaced to the waiter as the error itself, so
     * the flow wipes the pending request the way it does for `NoBrowserAvailable`.
     */
    fun fail(error: VersolaError) {
        outcomes.trySend(Result.failure(error))
    }

    suspend fun await(): BrowserOutcome = outcomes.receive().getOrThrow()

    /**
     * Drops anything left over from an abandoned session. A buffered redirect nobody
     * collected must not be handed to the next `login()`, whose `state` it cannot match —
     * that would turn a stale tab into a `Configuration` failure on an unrelated flow.
     */
    fun drain() {
        redirectDelivered = false
        while (outcomes.tryReceive().isSuccess) {
            // discard
        }
    }
}
