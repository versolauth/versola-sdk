package versola.sdk.browser

import android.net.Uri
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

    /**
     * The redirect the browser leg in progress waits for, set by the session before it opens
     * the browser and read by [accepts]. Null when no leg has said what to expect: a process
     * the redirect itself started, or a leg with no redirect URI. Process-wide like the
     * channel, and forgotten with it by [drain].
     */
    @Volatile
    private var expected: String? = null

    /** The redirect the browser leg about to open will deliver; see [accepts]. */
    fun expect(redirectUri: String?) {
        expected = redirectUri
    }

    /**
     * Whether an intent that reached the exported [VersolaRedirectActivity] is the redirect
     * the login waits for. Any app can start that activity with an explicit intent, which
     * skips the intent filter the OS applies to a browser's, so without this a URI like
     * `anything://x?state=junk` would be taken for the response: it fails the login as a
     * state mismatch, wipes the pending request, and (through [redirectDelivered]) silences
     * the cancel detector.
     *
     * Scheme, host, port and path must be the configured redirect's; the query is the
     * response itself and is not compared. A response that matches and carries the wrong
     * `state` is still delivered: that is the state mismatch the spec requires to fail.
     * With nothing expected the intent is accepted, as before, and the persisted request
     * does the validating.
     */
    fun accepts(uri: String): Boolean {
        val redirect = expected ?: return true
        return sameRedirect(redirect, uri)
    }

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
        expected = null
        while (outcomes.tryReceive().isSuccess) {
            // discard
        }
    }
}

/**
 * Whether [actual] is [expected] as a redirect: scheme and host without case, the port with a
 * scheme's default folded away, the path exactly as written (percent-encoding is not decoded:
 * `%2F` is not a `/`, as when iOS compares the raw path). A private-use scheme with no host compares
 * on scheme and path alone. A URI that dresses another host up with userinfo
 * (`https://app.example.com@evil.example.org/`) is compared on the host the OS would route to.
 */
internal fun sameRedirect(expected: String, actual: String): Boolean {
    val a = Uri.parse(expected)
    val b = Uri.parse(actual)
    return a.scheme.equals(b.scheme, ignoreCase = true) &&
        a.host.equals(b.host, ignoreCase = true) &&
        effectivePort(a) == effectivePort(b) &&
        a.encodedPath.orEmpty() == b.encodedPath.orEmpty()
}

private fun effectivePort(uri: Uri): Int = when {
    uri.port != -1 -> uri.port
    uri.scheme.equals("https", ignoreCase = true) -> 443
    uri.scheme.equals("http", ignoreCase = true) -> 80
    else -> -1
}
