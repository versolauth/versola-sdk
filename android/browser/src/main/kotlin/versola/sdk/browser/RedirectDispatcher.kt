package versola.sdk.browser

import android.net.Uri
import kotlinx.coroutines.channels.Channel
import versola.oauth.core.BrowserOutcome
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaLogger
import java.security.MessageDigest

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

    /**
     * The `state` of the request the leg in progress waits for the response to, set with
     * [expected]; read by [answers]. Null when the leg is not an authorization request (an
     * end-session leg) or nothing said: a cold-started process, where the stored request is read
     * later and the flow compares then.
     */
    @Volatile
    private var expectedState: String? = null

    /** Where an ignored redirect is noted, without its URL; the leg's session sets it. */
    @Volatile
    private var logger: VersolaLogger? = null

    /** The redirect, and the `state`, the browser leg about to open will deliver; see [accepts]. */
    fun expect(redirectUri: String?, state: String? = null, logger: VersolaLogger? = null) {
        expected = redirectUri
        expectedState = state
        this.logger = logger
    }

    /**
     * Whether an intent that reached the exported [VersolaRedirectActivity] is the response the
     * login waits for. Any app can start that activity with an explicit intent, which skips the
     * intent filter the OS applies to a browser's, and the redirect URI is public besides, so
     * without this a URI like `<redirect-uri>?state=junk&code=x` would be taken for the response
     * (scenario 15): handed to the flow, bringing the app over the open tab and, through
     * [redirectDelivered], silencing the cancel detector for a dismissal that follows.
     *
     * Scheme, host, port and path must be the configured redirect's, and `state` the awaited
     * request's: not the query's other parameters, which are the response itself and are the
     * flow's to validate. A redirect that fails either is ignored, and the login it was fired at
     * goes on waiting: nothing is delivered, the detector is not touched and the tab stays in
     * front. With nothing expected the intent is accepted and the flow, which reads the persisted
     * request, does the judging.
     *
     * The `state` is compared here only to drop what is plainly not the response, in constant
     * time like everywhere else; the flow compares again, and is what decides.
     */
    fun accepts(uri: String): Boolean {
        val accepted = expected.let { it == null || sameRedirect(it, uri) } && answers(uri)
        if (!accepted) logger?.warn("ignored an intent at the redirect activity that is not the response to the login in progress")
        return accepted
    }

    /**
     * Whether [uri] carries the `state` of the request the leg awaits (true when none is
     * known). Absent is not the awaited one.
     */
    fun answers(uri: String): Boolean {
        val awaited = expectedState ?: return true
        val received = try {
            Uri.parse(uri).getQueryParameter("state")
        } catch (e: Exception) {
            null
        } ?: return false
        return MessageDigest.isEqual(awaited.toByteArray(Charsets.UTF_8), received.toByteArray(Charsets.UTF_8))
    }

    /**
     * An Auth Tab ended with a redirect that is not the awaited response (see [answers]): the
     * tab closed itself with it, so nothing can follow from that tab and no dismissal can be
     * observed any more. The wait ends as the user closing it would end it
     * (`spec/state-machine.md`, "A redirect that is not the awaited response").
     */
    fun deliverUnansweredTabEnded() {
        logger?.warn("an Auth Tab ended with a redirect that is not the response to the login in progress; the login is over")
        deliverUserCancelled()
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
        expectedState = null
        logger = null
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
