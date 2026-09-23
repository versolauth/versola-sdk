package kz.versola.sdk.core

/** How the browser leg ended. */
public sealed interface BrowserOutcome {

    /** The redirect URI was delivered back to the app. Not yet validated. */
    public data class Redirect(public val uri: String) : BrowserOutcome

    /**
     * The user dismissed the browser and the app came back to the foreground with no
     * redirect. The pending request is wiped on this; it is never retried automatically.
     *
     * A *system* cancel — the process torn down while backgrounded — is not reported here at
     * all: there is no live caller to report it to. It is recognised on the next cold start,
     * as a pending request with nothing in flight, and the request is kept so the flow can
     * resume. That asymmetry is the whole difference between the two on Android.
     */
    public data object UserCancelled : BrowserOutcome
}

/**
 * The system browser leg of the authorization flow.
 *
 * The interface takes and returns URIs and nothing else. No implementation may accept a
 * `WebView`, and none can be written against this interface that does: an embedded WebView
 * silently downgrades passkeys and breaks federation, and RFC 8252 forbids it (#1 §4).
 */
public interface BrowserAuthorizationSession {

    /**
     * Opens [uri] in the system browser and suspends until a redirect is delivered or the
     * user dismisses it.
     *
     * @throws VersolaError.Configuration with [VersolaError.Configuration.Detail.NoBrowserAvailable]
     *   when the device has no browser at all.
     */
    public suspend fun authorize(uri: String): BrowserOutcome

    /**
     * Suspends for a redirect belonging to an authorization this process did not start — the
     * browser was opened before the app was killed, and the response is still coming.
     *
     * Opens nothing, and reports no user cancel: there is no dismissal to observe from a
     * process that was not running when the browser was opened.
     */
    public suspend fun awaitPendingRedirect(): BrowserOutcome
}

/**
 * Where the SDK's warnings go. An interface rather than a direct `android.util.Log` call so
 * the warnings are assertable in a unit test, and so an integrator can route them into
 * whatever they already use.
 */
public interface VersolaLogger {
    public fun info(message: String)
    public fun warn(message: String)
}
