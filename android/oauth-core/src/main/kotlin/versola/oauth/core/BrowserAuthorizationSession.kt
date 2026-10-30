package versola.oauth.core

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
 * What one browser leg may ask of the session beyond the URI it opens
 * (`spec/oauth-sdk-api.md` section 6, `ephemeralBrowser`; section 13). Still URIs and flags
 * only: nothing here lets an implementation see a page, a cookie or a credential.
 */
public class BrowserSessionOptions(
    /**
     * Open the browser without the user's shared browsing state: no cookies in, none kept.
     * Off by default because an ephemeral session breaks passkeys and single sign-on; a
     * browser that cannot honour it says so once and proceeds shared (best effort, as iOS's
     * `prefersEphemeralWebBrowserSession`).
     */
    public val ephemeral: Boolean = false,
    /**
     * The URI the provider will redirect to, when the session can intercept it itself (Auth
     * Tab does, from its result; a Custom Tab relies on the redirect activity instead). Null
     * when there is none to expect, as for an end-session request without a post-logout URI.
     */
    public val redirectUri: String? = null,
) {
    /**
     * The `state` of the authorization request this leg waits for the response to, or null when
     * the leg is not one (an end-session request) or the caller did not say. A session that can
     * tell a redirect for another request apart before it disturbs the app (the redirect
     * activity, which any app can start) uses it to drop one; the decision stays the flow's,
     * which compares every redirect it is handed with the persisted request, so a session that
     * ignores this loses nothing but that early answer. Wiring between the flow and the browser
     * module, not API: set by [AuthorizationFlow], read by the sessions.
     */
    @VersolaInternalApi
    public var expectedState: String? = null

    public companion object {
        public val Default: BrowserSessionOptions = BrowserSessionOptions()
    }
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
     * [authorize] with [options]. The default ignores them, so an implementation that cannot
     * act on them (a driver's HTTP login conversation) needs no change; the system browser
     * sessions override it. The flow always calls this form.
     */
    public suspend fun authorize(uri: String, options: BrowserSessionOptions): BrowserOutcome = authorize(uri)

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
