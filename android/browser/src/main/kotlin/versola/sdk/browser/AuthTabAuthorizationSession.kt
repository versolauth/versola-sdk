package versola.sdk.browser

import android.app.Application
import android.content.Context
import androidx.browser.customtabs.CustomTabsClient
import versola.oauth.core.BrowserAuthorizationSession
import versola.oauth.core.BrowserOutcome
import versola.oauth.core.BrowserSessionOptions
import versola.oauth.core.VersolaInternalApi
import versola.oauth.core.VersolaLogger

/**
 * The system browser leg: an Auth Tab (androidx.browser 1.9+, Chrome 132+) where the device's
 * Custom Tabs provider supports it, [fallback] (Custom Tabs, then any browser) where it does
 * not. The default browser leg of both facades.
 *
 * An Auth Tab is a Custom Tab that returns the redirect as an activity result: the redirect
 * is delivered to the app that opened the tab and to nothing else, the tab closes itself, and
 * a dismissal is a result code rather than an inference. That last point is architecture
 * review F1: a Custom Tab gives no dismissal signal, and the host app resuming (what the
 * fallback reads as a cancel) is also what Chrome's minimize button does while the tab lives.
 *
 * `ephemeral` ([BrowserSessionOptions]) is passed to the tab when the provider supports it and
 * logged once otherwise; the session then opens shared. An https redirect URI must be a
 * verified App Link of this app, or the tab answers with a verification failure that surfaces
 * as `Configuration(InvalidConfiguration)`. Without a redirect URI to intercept (an
 * end-session request with no post-logout URI) the fallback is used, since an Auth Tab has
 * nothing to return.
 */
@OptIn(VersolaInternalApi::class)
public class AuthTabAuthorizationSession(
    context: Context,
    private val logger: VersolaLogger? = null,
    private val fallback: BrowserAuthorizationSession = CustomTabsAuthorizationSession(context, logger),
) : BrowserAuthorizationSession {

    private val application: Application = context.applicationContext as Application

    @Volatile
    private var warnedEphemeral = false

    override suspend fun authorize(uri: String): BrowserOutcome = authorize(uri, BrowserSessionOptions.Default)

    override suspend fun authorize(uri: String, options: BrowserSessionOptions): BrowserOutcome {
        val redirectUri = options.redirectUri
        val provider = CustomTabsClient.getPackageName(application, null)
        if (redirectUri == null || provider == null || !CustomTabsClient.isAuthTabSupported(application, provider)) {
            if (provider != null && redirectUri != null) {
                logger?.info("Custom Tabs provider $provider has no Auth Tab support; using a Custom Tab")
            }
            return fallback.authorize(uri, options)
        }
        if (options.ephemeral && !warnedEphemeral && !CustomTabsClient.isEphemeralBrowsingSupported(application, provider)) {
            warnedEphemeral = true
            logger?.warn("ephemeralBrowser was asked for but $provider does not support ephemeral browsing; the session opens shared")
        }
        // Anything buffered belongs to a session that no longer exists.
        RedirectDispatcher.drain()
        RedirectDispatcher.expect(options.redirectUri, options.expectedState, logger)
        application.startActivity(VersolaAuthTabActivity.intent(application, uri, redirectUri, options.ephemeral, provider))
        return RedirectDispatcher.await()
    }

    override suspend fun awaitPendingRedirect(): BrowserOutcome = RedirectDispatcher.await()
}
