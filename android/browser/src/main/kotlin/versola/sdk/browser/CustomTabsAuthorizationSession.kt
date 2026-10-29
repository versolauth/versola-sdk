package versola.sdk.browser

import android.app.Application
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.browser.customtabs.CustomTabsClient
import androidx.browser.customtabs.CustomTabsIntent
import versola.oauth.core.BrowserAuthorizationSession
import versola.oauth.core.BrowserOutcome
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaLogger

/**
 * Chrome Custom Tabs, falling back to whatever browser the device has.
 *
 * A Custom Tab is a System WebView in the top-level site's context, so passkeys and
 * federation work and the browser's own credentials are available — which is why
 * `prefersEphemeralWebBrowserSession`'s Android equivalent is not offered either. The type
 * system carries the rest of the rule: nothing here takes a `WebView`, and
 * [BrowserAuthorizationSession] gives no way to introduce one.
 */
public class CustomTabsAuthorizationSession(
    context: Context,
    private val logger: VersolaLogger? = null,
) : BrowserAuthorizationSession {

    private val application: Application = context.applicationContext as Application

    override suspend fun authorize(uri: String): BrowserOutcome {
        // Anything buffered belongs to a session that no longer exists.
        RedirectDispatcher.drain()

        // Armed before the browser starts, not after: `startActivity` is asynchronous, so
        // arming afterwards can miss the host activity stopping — and a detector that never
        // saw the app leave the foreground will never report it coming back, leaving this
        // call suspended on a redirect the user already gave up on.
        val detector = ForegroundReturnDetector(application) { RedirectDispatcher.deliverUserCancelled() }
        detector.arm()
        return try {
            launch(uri)
            RedirectDispatcher.await()
        } finally {
            detector.disarm()
        }
    }

    override suspend fun awaitPendingRedirect(): BrowserOutcome = RedirectDispatcher.await()

    /**
     * The fallback chain: the best Custom Tabs provider the device has, then any browser via
     * `ACTION_VIEW`, then failure. The middle step is the one that matters on a device with
     * no Custom Tabs provider at all — the flow still completes in a plain browser tab.
     */
    private fun launch(uri: String) {
        val target = Uri.parse(uri)
        val provider = CustomTabsClient.getPackageName(application, null)

        if (provider != null) {
            val customTabs = CustomTabsIntent.Builder().setShowTitle(true).build()
            customTabs.intent.setPackage(provider)
            // Launched from the application context, so it needs its own task.
            customTabs.intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            try {
                customTabs.launchUrl(application, target)
                return
            } catch (e: ActivityNotFoundException) {
                logger?.warn("Custom Tabs provider $provider could not be started: ${e.message}")
            }
        } else {
            logger?.warn(
                "No Custom Tabs provider on this device; falling back to the default browser. " +
                    "The flow is unchanged, but the browser opens as a separate app rather than in-app.",
            )
        }

        val view = Intent(Intent.ACTION_VIEW, target).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        try {
            application.startActivity(view)
        } catch (e: ActivityNotFoundException) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.NoBrowserAvailable,
                e,
            )
        }
    }
}
