package versola.sdk.browser

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.result.ActivityResultLauncher
import androidx.browser.auth.AuthTabIntent
import versola.oauth.core.VersolaError

/**
 * Launches an Auth Tab and hands its result to [RedirectDispatcher].
 *
 * An Auth Tab answers through the activity-result API, which needs a `ComponentActivity` that
 * registered its launcher before being started: the SDK is given an application context and
 * must not reach into the integrator's activities, so this one exists. It is transparent, sits
 * under the tab for as long as the tab lives, and finishes the moment the result is in. On a
 * process death while the tab is open the system restores it with the tab's result, and the
 * result is delivered to the dispatcher's buffer; finishing the authorization from there on a
 * cold start (scenario 12) is the facade's `awaitPendingRedirect()` call, which `OAuthClient`
 * starts when it is created (`spec/oauth-sdk-api.md` section 4).
 *
 * Nothing credential-shaped passes through here: the extras are the authorization URI and the
 * redirect URI to intercept, both of which the browser sees anyway.
 */
internal class VersolaAuthTabActivity : ComponentActivity() {

    private lateinit var launcher: ActivityResultLauncher<Intent>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Registered unconditionally, and first: the registry keys launchers by registration
        // order, so a recreated activity must register the same one before any result arrives.
        launcher = AuthTabIntent.registerActivityResultLauncher(this) { result ->
            deliver(result.resultCode, result.resultUri)
            finish()
        }
        if (savedInstanceState != null) return

        val uri = Uri.parse(intent.getStringExtra(EXTRA_URI) ?: run { finish(); return })
        val redirect = Uri.parse(intent.getStringExtra(EXTRA_REDIRECT_URI) ?: run { finish(); return })
        val authTab = AuthTabIntent.Builder()
            .setEphemeralBrowsingEnabled(intent.getBooleanExtra(EXTRA_EPHEMERAL, false))
            .build()
        // The provider the session chose, so the launch cannot land in a browser without
        // Auth Tab support and fall back to a plain tab that never answers.
        intent.getStringExtra(EXTRA_PROVIDER)?.let { authTab.intent.setPackage(it) }
        try {
            if (redirect.scheme.equals("https", ignoreCase = true)) {
                authTab.launch(launcher, uri, redirect.host.orEmpty(), redirect.path.orEmpty())
            } else {
                authTab.launch(launcher, uri, redirect.scheme.orEmpty())
            }
        } catch (e: ActivityNotFoundException) {
            // The provider went away between the session's check and this launch, or answers
            // the Auth Tab query without a BROWSABLE handler. An SDK activity must not take the
            // host app down; the waiter gets the same answer a missing browser gives.
            noBrowser(e)
        } catch (e: SecurityException) {
            noBrowser(e)
        }
    }

    private fun noBrowser(cause: Exception) {
        RedirectDispatcher.fail(VersolaError.Configuration(VersolaError.Configuration.Detail.NoBrowserAvailable, cause))
        finish()
    }

    private fun deliver(resultCode: Int, resultUri: Uri?) {
        when (resultCode) {
            AuthTabIntent.RESULT_OK -> {
                when {
                    resultUri == null -> RedirectDispatcher.deliverUserCancelled()
                    // The tab has closed with a redirect that is not this request's response: another
                    // request's, or none of the awaited one. Nothing more comes from it, and the wait
                    // ends as a visible failure (`Configuration(StateMismatch)`), not as a cancel.
                    !RedirectDispatcher.answers(resultUri.toString()) -> RedirectDispatcher.failUnansweredTabEnded()
                    else -> RedirectDispatcher.deliver(resultUri.toString())
                }
            }
            AuthTabIntent.RESULT_CANCELED -> RedirectDispatcher.deliverUserCancelled()
            // The browser could not verify that the redirect's https host belongs to this app
            // (Digital Asset Links), or gave up trying. A deployment mistake, not something the
            // user can fix by trying again: Configuration, and the pending request goes.
            AuthTabIntent.RESULT_VERIFICATION_FAILED, AuthTabIntent.RESULT_VERIFICATION_TIMED_OUT -> RedirectDispatcher.fail(
                VersolaError.Configuration(
                    VersolaError.Configuration.Detail.InvalidConfiguration(
                        "the redirect URI's host is not a verified App Link for this app (Auth Tab result $resultCode)",
                    ),
                ),
            )
            // A result this version of the browser library does not know: the tab is gone and
            // nothing arrived. Reported as a system cancel, but the pending request is wiped
            // (the flow treats a failed browser leg that way), since no redirect can follow;
            // `spec/state-machine.md`'s cancel table says so for this cause.
            else -> RedirectDispatcher.fail(VersolaError.Recoverable(VersolaError.Recoverable.Cause.SystemCancelled))
        }
    }

    internal companion object {
        const val EXTRA_URI = "versola.sdk.browser.extra.URI"
        const val EXTRA_REDIRECT_URI = "versola.sdk.browser.extra.REDIRECT_URI"
        const val EXTRA_EPHEMERAL = "versola.sdk.browser.extra.EPHEMERAL"
        const val EXTRA_PROVIDER = "versola.sdk.browser.extra.PROVIDER"

        fun intent(context: Context, uri: String, redirectUri: String, ephemeral: Boolean, provider: String): Intent =
            Intent(context, VersolaAuthTabActivity::class.java)
                .putExtra(EXTRA_URI, uri)
                .putExtra(EXTRA_REDIRECT_URI, redirectUri)
                .putExtra(EXTRA_EPHEMERAL, ephemeral)
                .putExtra(EXTRA_PROVIDER, provider)
                // Launched from the application context, so it needs its own task entry; it
                // joins the app's task by affinity.
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
}
