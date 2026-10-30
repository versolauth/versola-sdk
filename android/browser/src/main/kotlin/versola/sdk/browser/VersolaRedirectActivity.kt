package versola.sdk.browser

import android.app.Activity
import android.content.Intent
import android.os.Bundle

/**
 * Receives the authorization response and hands it to whatever is waiting.
 *
 * The integrator re-declares this activity in their own manifest to attach the intent filter
 * for their redirect URI; the manifest merger unions it with the declaration in this library.
 * For a verified App Link:
 *
 * ```xml
 * <activity
 *     android:name="versola.sdk.browser.VersolaRedirectActivity"
 *     android:exported="true"
 *     tools:node="merge">
 *     <intent-filter android:autoVerify="true">
 *         <action android:name="android.intent.action.VIEW" />
 *         <category android:name="android.intent.category.DEFAULT" />
 *         <category android:name="android.intent.category.BROWSABLE" />
 *         <data android:scheme="https" android:host="app.example.com" android:path="/oauth" />
 *     </intent-filter>
 * </activity>
 * ```
 *
 * It holds no state of its own beyond the redirect the login in progress expects. Everything
 * needed to finish the flow was persisted before the browser opened, so a redirect arriving at
 * a cold-started process completes exactly as one arriving at a live process does.
 *
 * Any app can start this activity with an explicit intent, which skips the intent filter above:
 * an intent for a URI other than the redirect the login in progress waits for is ignored
 * (scheme, host, port and path are compared, not the query).
 */
public class VersolaRedirectActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handle(intent)
    }

    // singleTask: a redirect arriving while this instance exists comes here, not to onCreate.
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handle(intent)
    }

    private fun handle(intent: Intent?) {
        val uri = intent?.data?.toString()
        if (uri == null || !RedirectDispatcher.accepts(uri)) {
            // Not a response: see [RedirectDispatcher.accepts]. Nothing is delivered and the app
            // is not brought forward on its account; the login it did not answer carries on.
            finish()
            return
        }
        RedirectDispatcher.deliver(uri)

        // The Custom Tab is still on top of its own task, so the app's task is brought forward
        // to land the user back where they started — and on a cold start that starts the app,
        // which is what makes the killed-mid-browser case (scenario 12) look ordinary to the
        // user. No CLEAR_TOP: it would also finish every screen above the launcher, including
        // the one `login()` was called from, and with it the scope the caller was waiting in.
        packageManager.getLaunchIntentForPackage(packageName)?.let { startActivity(it) }
        finish()
    }
}
