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
 * It holds no state of its own. Everything needed to finish the flow was persisted before the
 * browser opened, so a redirect arriving at a cold-started process completes exactly as one
 * arriving at a live process does.
 */
public class VersolaRedirectActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        intent?.data?.let { RedirectDispatcher.deliver(it.toString()) }

        // The Custom Tab is still on top of its own task. Bringing the app's task forward
        // with CLEAR_TOP dismisses it and lands the user back where they started — and on a
        // cold start, starts the app, which is what makes the killed-mid-browser case
        // (scenario 12) look ordinary to the user.
        packageManager.getLaunchIntentForPackage(packageName)?.let { launch ->
            launch.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            startActivity(launch)
        }
        finish()
    }
}
