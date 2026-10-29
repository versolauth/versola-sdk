package versola.sdk.browser

import android.app.Application
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ActivityInfo
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.ResolveInfo
import android.content.pm.ServiceInfo
import android.net.Uri
import androidx.browser.auth.AuthTabIntent
import androidx.browser.customtabs.CustomTabsIntent
import androidx.browser.customtabs.CustomTabsService
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import versola.oauth.core.BrowserOutcome
import versola.oauth.core.BrowserSessionOptions
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaLogger

private const val AUTHORIZE = "https://id.example.com/authorize?response_type=code&state=s"
private const val REDIRECT = "https://app.example.com/oauth"
private const val BROWSER = "com.example.browser"

private class RecordingLogger : VersolaLogger {
    val warnings = mutableListOf<String>()
    val infos = mutableListOf<String>()
    override fun info(message: String) {
        infos += message
    }
    override fun warn(message: String) {
        warnings += message
    }
}

@RunWith(RobolectricTestRunner::class)
class AuthTabAuthorizationSessionTest {

    private val application = ApplicationProvider.getApplicationContext<Application>()
    private val logger = RecordingLogger()

    @Before
    fun drainPreviousSessions() {
        RedirectDispatcher.drain()
    }

    /**
     * A Custom Tabs provider as `CustomTabsClient` finds one: resolves `ACTION_VIEW http://`,
     * and exports the Custom Tabs service, with the Auth Tab and ephemeral categories when asked.
     */
    private fun installProvider(authTab: Boolean, ephemeral: Boolean = false) {
        val packageManager = shadowOf(application.packageManager)
        packageManager.installPackage(
            PackageInfo().apply {
                packageName = BROWSER
                applicationInfo = ApplicationInfo().apply { packageName = BROWSER }
            },
        )
        val activity = ResolveInfo().apply {
            activityInfo = ActivityInfo().apply {
                packageName = BROWSER
                name = "$BROWSER.BrowserActivity"
            }
        }
        packageManager.addResolveInfoForIntent(Intent(Intent.ACTION_VIEW, Uri.parse("http://")), activity)
        packageManager.addResolveInfoForIntent(Intent(Intent.ACTION_VIEW, Uri.parse(AUTHORIZE)).addCategory(Intent.CATEGORY_BROWSABLE), activity)
        val service = ResolveInfo().apply {
            serviceInfo = ServiceInfo().apply {
                packageName = BROWSER
                name = "$BROWSER.CustomTabsService"
            }
            filter = IntentFilter(CustomTabsService.ACTION_CUSTOM_TABS_CONNECTION).apply {
                if (authTab) addCategory("androidx.browser.auth.category.AuthTab")
                if (ephemeral) addCategory(CustomTabsService.CATEGORY_EPHEMERAL_BROWSING)
            }
        }
        packageManager.addResolveInfoForIntent(Intent(CustomTabsService.ACTION_CUSTOM_TABS_CONNECTION), service)
        packageManager.addResolveInfoForIntent(Intent(CustomTabsService.ACTION_CUSTOM_TABS_CONNECTION).setPackage(BROWSER), service)
    }

    private fun options(ephemeral: Boolean = false, redirect: String? = REDIRECT) =
        BrowserSessionOptions(ephemeral = ephemeral, redirectUri = redirect)

    @Test
    fun `a provider with Auth Tab support gets the trampoline, not a Custom Tab`() = runTest {
        installProvider(authTab = true)
        val session = AuthTabAuthorizationSession(application, logger)

        val pending = async { session.authorize(AUTHORIZE, options()) }
        runCurrent()
        RedirectDispatcher.deliver("$REDIRECT?code=c&state=s")
        val outcome = pending.await()

        val launched = shadowOf(application).nextStartedActivity
        assertEquals(VersolaAuthTabActivity::class.java.name, launched.component?.className)
        assertEquals(AUTHORIZE, launched.getStringExtra(VersolaAuthTabActivity.EXTRA_URI))
        assertEquals(REDIRECT, launched.getStringExtra(VersolaAuthTabActivity.EXTRA_REDIRECT_URI))
        assertEquals(BROWSER, launched.getStringExtra(VersolaAuthTabActivity.EXTRA_PROVIDER))
        assertFalse(launched.getBooleanExtra(VersolaAuthTabActivity.EXTRA_EPHEMERAL, true))
        assertTrue(launched.flags and Intent.FLAG_ACTIVITY_NEW_TASK != 0)
        assertTrue(outcome is BrowserOutcome.Redirect)
        assertTrue(logger.warnings.isEmpty())
    }

    @Test
    fun `a provider without Auth Tab support falls back to a Custom Tab with the same options`() = runTest {
        installProvider(authTab = false, ephemeral = true)
        val session = AuthTabAuthorizationSession(application, logger)

        val pending = async { session.authorize(AUTHORIZE, options(ephemeral = true)) }
        runCurrent()
        RedirectDispatcher.deliver("$REDIRECT?code=c&state=s")
        pending.await()

        val launched = shadowOf(application).nextStartedActivity
        assertNull(launched.component)
        assertEquals(BROWSER, launched.`package`)
        assertEquals(AUTHORIZE, launched.data.toString())
        // The ephemeral request reached the Custom Tab, since this provider supports it there.
        assertTrue(launched.getBooleanExtra(CustomTabsIntent.EXTRA_ENABLE_EPHEMERAL_BROWSING, false))
        assertTrue(logger.infos.any { it.contains("no Auth Tab support") })
        assertTrue(logger.warnings.isEmpty())
    }

    @Test
    fun `without a redirect URI to intercept the fallback is used`() = runTest {
        installProvider(authTab = true)
        val session = AuthTabAuthorizationSession(application, logger)

        val pending = async { session.authorize("https://id.example.com/logout?id_token_hint=x", options(redirect = null)) }
        runCurrent()
        RedirectDispatcher.deliverUserCancelled()
        pending.await()

        assertNull(shadowOf(application).nextStartedActivity.component)
    }

    @Test
    fun `ephemeral asked of a provider that cannot honour it is logged once and still opens`() = runTest {
        installProvider(authTab = true, ephemeral = false)
        val session = AuthTabAuthorizationSession(application, logger)

        repeat(2) {
            val pending = async { session.authorize(AUTHORIZE, options(ephemeral = true)) }
            runCurrent()
            RedirectDispatcher.deliver("$REDIRECT?code=c&state=s")
            pending.await()
        }

        assertEquals(1, logger.warnings.count { it.contains("ephemeral") })
        assertTrue(shadowOf(application).nextStartedActivity.getBooleanExtra(VersolaAuthTabActivity.EXTRA_EPHEMERAL, false))
    }

    @Test
    fun `ephemeral is passed to a provider that supports it without a warning`() = runTest {
        installProvider(authTab = true, ephemeral = true)
        val session = AuthTabAuthorizationSession(application, logger)

        val pending = async { session.authorize(AUTHORIZE, options(ephemeral = true)) }
        runCurrent()
        RedirectDispatcher.deliver("$REDIRECT?code=c&state=s")
        pending.await()

        assertTrue(logger.warnings.isEmpty())
    }

    @Test
    fun `a Custom Tab asked for ephemeral by a provider without it is logged and opens shared`() = runTest {
        installProvider(authTab = false, ephemeral = false)
        val session = CustomTabsAuthorizationSession(application, logger)

        val pending = async { session.authorize(AUTHORIZE, options(ephemeral = true)) }
        runCurrent()
        RedirectDispatcher.deliver("$REDIRECT?code=c&state=s")
        pending.await()

        val launched = shadowOf(application).nextStartedActivity
        assertFalse(launched.getBooleanExtra(CustomTabsIntent.EXTRA_ENABLE_EPHEMERAL_BROWSING, false))
        assertEquals(1, logger.warnings.count { it.contains("ephemeral") })
    }

    // ---- the trampoline ----

    private fun trampoline(redirect: String = REDIRECT, ephemeral: Boolean = false): ActivityController<VersolaAuthTabActivity> {
        val intent = VersolaAuthTabActivity.intent(application, AUTHORIZE, redirect, ephemeral, BROWSER)
        return ActivityController.of(VersolaAuthTabActivity(), intent).create().start().resume()
    }

    @Test
    fun `the trampoline launches the Auth Tab for result with the https redirect host and path`() {
        val controller = trampoline()

        val launched = shadowOf(controller.get()).nextStartedActivityForResult.intent
        assertEquals(Intent.ACTION_VIEW, launched.action)
        assertEquals(AUTHORIZE, launched.data.toString())
        assertEquals(BROWSER, launched.`package`)
        assertTrue(launched.getBooleanExtra(AuthTabIntent.EXTRA_LAUNCH_AUTH_TAB, false))
        assertEquals("app.example.com", launched.getStringExtra(AuthTabIntent.EXTRA_HTTPS_REDIRECT_HOST))
        assertEquals("/oauth", launched.getStringExtra(AuthTabIntent.EXTRA_HTTPS_REDIRECT_PATH))
        assertFalse(controller.get().isFinishing)
    }

    @Test
    fun `a private-use scheme redirect is intercepted by scheme`() {
        val controller = trampoline(redirect = "com.example.app:/oauth", ephemeral = true)

        val launched = shadowOf(controller.get()).nextStartedActivityForResult.intent
        assertEquals("com.example.app", launched.getStringExtra(AuthTabIntent.EXTRA_REDIRECT_SCHEME))
        assertNull(launched.getStringExtra(AuthTabIntent.EXTRA_HTTPS_REDIRECT_HOST))
        assertTrue(launched.getBooleanExtra(CustomTabsIntent.EXTRA_ENABLE_EPHEMERAL_BROWSING, false))
    }

    @Test
    fun `RESULT_OK delivers the redirect and finishes`() = runTest {
        val controller = trampoline()
        val activity = controller.get()
        val started = shadowOf(activity).nextStartedActivityForResult

        shadowOf(activity).receiveResult(started.intent, AuthTabIntent.RESULT_OK, Intent().setData(Uri.parse("$REDIRECT?code=c&state=s")))

        assertEquals("$REDIRECT?code=c&state=s", (RedirectDispatcher.await() as BrowserOutcome.Redirect).uri)
        assertTrue(activity.isFinishing)
    }

    @Test
    fun `RESULT_CANCELED is the user's dismissal`() = runTest {
        val controller = trampoline()
        val activity = controller.get()
        val started = shadowOf(activity).nextStartedActivityForResult

        shadowOf(activity).receiveResult(started.intent, AuthTabIntent.RESULT_CANCELED, null)

        assertEquals(BrowserOutcome.UserCancelled, RedirectDispatcher.await())
        assertTrue(activity.isFinishing)
    }

    @Test
    fun `a redirect host the browser could not verify is a Configuration failure`() = runTest {
        val controller = trampoline()
        val activity = controller.get()
        val started = shadowOf(activity).nextStartedActivityForResult

        shadowOf(activity).receiveResult(started.intent, AuthTabIntent.RESULT_VERIFICATION_FAILED, null)

        val error = runCatching { RedirectDispatcher.await() }.exceptionOrNull() as VersolaError.Configuration
        assertTrue(error.detail is VersolaError.Configuration.Detail.InvalidConfiguration)
        assertTrue(activity.isFinishing)
    }

    @Test
    fun `an unknown result code is a system cancel`() = runTest {
        val controller = trampoline()
        val activity = controller.get()
        val started = shadowOf(activity).nextStartedActivityForResult

        shadowOf(activity).receiveResult(started.intent, AuthTabIntent.RESULT_UNKNOWN_CODE, null)

        val error = runCatching { RedirectDispatcher.await() }.exceptionOrNull() as VersolaError.Recoverable
        assertEquals(VersolaError.Recoverable.Cause.SystemCancelled, error.reason)
    }

    @Test
    fun `a recreated trampoline registers its launcher and launches nothing twice`() {
        val controller = trampoline()
        val activity = controller.get()
        shadowOf(activity).nextStartedActivityForResult

        val recreated = controller.recreate()

        assertNull(shadowOf(recreated.get()).nextStartedActivityForResult)
    }
}
