package kz.versola.sdk.browser

import android.content.Intent
import android.content.pm.ActivityInfo
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.ResolveInfo
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.async
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kz.versola.sdk.core.BrowserOutcome
import kz.versola.sdk.core.VersolaError
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController

private const val AUTHORIZE = "https://id.versola.kz/authorize?response_type=code&state=s"

@RunWith(RobolectricTestRunner::class)
class CustomTabsAuthorizationSessionTest {

    private val application = ApplicationProvider.getApplicationContext<android.app.Application>()

    @Before
    fun drainPreviousSessions() {
        RedirectDispatcher.drain()
    }

    private fun installBrowser(packageName: String) {
        val packageManager = shadowOf(application.packageManager)
        val packageInfo = PackageInfo().apply {
            this.packageName = packageName
            applicationInfo = ApplicationInfo().apply { this.packageName = packageName }
        }
        packageManager.installPackage(packageInfo)

        val resolveInfo = ResolveInfo().apply {
            activityInfo = ActivityInfo().apply {
                this.packageName = packageName
                name = "$packageName.BrowserActivity"
            }
        }
        val browsable = Intent(Intent.ACTION_VIEW, Uri.parse("https://id.versola.kz/authorize"))
            .addCategory(Intent.CATEGORY_BROWSABLE)
        packageManager.addResolveInfoForIntent(browsable, resolveInfo)
    }

    @Test
    fun `with no browser at all the failure is Configuration, not a crash`() = runTest {
        // #5 asks for a manual check on a device with no Custom Tabs provider. This is the
        // harsher case — no browser of any kind — and it must name the cause rather than
        // surfacing an ActivityNotFoundException from somewhere inside the SDK.
        // Robolectric records a startActivity that resolves to nothing instead of throwing,
        // unless asked to behave like the device does.
        shadowOf(application).checkActivities(true)
        val session = CustomTabsAuthorizationSession(application)

        val error = runCatching { session.authorize(AUTHORIZE) }.exceptionOrNull()

        assertTrue(error is VersolaError.Configuration)
        assertEquals(
            VersolaError.Configuration.Detail.NoBrowserAvailable,
            (error as VersolaError.Configuration).detail,
        )
    }

    @Test
    fun `with no Custom Tabs provider the flow falls back to a plain browser`() = runTest {
        installBrowser("com.example.browser")
        val session = CustomTabsAuthorizationSession(application)

        val pending = async { session.authorize(AUTHORIZE) }
        // Let the call get as far as suspending on the redirect: it drains stale responses
        // on the way in, so delivering before it starts would deliver into the drain.
        runCurrent()
        RedirectDispatcher.deliver("https://app.example.com/oauth?code=c&state=s")
        val outcome = pending.await()

        val launched = shadowOf(application).nextStartedActivity
        assertNotNull(launched)
        assertEquals(Intent.ACTION_VIEW, launched.action)
        assertEquals(AUTHORIZE, launched.data.toString())
        assertTrue(outcome is BrowserOutcome.Redirect)
    }

    @Test
    fun `the launch carries NEW_TASK, since it comes from the application context`() = runTest {
        installBrowser("com.example.browser")
        val session = CustomTabsAuthorizationSession(application)

        val pending = async { session.authorize(AUTHORIZE) }
        runCurrent()
        RedirectDispatcher.deliver("https://app.example.com/oauth?code=c&state=s")
        pending.await()

        val launched = shadowOf(application).nextStartedActivity
        assertTrue(launched.flags and Intent.FLAG_ACTIVITY_NEW_TASK != 0)
    }

    @Test
    fun `the redirect activity hands the response over and closes itself`() {
        val intent = Intent(
            Intent.ACTION_VIEW,
            Uri.parse("https://app.example.com/oauth?code=the-code&state=s"),
        )

        val controller = ActivityController.of(VersolaRedirectActivity(), intent).create()

        assertTrue(controller.get().isFinishing)
        assertTrue(RedirectDispatcher.redirectDelivered)
    }

    @Test
    fun `a redirect delivered before anyone is waiting is not lost`() = runTest {
        // The cold-start case: the OS starts the redirect activity, and whatever will consume
        // the response has not been constructed yet.
        RedirectDispatcher.deliver("https://app.example.com/oauth?code=c&state=s")
        val session = CustomTabsAuthorizationSession(application)

        val outcome = session.awaitPendingRedirect()

        assertEquals(
            "https://app.example.com/oauth?code=c&state=s",
            (outcome as BrowserOutcome.Redirect).uri,
        )
    }

    @Test
    fun `a redirect left over from an abandoned session is not handed to the next one`() = runTest {
        installBrowser("com.example.browser")
        RedirectDispatcher.deliver("https://app.example.com/oauth?code=stale&state=old")
        val session = CustomTabsAuthorizationSession(application)

        val pending = async { session.authorize(AUTHORIZE) }
        runCurrent()
        RedirectDispatcher.deliver("https://app.example.com/oauth?code=fresh&state=s")

        assertEquals(
            "https://app.example.com/oauth?code=fresh&state=s",
            (pending.await() as BrowserOutcome.Redirect).uri,
        )
    }
}
