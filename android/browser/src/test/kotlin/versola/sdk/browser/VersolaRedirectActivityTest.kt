package versola.sdk.browser

import android.app.Activity
import android.content.Intent
import android.net.Uri
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.android.controller.ActivityController
import versola.oauth.core.BrowserOutcome
import versola.oauth.core.BrowserSessionOptions

private const val REDIRECT = "https://app.example.com/oauth"
private const val AUTHORIZE = "https://id.example.com/authorize?response_type=code&state=s"

/**
 * The exported redirect activity is reachable by an explicit intent from any app, which skips
 * the intent filter the OS would otherwise apply. What reaches the waiting login is therefore
 * checked against the redirect the login is waiting for (`REVIEW.md`, "Redirect validation").
 */
@RunWith(RobolectricTestRunner::class)
class VersolaRedirectActivityTest {

    private val application = ApplicationProvider.getApplicationContext<android.app.Application>()

    @Before
    fun drainPreviousSessions() {
        RedirectDispatcher.drain()
    }

    /** What the waiter would receive now, or null when nothing has been delivered. */
    private fun takeNow(): BrowserOutcome? = runBlocking { withTimeoutOrNull(50) { RedirectDispatcher.await() } }

    private fun open(uri: String): ActivityController<VersolaRedirectActivity> =
        ActivityController.of(VersolaRedirectActivity(), Intent(Intent.ACTION_VIEW, Uri.parse(uri))).create()

    @Test
    fun `a redirect to the one the login waits for is delivered`() {
        RedirectDispatcher.expect(REDIRECT)

        val controller = open("$REDIRECT?code=c&state=s")

        assertTrue(controller.get().isFinishing)
        assertTrue(RedirectDispatcher.redirectDelivered)
        assertEquals("$REDIRECT?code=c&state=s", (takeNow() as BrowserOutcome.Redirect).uri)
    }

    @Test
    fun `a redirect with no expectation is delivered, as on a cold start`() {
        // The process was started by this very intent: nothing has said what to expect yet,
        // and the persisted request validates the response afterwards.
        open("$REDIRECT?code=c&state=s")

        assertTrue(RedirectDispatcher.redirectDelivered)
    }

    @Test
    fun `an intent for any other URI is ignored and leaves the login alone`() {
        installLauncher()
        RedirectDispatcher.expect(REDIRECT)

        for (junk in listOf(
            "anything://x?state=junk",
            "https://evil.example.org/oauth?code=c&state=junk",
            "https://app.example.com/other?code=c&state=junk",
            "https://app.example.com/oauth/extra?code=c&state=junk",
            "https://app.example.com:8443/oauth?code=c&state=junk",
            "http://app.example.com/oauth?code=c&state=junk",
            "https://app.example.com@evil.example.org/oauth?code=c&state=junk",
        )) {
            val controller = open(junk)

            assertTrue("$junk: the activity still finishes", controller.get().isFinishing)
            assertFalse("$junk: not delivered", RedirectDispatcher.redirectDelivered)
            assertNull("$junk: nothing reaches the waiter", takeNow())
            assertNull("$junk: the app is not brought forward", shadowOf(application).nextStartedActivity)
        }
    }

    @Test
    fun `scheme and host are compared case-insensitively, the query is not compared`() {
        RedirectDispatcher.expect("HTTPS://App.Example.com/oauth")

        open("https://APP.example.COM/oauth?code=c&state=s&iss=https%3A%2F%2Fid.example.com")

        assertTrue(RedirectDispatcher.redirectDelivered)
    }

    @Test
    fun `an explicit default port is the same redirect`() {
        RedirectDispatcher.expect(REDIRECT)

        open("https://app.example.com:443/oauth?code=c&state=s")

        assertTrue(RedirectDispatcher.redirectDelivered)
    }

    @Test
    fun `a private-use scheme without a host is compared on scheme and path`() {
        RedirectDispatcher.expect("com.example.app:/oauth")

        open("com.example.app:/other?state=junk")
        assertFalse(RedirectDispatcher.redirectDelivered)

        open("com.example.app:/oauth?code=c&state=s")
        assertTrue(RedirectDispatcher.redirectDelivered)
    }

    @Test
    fun `a redirect that arrives while the activity exists is handled too`() {
        RedirectDispatcher.expect(REDIRECT)
        val controller = open("anything://x?state=junk")
        assertFalse(RedirectDispatcher.redirectDelivered)

        controller.newIntent(Intent(Intent.ACTION_VIEW, Uri.parse("$REDIRECT?code=c&state=s")))

        assertTrue(RedirectDispatcher.redirectDelivered)
    }

    @Test
    fun `an intent with no data is ignored`() {
        val controller = ActivityController.of(VersolaRedirectActivity(), Intent(Intent.ACTION_VIEW)).create()

        assertTrue(controller.get().isFinishing)
        assertFalse(RedirectDispatcher.redirectDelivered)
    }

    @Test
    fun `a junk intent during a live login neither ends it nor silences the cancel detector`() = runTest {
        val session = CustomTabsAuthorizationSession(application)
        shadowOf(application).checkActivities(false)
        val host = Robolectric.buildActivity(Activity::class.java).setup()
        val login = async { session.authorize(AUTHORIZE, BrowserSessionOptions(redirectUri = REDIRECT)) }
        runCurrent()
        host.pause().stop()

        // Another app fires the exported activity at the open login; the system raises the app.
        open("anything://x?code=c&state=junk")
        host.start().resume()
        runCurrent()
        assertFalse("the raise is not a dismissal: the login is still waiting", login.isCompleted)

        // Later the user leaves for the tab and closes it: the detector is still armed, so
        // that return is a cancel.
        val later = Robolectric.buildActivity(Activity::class.java).setup()
        later.pause().stop()
        later.start().resume()
        runCurrent()
        assertEquals(BrowserOutcome.UserCancelled, login.await())
    }

    @Test
    fun `a junk intent then the real redirect completes the login with the real one`() = runTest {
        val session = CustomTabsAuthorizationSession(application)
        val login = async { session.authorize(AUTHORIZE, BrowserSessionOptions(redirectUri = REDIRECT)) }
        runCurrent()

        open("anything://x?code=c&state=junk")
        open("$REDIRECT?code=c&state=s")

        assertEquals("$REDIRECT?code=c&state=s", (login.await() as BrowserOutcome.Redirect).uri)
    }

    @Test
    fun `a login that was told no redirect delivers whatever arrives, as before`() = runTest {
        // End-session without a post-logout URI: nothing to compare against.
        val session = CustomTabsAuthorizationSession(application)
        val login = async { session.authorize(AUTHORIZE, BrowserSessionOptions(redirectUri = null)) }
        runCurrent()

        open("$REDIRECT?state=s")

        assertTrue(login.await() is BrowserOutcome.Redirect)
    }

    @Test
    fun `a new login forgets the previous one's expectation`() = runTest {
        RedirectDispatcher.expect("https://app.example.com/old")
        RedirectDispatcher.drain()

        open("$REDIRECT?code=c&state=s")

        assertTrue(RedirectDispatcher.redirectDelivered)
    }

    @Test
    fun `the app is brought forward without clearing the screens above its launcher`() {
        installLauncher()

        open("$REDIRECT?code=c&state=s")

        val started = shadowOf(application).nextStartedActivity
        assertNotNull("the launcher is started", started)
        assertEquals(0, started.flags and Intent.FLAG_ACTIVITY_CLEAR_TOP)
    }

    private fun installLauncher() {
        val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER).setPackage(application.packageName)
        shadowOf(application.packageManager).addResolveInfoForIntent(launcher, resolveInfoFor("MainActivity"))
    }

    private fun resolveInfoFor(name: String) = android.content.pm.ResolveInfo().apply {
        activityInfo = android.content.pm.ActivityInfo().apply {
            packageName = application.packageName
            this.name = "${application.packageName}.$name"
        }
    }
}
