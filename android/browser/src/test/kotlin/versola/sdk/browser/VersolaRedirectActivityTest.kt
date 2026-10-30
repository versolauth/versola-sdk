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
import versola.oauth.core.VersolaInternalApi
import versola.oauth.core.VersolaLogger

private const val REDIRECT = "https://app.example.com/oauth"
private const val AUTHORIZE = "https://id.example.com/authorize?response_type=code&state=s"

/** What the flow hands its session: the redirect and the state of the request it waits for. */
@OptIn(VersolaInternalApi::class)
private fun awaiting(state: String?) = BrowserSessionOptions(redirectUri = REDIRECT).also { it.expectedState = state }

private class NoteTaker : VersolaLogger {
    val lines = mutableListOf<String>()
    override fun info(message: String) {
        lines += message
    }
    override fun warn(message: String) {
        lines += message
    }
}

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
    fun `the path is compared as written, an encoded slash is not a slash`() {
        RedirectDispatcher.expect("https://app.example.com/oauth/cb")

        open("https://app.example.com/oauth%2Fcb?code=c&state=junk")
        assertFalse(RedirectDispatcher.redirectDelivered)

        open("https://app.example.com/oauth/cb?code=c&state=s")
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

        // Another app fires the exported activity at the open login. It runs in a task of its
        // own, so the host is not resumed: nothing here may read as a dismissal.
        open("anything://x?code=c&state=junk")
        runCurrent()
        assertFalse("the login is still waiting", login.isCompleted)

        // Later the user leaves for the tab and closes it: the detector is still armed, so
        // that return is a cancel.
        host.start().resume()
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

    // ---- scenario 15: a redirect for the awaited URI whose state is not the request's ----

    @Test
    fun `a redirect for the awaited URI with another state is ignored, and so is one with none`() {
        installLauncher()
        val notes = NoteTaker()
        RedirectDispatcher.expect(REDIRECT, "s", notes)

        for (junk in listOf("$REDIRECT?code=c&state=junk", "$REDIRECT?code=c", "$REDIRECT?code=c&state=", "$REDIRECT?code=c&state=ss", "$REDIRECT?code=c&state=S")) {
            val controller = open(junk)

            assertTrue("$junk: the activity still finishes", controller.get().isFinishing)
            assertFalse("$junk: not delivered, so the cancel detector is not silenced", RedirectDispatcher.redirectDelivered)
            assertNull("$junk: nothing reaches the waiter", takeNow())
            assertNull("$junk: the app is not brought forward over the tab", shadowOf(application).nextStartedActivity)
        }
        assertEquals("one line each", 5, notes.lines.size)
        assertTrue("no value of the URL in it: ${notes.lines}", notes.lines.none { "junk" in it || "app.example.com" in it })

        // The awaited state is delivered, whatever else the query carries.
        open("$REDIRECT?code=c&state=s&iss=https%3A%2F%2Fid.example.com")
        assertTrue(RedirectDispatcher.redirectDelivered)
    }

    @Test
    fun `after a redirect with another state was ignored a user's dismissal still ends the login and the genuine redirect still completes one`() = runTest {
        val session = CustomTabsAuthorizationSession(application)
        shadowOf(application).checkActivities(false)
        val host = Robolectric.buildActivity(Activity::class.java).setup()
        val login = async { session.authorize(AUTHORIZE, awaiting("s")) }
        runCurrent()
        host.pause().stop()

        // Another app, or a stale link, fires the public redirect URI at the exported activity.
        open("$REDIRECT?code=c&state=junk")
        runCurrent()
        assertFalse("the login is still waiting", login.isCompleted)

        // The user closes the tab: the detector was never silenced, so that return is a cancel.
        host.start().resume()
        runCurrent()
        assertEquals(BrowserOutcome.UserCancelled, login.await())
    }

    @Test
    fun `after a redirect with another state was ignored the genuine one completes the login`() = runTest {
        val session = CustomTabsAuthorizationSession(application)
        shadowOf(application).checkActivities(false)
        val login = async { session.authorize(AUTHORIZE, awaiting("s")) }
        runCurrent()

        open("$REDIRECT?code=c&state=junk")
        open("$REDIRECT?code=c&state=another")
        runCurrent()
        assertFalse(login.isCompleted)
        open("$REDIRECT?code=c&state=s")

        assertEquals("$REDIRECT?code=c&state=s", (login.await() as BrowserOutcome.Redirect).uri)
    }

    @Test
    fun `a login that names no state, an end-session leg, takes every redirect for its URI as before`() = runTest {
        val session = CustomTabsAuthorizationSession(application)
        val leg = async { session.authorize(AUTHORIZE, awaiting(null)) }
        runCurrent()

        open("$REDIRECT?state=whatever")

        assertTrue(leg.await() is BrowserOutcome.Redirect)
    }

    @Test
    fun `a new login forgets the previous one's awaited state`() {
        RedirectDispatcher.expect(REDIRECT, "old")
        RedirectDispatcher.drain()

        open("$REDIRECT?code=c&state=anything")

        assertTrue(RedirectDispatcher.redirectDelivered)
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
