package versola.sdk.browser

import android.app.Activity
import android.app.Application
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner

/**
 * The user-cancel signal. Android reports nothing when a Custom Tab is dismissed; what it
 * does report is the host activity resuming, and that — while an authorization is
 * outstanding and no redirect has arrived — is the dismissal.
 */
@RunWith(RobolectricTestRunner::class)
class ForegroundReturnDetectorTest {

    private val application = ApplicationProvider.getApplicationContext<Application>()

    @Before
    fun drainPreviousSessions() {
        RedirectDispatcher.drain()
    }

    private fun detector(onReturn: () -> Unit) = ForegroundReturnDetector(application, onReturn)

    @Test
    fun `returning to the foreground with no redirect is a user cancel`() {
        var cancelled = false
        val detector = detector { cancelled = true }
        val host = Robolectric.buildActivity(Activity::class.java).setup()

        detector.arm()
        host.pause().stop()
        host.start().resume()

        assertTrue(cancelled)
    }

    @Test
    fun `a resume before the app ever backgrounded is not a cancel`() {
        // A launch that failed, or a configuration change, must not read as a dismissal the
        // user never performed.
        var cancelled = false
        val detector = detector { cancelled = true }
        val host = Robolectric.buildActivity(Activity::class.java).setup()

        detector.arm()
        host.pause().resume()

        assertFalse(cancelled)
    }

    @Test
    fun `a resume after a redirect was delivered is the success path, not a cancel`() {
        var cancelled = false
        val detector = detector { cancelled = true }
        val host = Robolectric.buildActivity(Activity::class.java).setup()

        detector.arm()
        host.pause().stop()
        RedirectDispatcher.deliver("https://app.example.com/oauth?code=c&state=s")
        host.start().resume()

        assertFalse(cancelled)
    }

    @Test
    fun `a disarmed detector reports nothing`() {
        var cancelled = false
        val detector = detector { cancelled = true }
        val host = Robolectric.buildActivity(Activity::class.java).setup()

        detector.arm()
        detector.disarm()
        host.pause().stop()
        host.start().resume()

        assertFalse(cancelled)
    }

    @Test
    fun `only the first return is reported`() {
        // The outcome is consumed once; a second report would sit in the channel and be
        // handed to the next authorization.
        var cancels = 0
        val detector = detector { cancels++ }
        val host = Robolectric.buildActivity(Activity::class.java).setup()

        detector.arm()
        host.pause().stop()
        host.start().resume()
        host.pause().stop()
        host.start().resume()

        assertTrue(cancels == 1)
    }

    // AUDIT: C14 - onActivityResumed() reads ANY activity resuming after ANY activity stopped as the user
    // dismissing the tab. The host app's own second activity (a splash handing over, a deep-link screen)
    // resuming while the tab is still opening is not a dismissal. Unit tier only: that the tab is really
    // still up is a device-tier fact; this pins that the heuristic does not equate "some activity resumed"
    // with "the user cancelled".
    @Test
    fun `AUDIT C14 another host activity resuming while the tab is opening is not a cancel`() {
        var cancelled = false
        val detector = detector { cancelled = true }
        val first = Robolectric.buildActivity(Activity::class.java).setup()

        detector.arm()
        // The tab opens over the first activity, which stops...
        first.pause().stop()
        // ...and a different activity of the host app comes up (not the one the login was started from).
        Robolectric.buildActivity(Activity::class.java).setup()

        assertFalse("activity B resuming after activity A stopped was reported as UserCancelled", cancelled)
    }
}
