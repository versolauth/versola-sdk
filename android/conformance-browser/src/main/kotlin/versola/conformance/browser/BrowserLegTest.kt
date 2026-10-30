package versola.conformance.browser

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

/**
 * The system browser leg against a real provider (Keycloak), on a real emulator, driving Chrome
 * the way a user does: the Custom Tab or Auth Tab opens on the provider's own login page, alice
 * types her password, and the redirect comes back to the app through the platform. What
 * `HttpLoginBrowser` (the conformance tier) replaces with an HTTP conversation is exercised here.
 *
 * Run once per browser leg: `customtabs` forces the Custom Tabs fallback; `default` leaves the
 * SDK's own choice, which is Auth Tab where Chrome offers it, and is skipped where it does not
 * (the host's log says "no Auth Tab support"), so that a skipped row says which leg this
 * emulator's Chrome could not run.
 *
 * The redirect is a private-use scheme (`com.example.versola.devicetier://app/oauth`): an App
 * Link needs a host this machine does not control (spec: `RedirectUriKind.AppLink` is verified
 * through `assetlinks.json`).
 *
 * Scenario ids: 01 (the happy half of the browser leg), 12 (process death with the browser
 * open), 15 (a redirect that is not the awaited response) and 18 (logout); the cancel table of `spec/state-machine.md`.
 */
@RunWith(Parameterized::class)
class BrowserLegTest(private val leg: String) {

    private val harness = Harness()

    @Before
    fun freshDevice() {
        assumeTrue("no `issuer` instrumentation argument: the browser-leg tier is not configured", harness.issuer != null)
        harness.keycloak!!.endSessions(ALICE)
        harness.reset()
        harness.launchHost(leg)
    }

    @After
    fun tidy() {
        if (harness.issuer != null) harness.cleanUp()
    }

    @Test
    fun browserOpensAliceSignsInRedirectReturnsAndLogoutEndsTheProviderSession() {
        startLogin()
        harness.awaitLoginForm()
        harness.awaitTopActivity("CustomTabActivity")
        assertEquals("the browser is Chrome's", Harness.CHROME, harness.topActivity().substringBefore('/'))
        assertEquals("an Auth Tab is the SDK's trampoline over Chrome's tab", leg == "default", harness.hasActivity("VersolaAuthTabActivity"))

        harness.submitCredentials()

        val log = harness.awaitLog("login: ok")
        assertTrue("Authorizing, then Authenticated", log.indexOf("state: Authorizing") in 0 until log.indexOf("state: Authenticated"))
        assertTrue("claims hold alice from the validated ID token\n$log", "claims: preferred_username=alice issuer=${harness.issuer}" in log)
        assertEquals("the redirect returned the user to the app", HOST_ACTIVITY, harness.topActivity())
        assertEquals("the provider holds the session the browser created", 1, harness.keycloak!!.sessions(ALICE))

        harness.tap("token")
        val used = harness.awaitLog("userinfo: preferred_username=alice")
        assertTrue("accessToken() returns a bearer token the provider accepts\n$used", "accessToken: present=true dpop=false" in used)

        harness.tap("logout")
        harness.awaitLog("logout: sessionEnded=true tokenRevoked=true")
        assertTrue("signed out locally", "state: Unauthenticated" in harness.log().substringAfter("login: ok"))
        assertEquals("the provider's session ended", 0, harness.keycloak.sessions(ALICE))
    }

    @Test
    fun backFromTheTabIsAUserCancelAndWipesThePendingRequest() {
        startLogin()
        harness.awaitLoginForm()

        harness.closeTabWithBack()

        assertUserCancelledAndPendingRequestWiped()
    }

    @Test
    fun theTabsCloseButtonIsAUserCancelAndWipesThePendingRequest() {
        startLogin()
        harness.awaitLoginForm()

        harness.closeTabWithCloseButton()

        assertUserCancelledAndPendingRequestWiped()
    }

    @Test
    fun theAppSentToTheBackgroundAndBackKeepsThePendingRequestAndTheSignInCompletes() {
        startLogin()
        harness.awaitLoginForm()

        harness.device.pressHome()
        Thread.sleep(SETTLE_MILLIS)
        harness.returnToBrowser()
        harness.awaitLoginForm()

        val log = harness.log()
        assertFalse("backgrounding is not a cancel\n$log", "login: failed" in log)
        harness.submitCredentials()
        harness.awaitLog("login: ok")
        assertTrue("signed in after the round trip", "state: Authenticated" in harness.log())
    }

    @Test
    fun aProcessKilledWhileTheBrowserIsOpenRestartsAsAuthorizingWhenTheRedirectArrives() {
        startLogin()
        harness.awaitLoginForm()

        harness.killHostProcess()
        val processesBefore = harness.processStarts()
        harness.submitCredentials()

        // Nothing but the redirect can have started the process again: the cold start of
        // scenario 12 is the redirect activity's.
        harness.await("the redirect to cold-start the app", Harness.FLOW_TIMEOUT_MILLIS) {
            true.takeIf { harness.processStarts() > processesBefore && "state: " in harness.currentProcessLog() }
        }
        val log = harness.currentProcessLog()
        assertTrue("the pending request survived the kill: the app observes Authorizing\n$log", "state: Authorizing" in log)
        assertFalse("never Unauthenticated on cold start\n$log", "state: Unauthenticated" in log)
        assertEquals("the redirect brought the app forward", HOST_ACTIVITY, harness.topActivity())
    }

    /**
     * Scenario 12's last assertion ("the restored code_verifier produces a successful exchange"):
     * the redirect cold-starts the app, `OAuthClient.create()` restores `Authorizing` and awaits
     * the buffered redirect, and the sign-in completes with nothing called by the app
     * (`spec/oauth-sdk-api.md` section 4).
     */
    @Test
    fun aRedirectDeliveredToAColdStartedProcessCompletesTheSignIn() {
        startLogin()
        harness.awaitLoginForm()

        harness.killHostProcess()
        harness.submitCredentials()

        val log = harness.awaitLog("state: Authenticated", COLD_START_COMPLETION_MILLIS)
        assertTrue("the restored request validated the redirect and the code was exchanged\n$log", "state: Authenticated" in harness.currentProcessLog())
        assertEquals("the provider holds the session", 1, harness.keycloak!!.sessions(ALICE))
    }

    /**
     * Scenario 15 (`15-state-mismatch`): the redirect URI is public, so another app can fire it at
     * the exported redirect activity with a state it made up. That is not the response to this
     * login: ignored, the tab stays in front, and the genuine sign-in in it still completes.
     */
    @Test
    fun aRedirectCarryingTheWrongStateIsIgnoredAndTheLoginStillCompletes() {
        startLogin()
        harness.awaitLoginForm()

        fireRedirect("code=forged&state=forged&iss=${harness.issuer}")
        fireRedirect("code=forged&iss=${harness.issuer}")
        Thread.sleep(SETTLE_MILLIS)

        val log = harness.log()
        assertFalse("not a failure: it was not the response\n$log", "login: failed" in log)
        assertFalse("no sign-in happened\n$log", "state: Authenticated" in log)
        assertEquals("the provider never saw a code exchange", 0, harness.keycloak!!.sessions(ALICE))
        assertTrue("the tab is still in front, not the app: ${harness.topActivity()}", "CustomTabActivity" in harness.topActivity())

        harness.signInAtProvider()
        harness.awaitLog("login: ok")
        assertTrue("the genuine redirect completed the login that waited", "state: Authenticated" in harness.log())
    }

    /**
     * The other half of scenario 15 on a device: after a redirect was ignored the cancel detection
     * is intact. A delivered redirect silences it (`redirectDelivered`), so the ignored one must not
     * have been delivered; the user closing the tab afterwards is still a cancel.
     */
    @Test
    fun aDismissalAfterAnIgnoredRedirectStillEndsTheLoginAsACancel() {
        startLogin()
        harness.awaitLoginForm()

        fireRedirect("code=forged&state=forged&iss=${harness.issuer}")
        Thread.sleep(SETTLE_MILLIS)
        assertFalse("not a failure\n${harness.log()}", "login: failed" in harness.log())
        harness.awaitTopActivity("CustomTabActivity")
        harness.closeTabWithBack()

        assertUserCancelledAndPendingRequestWiped()
    }

    private fun fireRedirect(query: String) {
        harness.shell(
            "am start -W -a android.intent.action.VIEW -n ${Harness.HOST}/versola.sdk.browser.VersolaRedirectActivity " +
                "-d com.example.versola.devicetier://app/oauth?$query",
        )
    }

    @Test
    fun aRedirectToAnotherUriIsIgnoredAndTheLoginStillCompletes() {
        startLogin()
        harness.awaitLoginForm()

        // Another app firing the exported redirect activity with a URI that is not the
        // redirect the login waits for: it must neither fail the login nor end it.
        harness.shell(
            "am start -W -a android.intent.action.VIEW -n ${Harness.HOST}/versola.sdk.browser.VersolaRedirectActivity " +
                "-d anything://x?code=forged&state=forged",
        )
        Thread.sleep(SETTLE_MILLIS)

        val log = harness.log()
        assertFalse("a foreign redirect is not a response\n$log", "login: failed" in log)
        assertFalse("no sign-in happened\n$log", "state: Authenticated" in log)
        // The redirect activity runs in a task of its own, so ignoring the intent leaves the tab
        // in front rather than raising the app over it.
        assertTrue("the tab is still in front: ${harness.topActivity()}", "CustomTabActivity" in harness.topActivity())
        harness.signInAtProvider()
        harness.awaitLog("login: ok")
        assertTrue("signed in after the foreign intent", "state: Authenticated" in harness.log())
    }

    private fun startLogin() {
        harness.tap("login")
        harness.awaitLog("state: Authorizing")
        // Which leg the SDK chose is logged (a fallback) or visible (the Auth Tab trampoline)
        // before the browser is: awaited with Chrome's first-run prompts answered, since on a
        // fresh image the first thing Chrome shows is not the tab.
        val chosen = harness.await("the SDK to open a browser", Harness.FLOW_TIMEOUT_MILLIS) {
            harness.dismissChromePrompts()
            when {
                "no Auth Tab support" in harness.log() -> "customtabs"
                harness.hasActivity("VersolaAuthTabActivity") -> "authtab"
                leg == "customtabs" && "state: Authorizing" in harness.log() && harness.hasActivity("CustomTabActivity") -> "customtabs"
                else -> null
            }
        }
        // `default` is the SDK's own choice: where Chrome has no Auth Tab it falls back, and a
        // row that cannot exercise Auth Tab is skipped rather than passed on the wrong leg.
        assumeTrue("this emulator's Chrome has no Auth Tab support", leg != "default" || chosen == "authtab")
    }

    /** The cancel half of `spec/state-machine.md`: `Recoverable(UserCancelled)`, and the request does not outlive it. */
    private fun assertUserCancelledAndPendingRequestWiped() {
        val log = harness.awaitLog("login: failed Recoverable(UserCancelled)")
        assertTrue("Authorizing back to Unauthenticated\n$log", log.indexOf("state: Authorizing") in 0 until log.lastIndexOf("state: Unauthenticated"))
        // A wiped request leaves nothing to restore: a cold start reports Unauthenticated,
        // where a kept one would report Authorizing.
        harness.shell("am force-stop ${Harness.HOST}")
        harness.resumeHost()
        harness.await("the restarted app to report a state", Harness.UI_TIMEOUT_MILLIS) {
            harness.currentProcessLog().takeIf { "state: " in it }
        }
        val restarted = harness.currentProcessLog()
        assertTrue("the pending request was wiped: a cold start reports Unauthenticated\n$restarted", "state: Unauthenticated" in restarted)
        assertFalse("not Authorizing\n$restarted", "state: Authorizing" in restarted)
    }

    private companion object {
        const val ALICE = "alice"
        const val HOST_ACTIVITY = "${Harness.HOST}/.HostActivity"
        const val SETTLE_MILLIS = 1_500L
        const val COLD_START_COMPLETION_MILLIS = 20_000L

        @JvmStatic
        @Parameterized.Parameters(name = "{0}")
        fun legs() = listOf("customtabs", "default")
    }
}
