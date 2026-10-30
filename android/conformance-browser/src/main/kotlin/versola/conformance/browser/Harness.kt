package versola.conformance.browser

import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until

/**
 * What the tests share: the device, the host app's screen as a log, and Chrome.
 *
 * Everything is read off the screen or the system, never out of the SDK's process: the host app
 * writes one line per observable outcome (`:conformance-browser-app`), and the tests also ask
 * the system which activity is on top, so "the Custom Tab opened" is the browser's own activity
 * and not the SDK's word for it.
 */
internal class Harness {

    val device: UiDevice = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
    private val arguments = InstrumentationRegistry.getArguments()

    /** The provider's issuer as its discovery announces it; absent means the tier is not configured. */
    val issuer: String? = arguments.getString("issuer")

    val keycloak: Keycloak? = issuer?.let {
        Keycloak(it, arguments.getString("adminUser") ?: "admin", arguments.getString("adminPassword") ?: "admin")
    }

    fun shell(command: String): String = device.executeShellCommand(command)

    /** A clean slate: no app data (so no stored grant or pending request), no Chrome tab left over. */
    fun reset() {
        shell("am force-stop $CHROME")
        shell("pm clear $HOST")
        device.pressHome()
    }

    fun launchHost(leg: String) {
        shell("am start -W -n $HOST/.HostActivity --es browser $leg --es issuer $issuer")
        check(device.wait(Until.hasObject(By.res(HOST, "login")), UI_TIMEOUT_MILLIS)) { "the host app did not come up" }
    }

    /** Relaunches the app the way the launcher does, with no extras. */
    fun resumeHost() {
        shell("am start -n $HOST/.HostActivity")
        check(device.wait(Until.hasObject(By.res(HOST, "login")), UI_TIMEOUT_MILLIS)) { "the host app did not come up" }
    }

    fun tap(id: String) {
        val button = device.wait(Until.findObject(By.res(HOST, id)), UI_TIMEOUT_MILLIS)
            ?: error("no $id button on screen; top is ${topActivity()}")
        button.click()
    }

    /**
     * The host app's log, oldest line first, across every process since the data was cleared;
     * read from the app's file, since the app is behind the browser for most of a flow. Debuggable,
     * so `run-as` reads it.
     */
    fun log(): String = shell("run-as $HOST cat files/log.txt")

    /** How many processes the app has started since its data was cleared. */
    fun processStarts(): Int = log().lines().count { it == "process: started" }

    /** The log of the app's current process only: what it observed since it last started. */
    fun currentProcessLog(): String = log().substringAfterLast("process: started")

    fun awaitLog(fragment: String, timeoutMillis: Long = FLOW_TIMEOUT_MILLIS): String =
        await("the log to contain \"$fragment\"", timeoutMillis) { log().takeIf { fragment in it } }

    /** The activity the system says is in front: `package/class`. */
    fun topActivity(): String =
        shell("dumpsys activity activities").lineSequence()
            .firstOrNull { "topResumedActivity" in it }
            ?.substringAfter(" u0 ")?.substringBefore(' ')?.substringBefore('}').orEmpty()

    /** Whether [fragment] names an activity in any task: used to tell Auth Tab's trampoline from a Custom Tab alone. */
    fun hasActivity(fragment: String): Boolean = fragment in shell("dumpsys activity activities")

    fun awaitTopActivity(fragment: String, timeoutMillis: Long = UI_TIMEOUT_MILLIS) {
        await("$fragment on top", timeoutMillis) { topActivity().takeIf { fragment in it } }
    }

    // -- Chrome ---------------------------------------------------------------------------

    /**
     * Waits for the provider's login form in the browser. A Chrome that has never run in this
     * emulator first asks about accounts, sync and notifications even inside a Custom Tab, so
     * those prompts are dismissed on the way (the "use without" and "no thanks" answers; nothing
     * is signed in to Chrome).
     */
    fun awaitLoginForm() {
        await("the provider's login form", FLOW_TIMEOUT_MILLIS) {
            for (label in CHROME_PROMPTS) device.findObject(By.pkg(CHROME).text(label))?.click()
            device.findObject(By.res("username")).takeIf { it != null }
        }
    }

    /** Types alice's credentials from the realm into the form and submits it. */
    fun submitCredentials(username: String = "alice", password: String = "alice-password") {
        // Real key events rather than ACTION_SET_TEXT: the form validates what the page saw.
        device.findObject(By.res("username")).click()
        shell("input text $username")
        device.findObject(By.res("password")).click()
        shell("input text $password")
        shell("input keyevent 66")
    }

    /** Signs in at the form and waits for the browser to hand control back to the app. */
    fun signInAtProvider() {
        awaitLoginForm()
        submitCredentials()
    }

    /** Back to the open tab the way a user does after Home: through the recent apps. */
    fun returnToBrowser() {
        device.pressRecentApps()
        val card = device.wait(Until.findObject(By.descStartsWith("Chrome")), UI_TIMEOUT_MILLIS)
            ?: error("no Chrome card in the recent apps")
        card.click()
    }

    fun closeTabWithBack() {
        device.pressBack()
    }

    fun closeTabWithCloseButton() {
        (device.findObject(By.res(CHROME, "close_button")) ?: error("no close button on the tab")).click()
    }

    // -- Process ---------------------------------------------------------------------------

    /** Kills the host app's process the way the system does under memory pressure: no callback, no clean-up. */
    fun killHostProcess() {
        val pid = shell("pidof $HOST").trim()
        check(pid.isNotEmpty()) { "the host app is not running" }
        shell("run-as $HOST kill -9 $pid")
        await("the host process to be gone", UI_TIMEOUT_MILLIS) { true.takeIf { shell("pidof $HOST").isBlank() } }
    }

    fun cleanUp() {
        shell("am force-stop $CHROME")
        shell("am force-stop $HOST")
    }

    /** Polls [probe] until it returns non-null; the failure says what was awaited and what was on screen. */
    fun <T : Any> await(what: String, timeoutMillis: Long, probe: () -> T?): T {
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        while (true) {
            probe()?.let { return it }
            if (SystemClock.elapsedRealtime() > deadline) {
                error("timed out after ${timeoutMillis}ms waiting for $what; top activity ${topActivity()}; host log:\n${log()}")
            }
            SystemClock.sleep(POLL_MILLIS)
        }
    }

    companion object {
        const val HOST = "versola.conformance.browser.app"
        const val CHROME = "com.android.chrome"
        const val UI_TIMEOUT_MILLIS = 15_000L
        const val FLOW_TIMEOUT_MILLIS = 45_000L
        private const val POLL_MILLIS = 500L

        /** The answers that leave Chrome unsigned and unsynced; anything else is the provider's page. */
        private val CHROME_PROMPTS = listOf("Use without an account", "No thanks", "Got it")
    }
}
