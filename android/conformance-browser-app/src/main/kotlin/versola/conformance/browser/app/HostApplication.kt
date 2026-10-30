package versola.conformance.browser.app

import android.app.Application
import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.launch
import versola.oauth.OAuthClient
import versola.oauth.OAuthConfiguration
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaLogger
import versola.sdk.browser.CustomTabsAuthorizationSession
import java.io.File
import java.net.URI

/**
 * Owns the client and the on-screen log for the life of the process, not of an activity: the
 * redirect activity brings the host activity back (and, on a cold start, creates it anew), and a
 * `login()` the user is still waiting on must not be cancelled with the activity that started
 * it. The log is what the tests read; it never holds a token, a code or a `state`.
 */
class HostApplication : Application() {

    /** Not tied to any activity; see the class comment. */
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    /** The lines the screen shows, oldest first, one per event. */
    val log = MutableStateFlow("")

    @Volatile
    private var client: OAuthClient? = null

    override fun onCreate() {
        super.onCreate()
        append("process: started")
    }

    /**
     * One line to the screen and to `files/log.txt`. The tests read the file, not the screen:
     * the app is behind the browser for most of a flow, and a file also survives the process the
     * tests kill. `process: started` marks each process's first line.
     */
    fun append(line: String) {
        log.value = log.value + line + "\n"
        synchronized(this) { File(filesDir, "log.txt").appendText(line + "\n") }
    }

    /**
     * The client, created on first use. [browser] picks the leg and [issuer] the provider for
     * this process and the next ones (kept in preferences, because a cold start through the
     * redirect activity relaunches the app with no extras): `customtabs` forces the Custom Tabs
     * leg, anything else leaves the SDK's own choice, which is Auth Tab where the device's
     * browser has it. The issuer is the one the provider's discovery announces, reached over
     * `adb reverse`, so it is the caller's to say.
     */
    @Synchronized
    fun client(browser: String?, issuer: String?): OAuthClient {
        client?.let { return it }
        val preferences = getSharedPreferences("host", Context.MODE_PRIVATE)
        preferences.edit().apply {
            if (browser != null) putString("browser", browser)
            if (issuer != null) putString("issuer", issuer)
        }.apply()
        val leg = preferences.getString("browser", "default")
        val providerIssuer = preferences.getString("issuer", null)
        if (providerIssuer == null) {
            append("configuration refused: no issuer; launch with --es issuer <issuer>")
            error("no issuer")
        }

        val logger = object : VersolaLogger {
            override fun info(message: String) = append("sdk: $message")
            override fun warn(message: String) = append("sdk warning: $message")
        }
        val configuration = OAuthConfiguration(
            issuer = providerIssuer,
            clientId = BuildConfig.CLIENT_ID,
            redirectUri = BuildConfig.REDIRECT_URI,
            postLogoutRedirectUri = BuildConfig.POST_LOGOUT_REDIRECT_URI,
            scopes = setOf("openid", "profile"),
            protectedOrigins = setOf(originOf(providerIssuer)),
            logger = logger,
        )
        val created = try {
            if (leg == "customtabs") {
                OAuthClient.create(this, configuration, browser = CustomTabsAuthorizationSession(this, logger))
            } else {
                OAuthClient.create(this, configuration)
            }
        } catch (error: VersolaError) {
            append("configuration refused: ${error.message}")
            throw error
        }
        append("browser: $leg")
        scope.launch { created.sessionState.collect { append("state: $it") } }
        client = created
        return created
    }

    private fun originOf(url: String): String {
        val uri = URI(url)
        val port = if (uri.port == -1) "" else ":${uri.port}"
        return "${uri.scheme}://${uri.host}$port"
    }
}
