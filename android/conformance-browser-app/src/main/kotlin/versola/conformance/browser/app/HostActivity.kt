package versola.conformance.browser.app

import android.app.Activity
import android.os.Bundle
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import versola.oauth.LoginOptions
import versola.oauth.core.VersolaError

/**
 * Three buttons and a log. The tests press the buttons and read the log, so every outcome the
 * SDK reports is one line of it: `state: <state>`, `login: ok` or `login: failed <error>`,
 * `claims: ...`, `accessToken: ...`, `userinfo: ...`, `refresh: ...`, `logout: ...`.
 *
 * The launch extras `browser` (`customtabs` or `default`) and `issuer` say which browser leg and
 * which provider; see [HostApplication.client].
 */
class HostActivity : Activity() {

    private val app get() = application as HostApplication
    private var collecting: Job? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val status = TextView(this).apply {
            id = R.id.status
            setTextIsSelectable(false)
        }
        val login = button(R.id.login, "Sign in")
        val loginEphemeral = button(R.id.loginEphemeral, "Sign in (ephemeral)")
        val logout = button(R.id.logout, "Sign out")
        val refresh = button(R.id.refresh, "Refresh")
        val token = button(R.id.token, "Access token")
        setContentView(
            LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(PADDING, PADDING, PADDING, PADDING)
                addView(login)
                addView(loginEphemeral)
                addView(token)
                addView(refresh)
                addView(logout)
                // Content is laid out under the status bar from targetSdk 35; this pads it clear.
                fitsSystemWindows = true
                addView(
                    ScrollView(this@HostActivity).apply { addView(status) },
                    LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f),
                )
            },
        )

        val client = app.client(intent?.getStringExtra("browser"), intent?.getStringExtra("issuer"))
        collecting = app.scope.launch { app.log.collect { status.text = it } }

        for ((button, ephemeral) in listOf(login to false, loginEphemeral to true)) button.setOnClickListener {
            app.scope.launch {
                try {
                    client.login(LoginOptions(ephemeralBrowser = ephemeral))
                    app.append("login: ok")
                    val claims = client.claims
                    app.append("claims: preferred_username=${claims?.all?.get("preferred_username")} issuer=${claims?.issuer}")
                } catch (error: VersolaError) {
                    app.append("login: failed ${describe(error)}")
                }
            }
        }
        token.setOnClickListener {
            app.scope.launch {
                try {
                    val accessToken = client.accessToken()
                    app.append("accessToken: present=${accessToken.value.isNotEmpty()} dpop=${accessToken.isDpopBound}")
                    // The token is spent on the provider's own UserInfo endpoint, which only
                    // answers for a token it issued: that is the proof the token works.
                    val userInfo = client.userInfo()
                    app.append("userinfo: preferred_username=${userInfo.claims["preferred_username"]}")
                } catch (error: VersolaError) {
                    app.append("accessToken: failed ${describe(error)}")
                }
            }
        }
        refresh.setOnClickListener {
            app.scope.launch {
                try {
                    client.refresh()
                    app.append("refresh: ok")
                } catch (error: VersolaError) {
                    app.append("refresh: failed ${describe(error)}")
                }
            }
        }
        logout.setOnClickListener {
            app.scope.launch {
                val outcome = client.logout()
                app.append("logout: sessionEnded=${outcome.sessionEnded} tokenRevoked=${outcome.tokenRevoked}")
            }
        }
    }

    override fun onDestroy() {
        collecting?.cancel()
        super.onDestroy()
    }

    private fun button(viewId: Int, label: String) = Button(this).apply {
        id = viewId
        text = label
    }

    /** The category and its cause, nothing the error's message might quote. */
    private fun describe(error: VersolaError): String = when (error) {
        is VersolaError.Recoverable -> "Recoverable(${error.reason})"
        is VersolaError.Reauthenticate -> "Reauthenticate(${error.reason})"
        is VersolaError.Configuration -> "Configuration(${error.detail})"
        else -> error::class.simpleName.orEmpty()
    }

    private companion object {
        const val PADDING = 32
    }
}
