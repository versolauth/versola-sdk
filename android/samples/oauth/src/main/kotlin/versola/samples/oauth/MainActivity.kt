package versola.samples.oauth

import android.app.Activity
import android.os.Bundle
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.net.URI
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import okhttp3.Request
import versola.oauth.OAuthClient
import versola.oauth.OAuthConfiguration
import versola.oauth.core.VersolaError

/**
 * A minimal app over the generic facade [OAuthClient]: sign in, call a protected resource,
 * sign out, with the session state and every outcome written to an on-screen log.
 *
 * What it proves is its build, not its screen: the release variant is minified by R8 with the
 * stock rules and an empty `proguard-rules.pro`, so the SDK needs no consumer keep rules. The
 * instrumented `SmokeTest` runs discovery, sign-in and an authenticated call on the debug build;
 * the build file says why not on the minified one.
 *
 * The configuration comes from Gradle properties baked into `BuildConfig`
 * (`-PsampleIssuer=...`, `-PsampleClientId=...`, `-PsampleRedirectUri=...`,
 * `-PsamplePostLogoutRedirectUri=...`, `-PsampleResourceUrl=...`); see the module README.
 * The UI is built in code so the module needs no layout resources and no AppCompat or Material
 * dependency. Tokens are never logged here.
 */
class MainActivity : Activity() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private lateinit var client: OAuthClient
    private lateinit var log: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        log = TextView(this).apply { setTextIsSelectable(true) }
        val signIn = Button(this).apply { text = "Sign in" }
        val callResource = Button(this).apply { text = "Call resource" }
        val signOut = Button(this).apply { text = "Sign out" }
        setContentView(
            LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(PADDING, PADDING, PADDING, PADDING)
                addView(signIn)
                addView(callResource)
                addView(signOut)
                addView(
                    ScrollView(this@MainActivity).apply { addView(log) },
                    LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f),
                )
            },
        )

        try {
            client = OAuthClient.create(
                this,
                OAuthConfiguration(
                    issuer = BuildConfig.ISSUER,
                    clientId = BuildConfig.CLIENT_ID,
                    redirectUri = BuildConfig.REDIRECT_URI,
                    postLogoutRedirectUri = BuildConfig.POST_LOGOUT_REDIRECT_URI,
                    scopes = setOf("openid", "profile"),
                    protectedOrigins = setOf(originOf(BuildConfig.RESOURCE_URL)),
                ),
            )
        } catch (error: VersolaError) {
            append("configuration refused: ${error.message}")
            return
        }

        scope.launch { client.sessionState.collect { append("state: $it") } }

        signIn.setOnClickListener {
            scope.launch {
                guarded("sign in") {
                    client.login()
                    append("signed in as ${client.claims?.subject}")
                }
            }
        }
        callResource.setOnClickListener {
            scope.launch {
                guarded("call") {
                    val request = Request.Builder().url(BuildConfig.RESOURCE_URL).build()
                    val status = client.call(request).use { it.code }
                    append("resource answered $status")
                }
            }
        }
        signOut.setOnClickListener {
            scope.launch {
                guarded("sign out") {
                    val outcome = client.logout()
                    append("signed out: sessionEnded=${outcome.sessionEnded} tokenRevoked=${outcome.tokenRevoked}")
                }
            }
        }
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private suspend fun guarded(what: String, block: suspend () -> Unit) {
        try {
            block()
        } catch (error: VersolaError) {
            append("$what failed: ${error.message}")
        }
    }

    private fun append(line: String) {
        log.append(line + "\n")
    }

    private fun originOf(url: String): String {
        val uri = URI(url)
        val port = if (uri.port == -1) "" else ":${uri.port}"
        return "${uri.scheme}://${uri.host}$port"
    }

    private companion object {
        const val PADDING = 32
    }
}
