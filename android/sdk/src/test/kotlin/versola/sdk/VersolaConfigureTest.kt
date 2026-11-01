package versola.sdk

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import versola.sdk.core.BackChannel
import versola.oauth.core.SessionState
import versola.oauth.core.TokenBinding
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaLogger
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import versola.sdk.storage.HardwareKeyProvider
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

private class CollectingLogger : VersolaLogger {
    val warnings = mutableListOf<String>()
    val info = mutableListOf<String>()

    override fun info(message: String) {
        info += message
    }

    override fun warn(message: String) {
        warnings += message
    }
}

@RunWith(RobolectricTestRunner::class)
class VersolaConfigureTest {

    private val application = ApplicationProvider.getApplicationContext<Application>()

    private fun configure(
        issuer: String = "https://id.versola.io",
        clientId: String = "mobile-app",
        redirectUri: String = "https://app.example.com/oauth",
        tokenBinding: TokenBinding = TokenBinding.Dpop(),
        logger: VersolaLogger = CollectingLogger(),
    ) = Versola.configure(application, issuer, clientId, redirectUri, logger, tokenBinding = tokenBinding)

    @Test
    fun `configure keeps the validated configuration`() {
        val versola = configure()

        assertEquals("https://id.versola.io", versola.configuration.issuer)
        assertEquals("mobile-app", versola.configuration.clientId)
        assertEquals("https://app.example.com/oauth", versola.configuration.redirectUri.value)
    }

    @Test
    fun `a private-use redirect scheme warns on the spot`() {
        // #5 asks for this to be loud, because the alternative is discovering on a support
        // ticket that another app claimed the scheme.
        val logger = CollectingLogger()

        configure(redirectUri = "com.example.app:/oauth", logger = logger)

        assertEquals(1, logger.warnings.size)
        assertTrue(logger.warnings.single().contains("private-use scheme"))
    }

    @Test
    fun `an App Link redirect warns about nothing`() {
        val logger = CollectingLogger()

        configure(logger = logger)

        assertTrue(logger.warnings.isEmpty())
    }

    @Test
    fun `a bad issuer fails at configure time rather than behind a login screen`() {
        assertThrows(VersolaError.Configuration::class.java) { configure(issuer = "http://id.versola.io") }
        assertThrows(VersolaError.Configuration::class.java) { configure(clientId = "") }
        assertThrows(VersolaError.Configuration::class.java) { configure(redirectUri = "/relative") }
    }

    @Test
    fun `a fresh install starts Unauthenticated`() = runTest {
        assertSame(SessionState.Unauthenticated, configure().sessionState.first())
    }

    @Test
    fun `DPoP is wired by default and Bearer is the only way out of it`() {
        // #1 §4: on and invisible. The integrator's one lever is refusing key binding
        // outright, and taking it is what makes `dpop` null rather than any discovery result.
        assertNotNull(configure().dpop)
        assertNull(configure(tokenBinding = TokenBinding.Bearer).dpop)
    }

    @Test
    fun `configure touches no keystore`() = runTest {
        // The key is generated on first use, off the main thread. Generating it here would
        // put a StrongBox keygen inside a synchronous call an app makes during startup — and
        // Robolectric has no Keystore to generate it in, so this passing at all is the check.
        assertNotNull(configure(tokenBinding = TokenBinding.Dpop(requireHardware = true)).dpop)
    }

    @Test
    fun `a post-logout redirect is validated at configure time like the login redirect`() {
        val versola = Versola.configure(
            application, "https://id.versola.io", "mobile-app", "https://app.example.com/oauth",
            postLogoutRedirectUri = "https://app.example.com/signed-out",
        )
        assertEquals("https://app.example.com/signed-out", versola.configuration.postLogoutRedirectUri?.value)

        assertThrows(VersolaError.Configuration::class.java) {
            Versola.configure(
                application, "https://id.versola.io", "mobile-app", "https://app.example.com/oauth",
                postLogoutRedirectUri = "signed-out",
            )
        }
    }

    @Test
    fun `BackChannel Edge needs edge, DPoP and an App Link, each refused at configure time`() {
        val viaEdge = Versola.configure(
            application, "https://id.versola.io", "mobile-app", "https://app.example.com/oauth",
            edgeBaseUrl = "https://versola.io", backChannel = BackChannel.Edge,
        )
        assertNotNull(viaEdge.dpop)

        val withoutEdge = assertThrows(VersolaError.Configuration::class.java) {
            Versola.configure(
                application, "https://id.versola.io", "mobile-app", "https://app.example.com/oauth",
                backChannel = BackChannel.Edge,
            )
        }
        assertTrue(withoutEdge.message!!.contains("edgeBaseUrl"))

        assertThrows(VersolaError.Configuration::class.java) {
            Versola.configure(
                application, "https://id.versola.io", "mobile-app", "https://app.example.com/oauth",
                tokenBinding = TokenBinding.Bearer, edgeBaseUrl = "https://versola.io", backChannel = BackChannel.Edge,
            )
        }
        assertThrows(VersolaError.Configuration::class.java) {
            Versola.configure(
                application, "https://id.versola.io", "mobile-app", "com.example.app:/oauth",
                edgeBaseUrl = "https://versola.io", backChannel = BackChannel.Edge,
            )
        }
    }

    @Test
    fun `configure twice in one process shares the credential store rather than opening a second DataStore`() = runTest {
        // Activity.onCreate re-runs configure() on every rotation.
        val first = configure()
        val second = configure()

        assertSame(SessionState.Unauthenticated, first.sessionState.first())
        assertSame(SessionState.Unauthenticated, second.sessionState.first())
    }

    // AUDIT: C2 - each configure() builds a whole second stack (coordinator, epoch, cached token, flow state)
    // over the one shared credential store, so a logout() on one instance cannot fence the other's in-flight
    // refresh. The simplest observable form of the fix: the same configuration yields the same instance,
    // as OAuthClient.create does. (A behavioural test of A.logout() vs B's refresh needs a real Keystore for
    // the credential store, which Robolectric does not have.)
    @Test
    fun `AUDIT C2 configure twice with the same configuration returns one instance`() {
        val first = configure()
        val second = configure()

        assertSame("two stacks over one credential store, each with its own epoch and token cache", first, second)
    }

    // AUDIT: C5 - the default client sets connect and read timeouts only, so nothing bounds a whole call.
    @Test
    fun `AUDIT C5 the default HTTP client has an overall call timeout`() {
        val timeout = Versola.configure(
            application, "https://id.versola.io", "mobile-app", "https://app.example.com/oauth",
            tokenBinding = TokenBinding.Bearer, edgeBaseUrl = "https://versola.io",
        ).httpClient().callTimeoutMillis

        assertTrue("callTimeoutMillis is $timeout; a slow-drip response can hold a call forever", timeout in 1..60_000)
    }

    // AUDIT: C4 - Versola.configure passes no retryClock, so the Retry-After cooldown runs on System.nanoTime,
    // which stops in deep sleep; the cooldown must elapse with elapsedRealtime.
    @Test
    fun `AUDIT C4 a Retry-After cooldown elapses with elapsedRealtime, not a clock that stops in deep sleep`() = runTest {
        Versola.keyProviders = {
            object : versola.oauth.core.CredentialKeyProvider {
                override suspend fun wrap(plaintext: ByteArray): ByteArray = plaintext.reversedArray()
                override suspend fun unwrap(blob: ByteArray): ByteArray = blob.reversedArray()
            }
        }
        val launched = mutableListOf<String>()
        val browser = object : versola.oauth.core.BrowserAuthorizationSession {
            override suspend fun authorize(uri: String): versola.oauth.core.BrowserOutcome {
                launched += uri
                val state = Regex("[?&]state=([^&]+)").find(uri)!!.groupValues[1]
                return versola.oauth.core.BrowserOutcome.Redirect(
                    "https://app.example.com/oauth?code=c&state=$state&iss=https%3A%2F%2Fid.example.com",
                )
            }
            override suspend fun awaitPendingRedirect(): versola.oauth.core.BrowserOutcome = throw UnsupportedOperationException()
        }
        val http = okhttp3.OkHttpClient.Builder().addInterceptor { chain ->
            val request = chain.request()
            val builder = okhttp3.Response.Builder().request(request).protocol(okhttp3.Protocol.HTTP_1_1).message("stub")
            if (request.url.encodedPath == "/.well-known/openid-configuration") {
                builder.code(200).body(
                    """{"issuer":"https://id.example.com","authorization_endpoint":"https://id.example.com/authorize",
                        "token_endpoint":"https://id.example.com/token","authorization_response_iss_parameter_supported":true}"""
                        .toResponseBody("application/json".toMediaType()),
                )
            } else {
                builder.code(429).header("Retry-After", "3600").body("".toResponseBody(null))
            }
            builder.build()
        }.build()
        val versola = Versola.configure(
            application, "https://id.example.com", "client-c4", "https://app.example.com/oauth", CollectingLogger(),
            httpClient = http, tokenBinding = TokenBinding.Bearer, browser = browser,
        )

        val first = runCatching { versola.login(setOf("openid")) }
        assertEquals("precondition: the first login opened the browser and was throttled at /token (${first.exceptionOrNull()})", 1, launched.size)
        org.robolectric.shadows.ShadowSystemClock.advanceBy(java.time.Duration.ofHours(2))
        runCatching { versola.login(setOf("openid")) }
        Versola.keyProviders = { HardwareKeyProvider() }

        assertEquals("the 1 h cooldown still held after 2 h of device time", 2, launched.size)
    }
}
