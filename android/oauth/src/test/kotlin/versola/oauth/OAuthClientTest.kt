package versola.oauth

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import mockwebserver3.Dispatcher
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import okhttp3.Request
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import versola.oauth.core.IdTokenRejection
import versola.oauth.core.PushedAuthorization
import versola.oauth.core.SessionState
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaLogger

private val counter = AtomicInteger()

private class RecordingLogger : VersolaLogger {
    val warnings = mutableListOf<String>()
    override fun info(message: String) {}
    override fun warn(message: String) {
        warnings += message
    }
}

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class OAuthClientTest {

    private val application = ApplicationProvider.getApplicationContext<Application>()
    private lateinit var server: MockWebServer
    private lateinit var provider: TestProvider
    private lateinit var browser: FakeBrowser
    private val logger = RecordingLogger()
    private val requests = mutableListOf<RecordedRequest>()

    /** What the provider answers; a test overrides single paths. */
    private var tokenBody: () -> String = { tokenResponse(refreshToken = true) }
    private var userInfoBody: () -> String = { """{"sub":"alice","name":"Alice"}""" }
    private var discoveryBody: () -> String = { provider.discovery() }

    @Before
    fun start() {
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                requests += request
                return when (request.url.encodedPath) {
                    "/.well-known/openid-configuration" -> provider.json(discoveryBody())
                    "/jwks" -> provider.json(provider.jwks())
                    "/token" -> provider.json(tokenBody())
                    "/userinfo" -> provider.json(userInfoBody())
                    "/revoke" -> MockResponse.Builder().code(200).build()
                    "/api" -> MockResponse.Builder().code(200).body("ok").build()
                    else -> MockResponse.Builder().code(404).build()
                }
            }
        }
        server.start()
        provider = TestProvider(server)
        browser = FakeBrowser(provider.issuer)
    }

    @After
    fun stop() {
        server.close()
    }

    /** The client id of the configuration under test: the ID token's audience. */
    private var clientId: String = CLIENT_ID

    private fun tokenResponse(refreshToken: Boolean, nonce: String? = null, subject: String = "alice"): String {
        val idToken = provider.idToken(nonce = nonce ?: checkNotNull(browser.nonceSeen), subject = subject, audience = clientId)
        return buildString {
            append("""{"access_token":"at","token_type":"Bearer","expires_in":3600,"id_token":"$idToken"""")
            if (refreshToken) append(""","refresh_token":"rt"""")
            append("}")
        }
    }

    private fun configuration(
        clientId: String = "client-${counter.incrementAndGet()}",
        endpoints: ProviderEndpoints? = null,
        protectedOrigins: Set<String> = emptySet(),
        scopes: Set<String> = setOf("openid"),
        pushedAuthorization: PushedAuthorization = PushedAuthorization.Never,
    ) = OAuthConfiguration(
        issuer = if (endpoints == null) provider.issuer else null,
        endpoints = endpoints,
        clientId = clientId,
        redirectUri = REDIRECT_URI,
        postLogoutRedirectUri = "https://app.example.com/signed-out",
        scopes = scopes,
        protectedOrigins = protectedOrigins,
        pushedAuthorization = pushedAuthorization,
        logger = logger,
    ).also { this.clientId = clientId }

    private fun client(configuration: OAuthConfiguration = configuration()) =
        OAuthClient.create(application, configuration, browser = browser, keyProvider = ReversingKeyProvider)

    @Test
    fun `create does no network and returns one instance per issuer and client id`() {
        val configuration = configuration()
        val first = client(configuration)
        val second = OAuthClient.create(application, configuration)

        assertSame(first, second)
        assertTrue(requests.isEmpty())
        // The same issuer and client id with a different configuration is refused rather than
        // silently answered with the first one.
        val other = OAuthConfiguration(issuer = provider.issuer, clientId = configuration.clientId, redirectUri = REDIRECT_URI, scopes = setOf("profile"))
        val error = org.junit.Assert.assertThrows(VersolaError.Configuration::class.java) { OAuthClient.create(application, other) }
        assertTrue(error.detail is VersolaError.Configuration.Detail.InvalidConfiguration)
    }

    @Test
    fun `login sends a plain public-client request, validates the ID token and persists the grant`() = runTest {
        val client = client()

        client.login()

        assertEquals(SessionState.Authenticated, client.sessionState.first())
        assertEquals("alice", client.claims?.subject)
        assertEquals(provider.issuer, client.claims?.issuer)
        assertEquals("at", client.accessToken().value)
        // The authorization request: code + S256, the configured scopes and nothing the SDK
        // was not asked for; no offline_access slipped in.
        val authorize = browser.launched.single()
        assertTrue(authorize.startsWith("${provider.issuer}/authorize?"))
        assertTrue(authorize.contains("response_type=code"))
        assertTrue(authorize.contains("code_challenge_method=S256"))
        assertTrue(authorize.contains("scope=openid"))
        assertFalse(authorize.contains("offline_access"))
        // The token request: a public client, the verifier, no secret, nothing non-standard.
        val token = requests.single { it.url.encodedPath == "/token" }
        val body = token.body!!.utf8()
        assertTrue(body.contains("grant_type=authorization_code"))
        assertTrue(body.contains("code_verifier="))
        assertTrue(body.contains("client_id="))
        assertFalse(body.contains("client_secret"))
        assertNull(token.headers["Idempotency-Key"])
        // Discovery and the JWKS were fetched once each, before Authenticated was published.
        assertEquals(1, requests.count { it.url.encodedPath == "/.well-known/openid-configuration" })
        assertEquals(1, requests.count { it.url.encodedPath == "/jwks" })
    }

    @Test
    fun `an ID token with the wrong nonce is refused before anything is persisted`() = runTest {
        tokenBody = { tokenResponse(refreshToken = true, nonce = "not-the-one") }
        val client = client()

        val error = runCatching { client.login() }.exceptionOrNull() as VersolaError.Configuration

        val detail = error.detail as VersolaError.Configuration.Detail.IdTokenRejected
        assertEquals(IdTokenRejection.Nonce, detail.reason)
        assertNull(client.claims)
        assertEquals(SessionState.Unauthenticated, client.sessionState.first())
        assertTrue(runCatching { client.accessToken() }.exceptionOrNull() is VersolaError.Reauthenticate)
        assertTrue(requests.none { it.url.encodedPath == "/userinfo" })
    }

    @Test
    fun `the authenticated client attaches the token to protected origins only`() = runTest {
        val other = MockWebServer().apply {
            dispatcher = object : Dispatcher() {
                override fun dispatch(request: RecordedRequest): MockResponse = MockResponse.Builder().code(200).build()
            }
            start()
        }
        try {
            val client = client(configuration(protectedOrigins = setOf(provider.issuer)))
            client.login()

            client.call(Request.Builder().url("${provider.issuer}/api").build()).close()
            client.call(Request.Builder().url(other.url("/elsewhere")).build()).close()

            assertEquals("Bearer at", requests.single { it.url.encodedPath == "/api" }.headers["Authorization"])
            assertNull(other.takeRequest().headers["Authorization"])
        } finally {
            other.close()
        }
    }

    @Test
    fun `userinfo must be about the user the ID token names`() = runTest {
        val client = client()
        client.login()

        assertEquals("alice", client.userInfo().subject)

        userInfoBody = { """{"sub":"bob"}""" }
        val error = runCatching { client.userInfo() }.exceptionOrNull() as VersolaError.Configuration
        assertTrue(error.detail is VersolaError.Configuration.Detail.UserInfoRejected)
    }

    @Test
    fun `logout revokes, ends the server session and wipes, and says what the server did`() = runTest {
        val client = client()
        client.login()

        val outcome = client.logout()

        assertTrue(outcome.tokenRevoked)
        assertTrue(outcome.sessionEnded)
        assertEquals(SessionState.Unauthenticated, client.sessionState.first())
        assertNull(client.claims)
        val revoke = requests.single { it.url.encodedPath == "/revoke" }
        assertTrue(revoke.body!!.utf8().contains("token=rt"))
        val endSession = browser.launched.last()
        assertTrue(endSession.startsWith("${provider.issuer}/logout?"))
        assertTrue(endSession.contains("id_token_hint="))
        assertTrue(endSession.contains("post_logout_redirect_uri="))
    }

    @Test
    fun `without an end_session_endpoint logout revokes and wipes and reports the session not ended`() = runTest {
        discoveryBody = { provider.discovery(endSession = false) }
        val client = client()
        client.login()

        val outcome = client.logout()

        assertTrue(outcome.tokenRevoked)
        assertFalse(outcome.sessionEnded)
        assertEquals(1, browser.launched.size)
        assertEquals(SessionState.Unauthenticated, client.sessionState.first())
    }

    @Test
    fun `explicit endpoints make no well-known request`() = runTest {
        val endpoints = ProviderEndpoints(
            issuer = provider.issuer,
            authorizationEndpoint = "${provider.issuer}/authorize",
            tokenEndpoint = "${provider.issuer}/token",
            jwksUri = "${provider.issuer}/jwks",
            revocationEndpoint = "${provider.issuer}/revoke",
        )
        val client = client(configuration(endpoints = endpoints))

        client.login()
        val outcome = client.logout()

        assertTrue(requests.none { it.url.encodedPath.contains("well-known") })
        assertTrue(outcome.tokenRevoked)
        assertFalse(outcome.sessionEnded)
    }

    @Test
    fun `a session without a refresh token is held in memory and warned about`() = runTest {
        tokenBody = { tokenResponse(refreshToken = false) }
        val client = client()

        client.login()

        assertEquals(SessionState.Authenticated, client.sessionState.first())
        assertEquals("at", client.accessToken().value)
        assertEquals("alice", client.claims?.subject)
        assertTrue(logger.warnings.any { it.contains("no refresh token") })
        val outcome = client.logout()
        assertFalse(outcome.tokenRevoked)
        assertTrue(browser.launched.last().contains("id_token_hint="))
    }
}
