package versola.oauth

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
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
import versola.oauth.core.BrowserAuthorizationSession
import versola.oauth.core.BrowserOutcome
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

/**
 * The browser of a process the redirect cold-started: nothing is opened, and what the OS
 * delivered is waiting in [outcome]. [awaited] counts how often the SDK asked for it.
 */
private class ColdStartBrowser(private val outcome: () -> BrowserOutcome) : BrowserAuthorizationSession {
    var awaited = 0

    override suspend fun authorize(uri: String): BrowserOutcome = throw AssertionError("a cold-started process opens no browser")

    override suspend fun awaitPendingRedirect(): BrowserOutcome {
        awaited++
        return outcome()
    }
}

@RunWith(RobolectricTestRunner::class)
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
        OAuthClient.resumeScope = defaultResumeScope
        server.close()
    }

    private val defaultResumeScope = OAuthClient.resumeScope

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
    fun `the ID token's iss is held to the issuer discovery announces, trailing slash included`() = runTest {
        // Auth0 announces `https://tenant/` and signs tokens with that `iss`; the configured
        // issuer has no slash. Discovery tolerates the one slash; the ID token, and the redirect's
        // RFC 9207 `iss`, must match what discovery said, not what was configured.
        provider.announcedIssuer = provider.issuer + "/"
        browser = FakeBrowser(provider.issuer + "/")
        val client = client()

        client.login()

        assertEquals(provider.issuer + "/", client.claims?.issuer)
        assertEquals(SessionState.Authenticated, client.sessionState.first())
    }

    @Test
    fun `a redirect iss that differs from the announced issuer by the trailing slash is refused`() = runTest {
        provider.announcedIssuer = provider.issuer + "/"
        browser = FakeBrowser(provider.issuer)
        val client = client()

        val error = runCatching { client.login() }.exceptionOrNull() as VersolaError.Configuration

        assertEquals(VersolaError.Configuration.Detail.IssuerMismatch(provider.issuer + "/", provider.issuer), error.detail)
        assertEquals(SessionState.Unauthenticated, client.sessionState.first())
    }

    @Test
    fun `a login whose caller was cancelled does not block the next one, though the state still reads Authorizing`() = runTest {
        browser.hold = kotlinx.coroutines.CompletableDeferred()
        val client = client()
        val first = async(start = CoroutineStart.UNDISPATCHED) { runCatching { client.login() } }
        browser.opened.await()
        first.cancelAndJoin()
        assertEquals("the slot is kept for a resume", SessionState.Authorizing, client.sessionState.first())

        // Nothing awaits that slot, so it is a leftover and the new login supersedes it at once.
        browser.hold = null
        client.login()

        assertEquals(SessionState.Authenticated, client.sessionState.first())
    }

    @Test
    fun `ephemeralBrowser reaches the browser session and is off by default`() = runTest {
        val client = client()

        client.login()
        client.login(LoginOptions(ephemeralBrowser = true))

        assertEquals(listOf(false, true), browser.options.map { it.ephemeral })
        assertEquals(REDIRECT_URI, browser.options.last().redirectUri)
    }

    @Test
    fun `login while an authorization is outstanding is refused, not queued`() = runTest {
        browser.hold = kotlinx.coroutines.CompletableDeferred()
        val client = client()
        val first = async(start = CoroutineStart.UNDISPATCHED) { client.login() }
        // Discovery runs first, off this thread; the state is Authorizing once the browser opened.
        browser.opened.await()
        assertEquals(SessionState.Authorizing, client.sessionState.first())

        val error = runCatching { client.login() }.exceptionOrNull() as VersolaError.Configuration

        assertTrue(error.detail is VersolaError.Configuration.Detail.InvalidConfiguration)
        assertEquals(1, browser.launched.size)
        browser.hold!!.complete(Unit)
        first.await()
        assertEquals(SessionState.Authenticated, client.sessionState.first())
    }

    @Test
    fun `two configurations built separately with the same values are one client`() {
        val id = "client-${counter.incrementAndGet()}"
        fun built() = OAuthConfiguration(
            issuer = provider.issuer, clientId = id, redirectUri = REDIRECT_URI,
            retryPolicy = versola.oauth.core.RetryPolicy(maxAttemptsPerOrigin = 2),
        )

        val first = OAuthClient.create(application, built(), browser = browser, keyProvider = ReversingKeyProvider)
        val second = OAuthClient.create(application, built())

        assertSame(first, second)
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

    // ---- a redirect delivered to a cold-started process (scenario 12) ------------------------

    private class KilledLogin(val configuration: OAuthConfiguration, val state: String, val nonce: String)

    /**
     * A login that opened the browser and then lost its process: the pending request is on disk,
     * no caller is left, and the singleton registry of the dead process is gone.
     */
    private suspend fun kotlinx.coroutines.test.TestScope.killedMidBrowser(): KilledLogin {
        val configuration = configuration()
        browser.hold = CompletableDeferred()
        val login = async(start = CoroutineStart.UNDISPATCHED) { runCatching { client(configuration).login() } }
        browser.opened.await()
        val query = browser.launched.single().substringAfter('?').split('&').associate { it.substringBefore('=') to it.substringAfter('=') }
        login.cancelAndJoin()
        OAuthClient.forgetAll()
        return KilledLogin(configuration, query.getValue("state"), query.getValue("nonce"))
    }

    private fun redirectFor(killed: KilledLogin, state: String = killed.state, iss: String = provider.issuer) =
        BrowserOutcome.Redirect("$REDIRECT_URI?code=the-code&state=$state&iss=${java.net.URLEncoder.encode(iss, "UTF-8")}")

    private fun kotlinx.coroutines.test.TestScope.restartWith(killed: KilledLogin, cold: ColdStartBrowser): OAuthClient {
        OAuthClient.resumeScope = backgroundScope
        return OAuthClient.create(application, killed.configuration, browser = cold, keyProvider = ReversingKeyProvider)
    }

    @Test
    fun `a login pre-empts the cold-start resume that waits for a redirect which is not coming`() = runTest {
        val killed = killedMidBrowser()
        // The process restarts into Authorizing and its resume waits; the user comes back to the app
        // itself, not through the redirect, and signs in again.
        val live = FakeBrowser(provider.issuer)
        browser = live
        val resuming = object : BrowserAuthorizationSession by live {
            override suspend fun awaitPendingRedirect(): BrowserOutcome = kotlinx.coroutines.awaitCancellation()
        }
        OAuthClient.resumeScope = backgroundScope
        val client = OAuthClient.create(application, killed.configuration, browser = resuming, keyProvider = ReversingKeyProvider)
        assertEquals(SessionState.Authorizing, client.sessionState.first())
        kotlinx.coroutines.yield()

        client.login()

        assertEquals(SessionState.Authenticated, client.sessionState.first())
    }

    @Test
    fun `a redirect delivered to a cold-started process completes the sign-in on its own`() = runTest {
        val killed = killedMidBrowser()
        tokenBody = { tokenResponse(refreshToken = true, nonce = killed.nonce) }
        val cold = ColdStartBrowser { redirectFor(killed) }

        val client = restartWith(killed, cold)

        // Nothing is called: the app only observes. Authorizing first, never Unauthenticated.
        val states = mutableListOf<SessionState>()
        client.sessionState.first { it.also(states::add) == SessionState.Authenticated }
        assertEquals(SessionState.Authorizing, states.first())
        assertFalse(SessionState.Unauthenticated in states)
        assertEquals("alice", client.claims?.subject)
        assertEquals("at", client.accessToken().value)
        assertEquals(1, cold.awaited)
        // The restored verifier produced the exchange, and the code was spent once.
        assertEquals(1, requests.count { it.url.encodedPath == "/token" })
        assertTrue(requests.single { it.url.encodedPath == "/token" }.body!!.utf8().contains("code_verifier="))
        // Persisted: a third process restores a session without the browser.
        OAuthClient.forgetAll()
        assertEquals(SessionState.Authenticated, client(killed.configuration).sessionState.first())
    }

    @Test
    fun `a cold-started process with nothing pending waits for no redirect`() = runTest {
        val configuration = configuration()
        val cold = ColdStartBrowser { throw AssertionError("nothing to wait for") }
        OAuthClient.resumeScope = backgroundScope

        val client = OAuthClient.create(application, configuration, browser = cold, keyProvider = ReversingKeyProvider)

        assertEquals(SessionState.Unauthenticated, client.sessionState.first())
        testScheduler.advanceUntilIdle()
        assertEquals(0, cold.awaited)
        assertTrue(requests.isEmpty())
    }

    @Test
    fun `a redirect carrying another state is refused in a cold-started process before any token request`() = runTest {
        val killed = killedMidBrowser()
        val cold = ColdStartBrowser { redirectFor(killed, state = "forged") }

        val client = restartWith(killed, cold)

        assertEquals(SessionState.Unauthenticated, client.sessionState.first { it != SessionState.Authorizing })
        assertTrue(requests.none { it.url.encodedPath == "/token" })
        assertNull(client.claims)
        assertTrue(logger.warnings.any { it.contains("StateMismatch") })
        // The failed request is gone: a cold start after this one reports nothing pending.
        OAuthClient.forgetAll()
        assertEquals(SessionState.Unauthenticated, client(killed.configuration).sessionState.first())
    }

    @Test
    fun `a redirect from another issuer is refused in a cold-started process before any token request`() = runTest {
        val killed = killedMidBrowser()
        val cold = ColdStartBrowser { redirectFor(killed, iss = "https://evil.example.com") }

        val client = restartWith(killed, cold)

        assertEquals(SessionState.Unauthenticated, client.sessionState.first { it != SessionState.Authorizing })
        assertTrue(requests.none { it.url.encodedPath == "/token" })
        assertTrue(logger.warnings.any { it.contains("IssuerMismatch") })
    }

    @Test
    fun `an ID token with the wrong nonce is refused in a cold-started process and nothing is persisted`() = runTest {
        val killed = killedMidBrowser()
        tokenBody = { tokenResponse(refreshToken = true, nonce = "not-the-one") }
        val cold = ColdStartBrowser { redirectFor(killed) }

        val client = restartWith(killed, cold)

        assertEquals(SessionState.Unauthenticated, client.sessionState.first { it != SessionState.Authorizing })
        assertNull(client.claims)
        assertTrue(runCatching { client.accessToken() }.exceptionOrNull() is VersolaError.Reauthenticate)
        OAuthClient.forgetAll()
        assertEquals(SessionState.Unauthenticated, client(killed.configuration).sessionState.first())
    }
}
