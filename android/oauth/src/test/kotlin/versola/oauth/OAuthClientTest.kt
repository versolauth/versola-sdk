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
import versola.oauth.core.TokenBinding
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
private class ColdStartBrowser(private val outcome: suspend () -> BrowserOutcome) : BrowserAuthorizationSession {
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

    private val realKeystore: java.security.Provider? = java.security.Security.getProvider("AndroidKeyStore")

    @After
    fun stop() {
        java.security.Security.removeProvider("AndroidKeyStore")
        realKeystore?.let { java.security.Security.insertProviderAt(it, 1) }
        OAuthClient.forgetAll()
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
        tokenBinding: TokenBinding = TokenBinding.Bearer,
    ) = OAuthConfiguration(
        issuer = if (endpoints == null) provider.issuer else null,
        endpoints = endpoints,
        clientId = clientId,
        redirectUri = REDIRECT_URI,
        postLogoutRedirectUri = "https://app.example.com/signed-out",
        scopes = scopes,
        protectedOrigins = protectedOrigins,
        pushedAuthorization = pushedAuthorization,
        tokenBinding = tokenBinding,
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
    fun `a redirect carrying another state is ignored in a cold-started process and the genuine one completes the sign-in`() = runTest {
        // Scenario 15, cold start: the redirect that started the process may be someone else's. It is
        // judged against the request the resume read, skipped, and what follows still answers.
        val killed = killedMidBrowser()
        tokenBody = { tokenResponse(refreshToken = true, nonce = killed.nonce) }
        val answers = ArrayDeque(listOf(redirectFor(killed, state = "forged"), redirectFor(killed)))
        val cold = ColdStartBrowser { answers.removeFirst() }

        val client = restartWith(killed, cold)

        client.sessionState.first { it == SessionState.Authenticated }
        assertEquals("the foreign redirect was stepped over and the next one answered", 2, cold.awaited)
        assertEquals("only the genuine redirect's code was exchanged", 1, requests.count { it.url.encodedPath == "/token" })
        assertEquals("alice", client.claims?.subject)
        val ignored = logger.warnings.filter { it.contains("not the response") }
        assertEquals(1, ignored.size)
        assertTrue("the line names no value of the redirect: $ignored", ignored.none { it.contains("forged") || it.contains(killed.state) })
    }

    @Test
    fun `a cold-started process handed only a redirect with another state keeps waiting with its request in place`() = runTest {
        val killed = killedMidBrowser()
        var calls = 0
        val waiting = kotlinx.coroutines.CompletableDeferred<Unit>()
        val cold = ColdStartBrowser {
            if (calls++ == 0) {
                redirectFor(killed, state = "forged")
            } else {
                waiting.complete(Unit)
                kotlinx.coroutines.awaitCancellation()
            }
        }

        val client = restartWith(killed, cold)
        waiting.await()

        assertEquals(2, cold.awaited)
        assertEquals(SessionState.Authorizing, client.sessionState.first())
        assertTrue(requests.none { it.url.encodedPath == "/token" })
        assertNull(client.claims)
        assertTrue("nothing failed", logger.warnings.none { it.contains("failed") })
        // That the request is still stored is the flow's own test (`clears` stays 0); a second client
        // here would start a second resume that outlives the test and holds the process-wide lock.
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

    // AUDIT: C4 - the coordinator's default elapsedMillis is System.nanoTime(), which stops in deep sleep;
    // OAuthClient wires only retryClock to elapsedRealtime. The cache must age with the device's real time.
    @Test
    fun `AUDIT C4 a cached access token ages with elapsedRealtime, so it is refreshed after the device slept past its lifetime`() = runTest {
        val client = client()
        client.login()
        assertEquals(1, requests.count { it.url.encodedPath == "/token" })
        assertEquals("at", client.accessToken().value)
        assertEquals("a fresh token is served from memory", 1, requests.count { it.url.encodedPath == "/token" })

        // Two hours of deep sleep: elapsedRealtime moves, a monotonic uptime clock does not.
        val nanoBefore = System.nanoTime()
        org.robolectric.shadows.ShadowSystemClock.advanceBy(java.time.Duration.ofHours(2))
        val nanoMovedMillis = (System.nanoTime() - nanoBefore) / 1_000_000
        assertTrue("precondition: System.nanoTime must not follow the shadowed clock (moved ${nanoMovedMillis}ms)", nanoMovedMillis < 60_000)
        tokenBody = { tokenResponse(refreshToken = true, nonce = null).replace("\"at\"", "\"at-2\"") }
        client.accessToken()

        assertEquals("the 1 h token was served after 2 h of device time", 2, requests.count { it.url.encodedPath == "/token" })
    }

    // AUDIT: C5 - the default client has connect and read timeouts only: no overall deadline on a call.
    @Test
    fun `AUDIT C5 the default HTTP client has an overall call timeout`() {
        val timeout = configuration().httpClient.callTimeoutMillis

        assertTrue("callTimeoutMillis is $timeout; a slow-drip response can hold a call forever", timeout in 1..60_000)
    }

    // AUDIT: C8 - a login whose caller was cancelled leaves its slot 'for resume', but only a cold-start
    // restore ever triggers the resume. The redirect that arrives afterwards must not be silently discarded.
    @Test
    fun `AUDIT C8 the redirect of a login whose caller was cancelled is consumed, not discarded`() = runTest {
        OAuthClient.resumeScope = backgroundScope
        val redirectArrives = CompletableDeferred<BrowserOutcome>()
        val opened = CompletableDeferred<String>()
        val live = FakeBrowser(provider.issuer)
        val awaitingBrowser = object : BrowserAuthorizationSession by live {
            override suspend fun authorize(uri: String, options: versola.oauth.core.BrowserSessionOptions): BrowserOutcome = authorize(uri)
            override suspend fun authorize(uri: String): BrowserOutcome {
                opened.complete(uri)
                kotlinx.coroutines.awaitCancellation()
            }
            // What the redirect activity buffered while no login awaited it.
            override suspend fun awaitPendingRedirect(): BrowserOutcome = redirectArrives.await()
        }
        val configuration = configuration()
        val client = OAuthClient.create(application, configuration, browser = awaitingBrowser, keyProvider = ReversingKeyProvider)
        val login = async(start = CoroutineStart.UNDISPATCHED) { runCatching { client.login() } }
        val query = opened.await().substringAfter('?').split('&').associate { it.substringBefore('=') to it.substringAfter('=') }
        login.cancelAndJoin()
        tokenBody = { tokenResponse(refreshToken = true, nonce = query.getValue("nonce")) }

        // The user finished signing in in the tab the cancelled login opened.
        redirectArrives.complete(
            BrowserOutcome.Redirect(
                "$REDIRECT_URI?code=the-code&state=${query.getValue("state")}&iss=${java.net.URLEncoder.encode(provider.issuer, "UTF-8")}",
            ),
        )
        val state = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Default) {
            kotlinx.coroutines.withTimeoutOrNull(5_000) { client.sessionState.first { it != SessionState.Authorizing } }
        }

        assertEquals("nothing consumed the redirect: the client is still Authorizing", SessionState.Authenticated, state)
    }

    // --- audit regressions (Z-series): each asserts the correct behaviour and fails on today's code ---

    private fun installKeystore(): SharedNamespaceAndroidKeyStore = SharedNamespaceAndroidKeyStore().also {
        java.security.Security.removeProvider("AndroidKeyStore")
        java.security.Security.insertProviderAt(it, 1)
    }

    /** A provider that advertises ES256 DPoP proofs: without it the SDK sends no proof at all. */
    private fun advertiseDpop() {
        discoveryBody = { provider.discovery().replace("\"code_challenge_methods_supported\"", "\"dpop_signing_alg_values_supported\":[\"ES256\"],\"code_challenge_methods_supported\"") }
        tokenBody = { dpopTokenBody() }
    }

    private fun dpopTokenBody() = tokenResponse(refreshToken = true).replace("\"token_type\":\"Bearer\"", "\"token_type\":\"DPoP\"")

    private val refreshedBody = """{"access_token":"at2","token_type":"DPoP","expires_in":3600,"refresh_token":"rt2"}"""

    private fun jwkOf(proof: String): String =
        String(java.util.Base64.getUrlDecoder().decode(proof.substringBefore('.'))).substringAfter("\"jwk\":").substringBefore('}')

    @Test
    fun `AUDIT Z1 the storage key and the DPoP key are never generated under one Keystore alias`() = runTest {
        // AUDIT: Z1 (HIGH). build() gives HardwareKeyProvider and KeystoreDpopKey the same alias
        // "versola-oauth-<storageKey>"; the AndroidKeyStore alias namespace is shared by every key
        // type and a generate under an existing alias replaces the entry, so each key destroys the other.
        val keystore = installKeystore()
        advertiseDpop()
        val client = OAuthClient.create(application, configuration(tokenBinding = TokenBinding.Dpop()), browser = browser)

        client.login()

        assertEquals("an alias was reused by the other key type: ${keystore.overwrites}", emptyList<String>(), keystore.overwrites)
        assertEquals("one AES storage key and one EC DPoP key, under two aliases", 2, keystore.generated.size)
    }

    @Test
    fun `AUDIT Z1 a DPoP session survives a process restart with its refresh token readable and its jkt unchanged`() = runTest {
        val keystore = installKeystore()
        advertiseDpop()
        val configuration = configuration(tokenBinding = TokenBinding.Dpop())
        OAuthClient.create(application, configuration, browser = browser).login()
        val jwkAtLogin = jwkOf(requests.last { it.url.encodedPath == "/token" }.headers["DPoP"]!!)
        tokenBody = { refreshedBody }

        // Process restart: new client objects, same files, same Keystore.
        OAuthClient.forgetAll()
        val restarted = OAuthClient.create(application, configuration, browser = browser)
        val outcome = runCatching { restarted.refresh() }

        assertTrue("the stored refresh token must still decrypt after a restart, got ${outcome.exceptionOrNull()} (overwrites: ${keystore.overwrites})", outcome.isSuccess)
        val refresh = requests.last { it.url.encodedPath == "/token" }
        assertTrue(refresh.body!!.utf8().contains("refresh_token=rt"))
        assertEquals("the proof key must be the one the grant was bound to", jwkAtLogin, jwkOf(refresh.headers["DPoP"]!!))
        assertEquals(SessionState.Authenticated, restarted.sessionState.first())
    }

    @Test
    fun `AUDIT Z11 a DPoP key that vanished from the Keystore is a typed re-authentication, not a new key under the same grant`() = runTest {
        // AUDIT: Z11 (PLAUSIBLE / design). The grant does not carry its jkt, so KeystoreDpopKey
        // regenerates silently when the entry is gone and key loss shows only as a server rejection.
        // The storage key is substituted here so the Z1 alias collision cannot be what ends the session.
        val keystore = installKeystore()
        advertiseDpop()
        val configuration = configuration(tokenBinding = TokenBinding.Dpop())
        client(configuration).login()
        val tokenRequestsAtLogin = requests.count { it.url.encodedPath == "/token" }
        keystore.generated.clear()
        tokenBody = { refreshedBody }

        OAuthClient.forgetAll()
        val restarted = client(configuration)
        val error = runCatching { restarted.refresh() }.exceptionOrNull()

        assertTrue("expected a typed Reauthenticate, got $error", error is VersolaError.Reauthenticate)
        assertEquals("no token request may be signed by a freshly minted key", tokenRequestsAtLogin, requests.count { it.url.encodedPath == "/token" })
    }

}
