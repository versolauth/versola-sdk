package versola.oauth

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import mockwebserver3.Dispatcher
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Response
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import versola.oauth.core.SessionState
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaLogger

private val ids = AtomicInteger()

private class Warnings : VersolaLogger {
    val lines = CopyOnWriteArrayList<String>()
    override fun info(message: String) {
        lines += message
    }
    override fun warn(message: String) {
        lines += message
    }
}

/**
 * Audit tests for the generic facade's developer-experience findings D1, D3, D4, D5 and D10.
 * Each asserts the CORRECT behaviour and is expected to FAIL until the finding is fixed; the ones
 * marked "design" pick one of two reasonable outcomes and assert the proposed one.
 */
@RunWith(RobolectricTestRunner::class)
class AuditDeveloperExperienceTest {

    private val application = ApplicationProvider.getApplicationContext<Application>()
    private lateinit var server: MockWebServer
    private lateinit var provider: TestProvider
    private lateinit var browser: FakeBrowser
    private val requests = CopyOnWriteArrayList<RecordedRequest>()
    private var clientId = CLIENT_ID
    private val defaultResumeScope = OAuthClient.resumeScope

    @Before
    fun start() {
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                requests += request
                return when (request.url.encodedPath) {
                    "/.well-known/openid-configuration" -> provider.json(provider.discovery())
                    "/jwks" -> provider.json(provider.jwks())
                    "/token" -> provider.json(token())
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

    private fun token(): String {
        val idToken = provider.idToken(nonce = checkNotNull(browser.nonceSeen), audience = clientId)
        return """{"access_token":"at","token_type":"Bearer","expires_in":3600,"id_token":"$idToken","refresh_token":"rt"}"""
    }

    private fun configuration(
        redirectUri: String = REDIRECT_URI,
        logger: VersolaLogger = Warnings(),
        httpClient: OkHttpClient? = null,
        id: String = "audit-${ids.incrementAndGet()}",
    ): OAuthConfiguration {
        clientId = id
        return if (httpClient == null) {
            OAuthConfiguration(issuer = provider.issuer, clientId = id, redirectUri = redirectUri, logger = logger)
        } else {
            OAuthConfiguration(
                issuer = provider.issuer, clientId = id, redirectUri = redirectUri, logger = logger, httpClient = httpClient,
            )
        }
    }

    private fun create(configuration: OAuthConfiguration) =
        OAuthClient.create(application, configuration, browser = browser, keyProvider = ReversingKeyProvider)

    // AUDIT: D1 (design). A double-tapped login button is a user action, not a deployment
    // mistake; `Configuration` means "never catch in production" (spec/errors.md:14), so the
    // refusal must not be one.
    @Test
    fun `AUDIT D1 a second login while one is in progress is not a Configuration error`() = runTest {
        browser.hold = CompletableDeferred()
        val client = create(configuration())
        val first = async(start = CoroutineStart.UNDISPATCHED) { client.login() }
        browser.opened.await()
        assertTrue(client.sessionState.first() == SessionState.Authorizing)

        val error = runCatching { client.login() }.exceptionOrNull()

        browser.hold!!.complete(Unit)
        first.await()
        assertTrue("the second login() must be refused with a VersolaError, was: $error", error is VersolaError)
        assertFalse("a double tap must not be Configuration: $error", error is VersolaError.Configuration)
    }

    // AUDIT: D3. userInfo() with no session says Reauthenticate(GrantRejected), which is documented
    // as "the token endpoint said invalid_grant"; no token endpoint was asked. Expected: SessionExpired
    // or a dedicated no-session reason, still a Reauthenticate.
    @Test
    fun `AUDIT D3 userInfo without a session is Reauthenticate but not GrantRejected`() = runTest {
        val client = create(configuration())

        val error = runCatching { client.userInfo() }.exceptionOrNull()

        assertTrue("expected Reauthenticate, was $error", error is VersolaError.Reauthenticate)
        assertNotEquals(
            VersolaError.Reauthenticate.Reason.GrantRejected,
            (error as VersolaError.Reauthenticate).reason,
        )
        assertTrue("no token request may have been made", requests.none { it.url.encodedPath == "/token" })
    }

    // AUDIT: D4 (design). The registry fingerprint ignores the logger and the HTTP client, so a
    // second create() with another OkHttpClient silently returns the first client and the app's new
    // client (timeouts, certificate pinning, proxy) is never used. Proposed: refuse, like any other
    // configuration difference.
    @Test
    fun `AUDIT D4 create with a different httpClient for the same client id is not silently the first`() {
        val id = "audit-${ids.incrementAndGet()}"
        val first = create(configuration(id = id, httpClient = OkHttpClient()))
        val pinned = OkHttpClient.Builder().callTimeout(java.time.Duration.ofSeconds(3)).build()

        val second = runCatching { OAuthClient.create(application, configuration(id = id, httpClient = pinned)) }

        val error = second.exceptionOrNull()
        assertTrue(
            "a second create() with another httpClient returned the first client instead of failing",
            error is VersolaError.Configuration || (second.getOrNull()?.let { it !== first } == true),
        )
    }

    // AUDIT: D4 (design), logger half: same silent return for a different logger.
    @Test
    fun `AUDIT D4 create with a different logger for the same client id is not silently the first`() {
        val id = "audit-${ids.incrementAndGet()}"
        val first = create(configuration(id = id, logger = Warnings()))

        val second = runCatching { OAuthClient.create(application, configuration(id = id, logger = Warnings())) }

        assertTrue(
            "a second create() with another logger returned the first client instead of failing",
            second.exceptionOrNull() is VersolaError.Configuration || (second.getOrNull()?.let { it !== first } == true),
        )
    }

    // AUDIT: D4 (design). Application interceptors on the app-supplied OkHttpClient are cloned into
    // the SDK's own requests: a body-logging interceptor then prints the SDK's token and refresh
    // tokens. The SDK's token-endpoint traffic must not pass through them.
    @Test
    fun `AUDIT D4 token and refresh requests do not pass through application interceptors`() = runTest {
        val seen = CopyOnWriteArrayList<String>()
        val recording = Interceptor { chain ->
            seen += chain.request().url.encodedPath
            val response: Response = chain.proceed(chain.request())
            response
        }
        val client = create(configuration(httpClient = OkHttpClient.Builder().addInterceptor(recording).build()))

        client.login()
        client.refresh()

        assertTrue("the server saw /token (login + refresh)", requests.count { it.url.encodedPath == "/token" } == 2)
        assertFalse("an application interceptor saw the token endpoint: $seen", "/token" in seen)
    }

    // AUDIT: D5 (design). The https redirect URI resolves to no activity of this app (the SDK's
    // VersolaRedirectActivity carries no intent filter until the app adds one), and nothing at
    // create() says so: the login then hangs until the user gives up. Expected: a typed
    // Configuration error or an actionable warning through the injected logger.
    @Test
    fun `AUDIT D5 an https redirect URI that resolves to no activity is reported at create`() {
        val warnings = Warnings()

        val outcome = runCatching { create(configuration(redirectUri = "https://app.example.com/oauth", logger = warnings)) }

        val reported = outcome.exceptionOrNull() is VersolaError.Configuration ||
            warnings.lines.any { "VersolaRedirectActivity" in it || "intent filter" in it.lowercase() }
        assertTrue("no error and no warning about the missing redirect intent filter: ${warnings.lines}", reported)
    }

    // AUDIT: D5 (design), custom scheme: today's warning is only about scheme hijacking; it does
    // not tell the integrator the scheme resolves to nothing.
    @Test
    fun `AUDIT D5 a custom scheme redirect URI that resolves to no activity is reported at create`() {
        val warnings = Warnings()

        val outcome = runCatching { create(configuration(redirectUri = "com.example.app:/oauth", logger = warnings)) }

        val reported = outcome.exceptionOrNull() is VersolaError.Configuration ||
            warnings.lines.any { "VersolaRedirectActivity" in it || "intent filter" in it.lowercase() }
        assertTrue("no error and no warning about the missing redirect intent filter: ${warnings.lines}", reported)
    }

    // AUDIT: D10. The Kotlin facade has only a cold Flow; Swift has `sessionState` and Dart
    // `currentSessionState()`, so an Activity deciding between a login screen and a home screen at
    // onCreate cannot read the current value synchronously. Expected: a StateFlow, or a
    // `currentSessionState()`-style snapshot read.
    @Test
    fun `AUDIT D10 OAuthClient exposes a current session state snapshot`() {
        val type = OAuthClient::class.java.getMethod("getSessionState").returnType
        val snapshotNames = setOf("currentSessionState", "getCurrentSessionState", "sessionStateSnapshot", "getSessionStateSnapshot")

        val hasSnapshot = StateFlow::class.java.isAssignableFrom(type) ||
            OAuthClient::class.java.methods.any { it.name in snapshotNames }

        assertTrue("sessionState is a cold ${type.simpleName} and no snapshot read exists", hasSnapshot)
    }
}
