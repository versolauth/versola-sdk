package versola.oauth.core

import java.io.File
import java.time.Instant
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.test.runTest
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Audit tests for the developer-experience findings D1, D2, D7 and D12. Every test asserts the
 * CORRECT behaviour and is expected to FAIL until the finding is fixed; the ones marked "design"
 * assert one of two reasonable outcomes (the proposed one).
 */
class AuditDeveloperExperienceTest {

    @get:Rule
    val folder: TemporaryFolder = TemporaryFolder()

    private lateinit var server: MockWebServer
    private lateinit var issuer: String

    @Before
    fun start() {
        server = MockWebServer()
        server.start()
        issuer = server.url("/").toString().trimEnd('/')
    }

    @After
    fun stop() {
        server.close()
    }

    private fun html(code: Int = 200) = MockResponse.Builder()
        .code(code)
        .setHeader("Content-Type", "text/html; charset=utf-8")
        .body("<html><body>Sign in to the airport Wi-Fi</body></html>")
        .build()

    // AUDIT: D1 (decided 2026-11-02). A captive portal answering the discovery request with a 200
    // HTML page stays `Configuration(DiscoveryMalformed)`: the document is not the provider's, which
    // the app cannot fix by retrying, and the portal's page is not echoed into the error.
    @Test
    fun `AUDIT D1 discovery answered with HTML 200 by a captive portal is Configuration and does not echo the page`() = runTest {
        server.enqueue(html())

        val error = failure { HttpDiscoveryClient(OkHttpClient()).fetch(issuer) }

        assertTrue("captive-portal HTML is DiscoveryMalformed: $error", error is VersolaError.Configuration &&
            error.detail is VersolaError.Configuration.Detail.DiscoveryMalformed)
        assertFalse("the portal's page must not be echoed: $error", error.toString().contains("airport"))
    }

    // AUDIT: D1 (decided 2026-11-02). A redirect is never followed, so a 302 to a portal login page
    // is `Configuration(InvalidConfiguration)` naming the status, not a followed request.
    @Test
    fun `AUDIT D1 discovery answered with a 302 by a captive portal is not followed and is Configuration`() = runTest {
        server.enqueue(
            MockResponse.Builder().code(302).setHeader("Location", "http://portal.example.com/login").build(),
        )
        val client = HttpDiscoveryClient(OkHttpClient.Builder().followRedirects(false).build())

        val error = failure { client.fetch(issuer) }

        assertTrue("a redirect is Configuration, not followed: $error", error is VersolaError.Configuration &&
            error.detail is VersolaError.Configuration.Detail.InvalidConfiguration)
        assertEquals("the redirect target was never asked", 1, server.requestCount)
    }

    // AUDIT: D1 (decided 2026-11-02). The token endpoint behind a captive portal answers 200
    // text/html: `Configuration(TokenResponseMalformed)`, and the page is not echoed.
    @Test
    fun `AUDIT D1 token endpoint answered with HTML 200 is TokenResponseMalformed and does not echo the page`() = runTest {
        server.enqueue(html())
        val metadata = ProviderMetadata(
            issuer = issuer,
            authorizationEndpoint = "$issuer/authorize",
            tokenEndpoint = "$issuer/token",
        )
        val client = HttpTokenClient(
            configuration = VersolaConfiguration.create(
                issuer = "https://id.example.com",
                clientId = "mobile-app",
                redirectUri = "https://app.example.com/oauth",
            ),
            discovery = DiscoveryService(
                issuer = issuer,
                client = object : DiscoveryClient {
                    override suspend fun fetch(issuer: String): ProviderMetadata = metadata
                },
                cache = FileProviderMetadataCache(File(folder.newFolder(), "metadata.json")),
            ),
            httpClient = OkHttpClient(),
            dpop = null,
            tokenBinding = TokenBinding.Bearer,
        )
        val grant = AuthorizationGrant(
            code = "the-code",
            codeVerifier = CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            redirectUri = "https://app.example.com/oauth",
            nonce = "the-nonce",
            scopes = setOf("openid"),
        )

        val error = failure { client.exchange(grant) }

        assertTrue("an HTML token response is TokenResponseMalformed: $error", error is VersolaError.Configuration &&
            error.detail is VersolaError.Configuration.Detail.TokenResponseMalformed)
        assertFalse("the portal's page must not be echoed: $error", error.toString().contains("airport"))
    }

    private fun oneOfEach(): Map<String, VersolaError> = mapOf(
        "network" to VersolaError.Recoverable(VersolaError.Recoverable.Cause.Network("x")),
        "server" to VersolaError.Recoverable(VersolaError.Recoverable.Cause.Server(503)),
        "user-cancelled" to VersolaError.Recoverable(VersolaError.Recoverable.Cause.UserCancelled),
        "system-cancelled" to VersolaError.Recoverable(VersolaError.Recoverable.Cause.SystemCancelled),
        "pending-expired" to VersolaError.Recoverable(VersolaError.Recoverable.Cause.PendingRequestExpired),
        "unlock" to VersolaError.Recoverable(VersolaError.Recoverable.Cause.UnlockRequired),
        "nonce-loop" to VersolaError.Recoverable(VersolaError.Recoverable.Cause.NonceLoop("https://a.example.com")),
        "denied" to VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.AuthorizationDenied),
        "grant-rejected" to VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.GrantRejected),
        "session-rejected" to VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.SessionRejected),
        "session-expired" to VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.SessionExpired),
        "step-up" to VersolaError.StepUp(listOf("c2"), null),
        "state-mismatch" to VersolaError.Configuration(VersolaError.Configuration.Detail.StateMismatch),
        "no-browser" to VersolaError.Configuration(VersolaError.Configuration.Detail.NoBrowserAvailable),
        "invalid-config" to VersolaError.Configuration(VersolaError.Configuration.Detail.InvalidConfiguration("x")),
        "id-token-nonce" to VersolaError.Configuration(VersolaError.Configuration.Detail.IdTokenRejected(IdTokenRejection.Nonce)),
    )

    // AUDIT: D2 (design). An app cannot log or branch on an error by a stable machine-readable
    // string: today only the data-class toString identifies a case. Reflection keeps this
    // compiling before `code` exists.
    @Test
    fun `AUDIT D2 every VersolaError exposes a stable non-empty code`() {
        val codes = oneOfEach().mapValues { (name, error) ->
            val getter = error.javaClass.methods.firstOrNull { it.name == "getCode" && it.parameterCount == 0 }
            assertTrue("$name: VersolaError has no `code: String` property", getter != null)
            getter!!.invoke(error) as? String
        }
        codes.forEach { (name, code) -> assertTrue("$name: code must be a non-empty string", !code.isNullOrEmpty()) }
        assertEquals("codes must be unique per case: $codes", codes.size, codes.values.toSet().size)
    }

    // AUDIT: D2 (design), second half: the same case yields the same code every time (stable).
    @Test
    fun `AUDIT D2 the code does not depend on the case's payload`() {
        fun code(error: VersolaError): String? =
            error.javaClass.methods.firstOrNull { it.name == "getCode" && it.parameterCount == 0 }?.invoke(error) as? String

        val a = code(VersolaError.Recoverable(VersolaError.Recoverable.Cause.Network("timeout A", attempts = 1)))
        val b = code(VersolaError.Recoverable(VersolaError.Recoverable.Cause.Network("timeout B", attempts = 5)))

        assertTrue("no `code` property", a != null)
        assertEquals(a, b)
    }

    // AUDIT: D7. spec/oauth-sdk-api.md:67 says clockSkewTolerance applies to `nbf`; JWT (RFC 7519
    // 4.1.5) says a token must not be accepted before nbf. A token valid only from an hour in
    // the future is outside any 60 s tolerance and must be rejected.
    @Test
    fun `AUDIT D7 an ID token whose nbf is in the future beyond the skew is rejected`() = runTest {
        val now: Instant = Instant.ofEpochSecond(1_900_000_000)
        val clientId = "client-1"
        val issuerUrl = "https://issuer.example.com"
        server.enqueue(
            MockResponse.Builder().code(200).body(Jose.jwks(Jose.jwk(Jose.rsa, "rsa"))).build(),
        )
        val validator = JwksIdTokenValidator(
            issuer = { issuerUrl },
            clientId = clientId,
            jwksUri = { server.url("/jwks.json").toString() },
            allowedAlgorithms = { emptyList() },
            jwks = JwksClient(OkHttpClient()),
            clockSkewTolerance = 60.seconds,
            clock = { now },
        )
        val claims = Jose.json(
            mapOf(
                "iss" to Jose.str(issuerUrl),
                "sub" to Jose.str("user-1"),
                "aud" to Jose.str(clientId),
                "exp" to Jose.num(now.epochSecond + 7200),
                "iat" to Jose.num(now.epochSecond - 10),
                "nbf" to Jose.num(now.epochSecond + 3600),
                "nonce" to Jose.str("nonce-1"),
            ),
        )
        val token = Jose.jws("RS256", Jose.rsa.private, claims, kid = "rsa")

        val error = runCatching { validator.validate(token, "nonce-1", null, null, null) }

        assertTrue("a token not yet valid (nbf +1h) was accepted", error.isFailure)
        val configuration = error.exceptionOrNull() as VersolaError.Configuration
        assertTrue(configuration.detail is VersolaError.Configuration.Detail.IdTokenRejected)
    }

    // AUDIT: D12 (design). The logger has info and warn only, so a developer cannot see
    // diagnostics (discovery fetched, refresh coalesced, retry scheduled) without a build of the SDK.
    @Test
    fun `AUDIT D12 VersolaLogger has a debug or trace level`() {
        val methods = VersolaLogger::class.java.methods.map { it.name }.toSet()

        assertTrue("VersolaLogger levels: $methods", "debug" in methods || "trace" in methods)
    }
}
