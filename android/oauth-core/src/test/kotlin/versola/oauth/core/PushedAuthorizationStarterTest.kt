package versola.oauth.core

import java.io.IOException
import java.net.URI
import java.net.URLDecoder
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class PushedAuthorizationStarterTest {

    private lateinit var server: MockWebServer
    private lateinit var parEndpoint: String

    private val configuration = VersolaConfiguration.create(
        issuer = "https://id.example.com",
        clientId = "mobile-app",
        redirectUri = "https://app.example.com/oauth",
    )

    @Before
    fun start() {
        server = MockWebServer()
        server.start()
        parEndpoint = server.url("/par").toString()
    }

    @After
    fun stop() {
        server.close()
    }

    private fun metadata(
        endpoint: String? = parEndpoint,
        required: Boolean = false,
    ) = ProviderMetadata(
        issuer = "https://id.example.com",
        authorizationEndpoint = "https://id.example.com/authorize",
        tokenEndpoint = "https://id.example.com/token",
        pushedAuthorizationRequestEndpoint = endpoint,
        requirePushedAuthorizationRequests = required,
    )

    private fun starter(policy: PushedAuthorization = PushedAuthorization.WhenAdvertised) =
        PushedAuthorizationStarter(configuration, OkHttpClient(), policy)

    private fun request() = AuthorizationRequest.create(
        configuration,
        scopes = setOf("openid", "profile"),
        parameters = AuthorizationParameters(resources = listOf("https://api.example.com/a")),
    )

    private fun pushed(requestUri: String = "urn:ietf:params:oauth:request_uri:abc") = MockResponse.Builder()
        .code(201)
        .setHeader("Content-Type", "application/json")
        .body("""{"request_uri":"$requestUri","expires_in":60}""")
        .build()

    private fun form(body: String): List<Pair<String, String>> = body.split('&').map {
        URLDecoder.decode(it.substringBefore('='), "UTF-8") to URLDecoder.decode(it.substringAfter('='), "UTF-8")
    }

    private fun query(uri: String): List<Pair<String, String>> = form(URI(uri).rawQuery)

    /** The error a suspending call raises; `assertThrows` takes no suspending lambda. */
    private suspend inline fun <reified T : VersolaError> thrown(block: () -> Unit): T = try {
        block()
        throw AssertionError("expected ${T::class.java.simpleName}, nothing was thrown")
    } catch (e: VersolaError) {
        e as? T ?: throw AssertionError("expected ${T::class.java.simpleName}, got $e")
    }

    private fun assertPar(error: VersolaError) {
        val configuration = error as VersolaError.Configuration
        assertEquals(VersolaError.Configuration.Detail.ProviderUnsupported("par"), configuration.detail)
    }

    @Test
    fun `an advertised endpoint is pushed to and the browser opens on client_id and request_uri only`() = runTest {
        server.enqueue(pushed())
        val request = request()

        val started = starter().start(request, metadata(), nowEpochMillis = 5_000)

        assertEquals(
            "https://id.example.com/authorize?client_id=mobile-app&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc",
            started.browserUri,
        )
        assertEquals(listOf("client_id", "request_uri"), query(started.browserUri).map { it.first })
    }

    @Test
    fun `the pending request keeps the verifier because the exchange is the ordinary one`() = runTest {
        server.enqueue(pushed())
        val request = request()

        val started = starter().start(request, metadata(), nowEpochMillis = 5_000)

        assertEquals(request.codeVerifier.value, started.pending.codeVerifier)
        assertEquals(request.state, started.pending.state)
        assertEquals(request.nonce, started.pending.nonce)
        assertEquals(5_000L, started.pending.createdAtEpochMillis)
        assertTrue(started.pending.extension.isEmpty())
        assertEquals(listOf("https://api.example.com/a"), started.pending.resources)
    }

    @Test
    fun `the form carries the whole request and no credential`() = runTest {
        server.enqueue(pushed())
        val request = request()

        starter().start(request, metadata(), nowEpochMillis = 0)

        val recorded = server.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/par", recorded.url.encodedPath)
        assertTrue(recorded.headers["Content-Type"]!!.startsWith("application/x-www-form-urlencoded"))
        assertNull(recorded.headers["Authorization"])
        val body = recorded.body!!.utf8()
        val fields = form(body)
        assertEquals(request.codeVerifier.challengeS256(), fields.single { it.first == "code_challenge" }.second)
        assertEquals(request.state, fields.single { it.first == "state" }.second)
        assertEquals(request.nonce, fields.single { it.first == "nonce" }.second)
        assertEquals("mobile-app", fields.single { it.first == "client_id" }.second)
        assertEquals("openid profile", fields.single { it.first == "scope" }.second)
        assertEquals("https://api.example.com/a", fields.single { it.first == "resource" }.second)
        assertFalse(body.contains("client_secret"))
        assertFalse(body.contains("client_assertion"))
        assertFalse(body.contains("code_verifier"))
        assertFalse(body.contains(request.codeVerifier.value))
    }

    @Test
    fun `the form is exactly the query the plain request would have carried`() = runTest {
        server.enqueue(pushed())
        val request = request()

        starter().start(request, metadata(), nowEpochMillis = 0)

        val pushedFields = form(server.takeRequest().body!!.utf8())
        assertEquals(query(request.toUri("https://id.example.com/authorize")), pushedFields)
    }

    @Test
    fun `a 200 answer with the same members is accepted`() = runTest {
        server.enqueue(
            MockResponse.Builder().code(200).body("""{"request_uri":"urn:x:1","expires_in":30}""").build(),
        )

        val started = starter().start(request(), metadata(), nowEpochMillis = 0)

        assertTrue(started.browserUri.contains("request_uri=urn%3Ax%3A1"))
    }

    @Test
    fun `Never with a provider that requires PAR is ProviderUnsupported and nothing is sent`() = runTest {
        val error = thrown<VersolaError.Configuration> {
                starter(PushedAuthorization.Never).start(request(), metadata(required = true), 0)
            }

        assertPar(error)
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `Required with no advertised endpoint is ProviderUnsupported and nothing is sent`() = runTest {
        val error = thrown<VersolaError.Configuration> {
                starter(PushedAuthorization.Required).start(request(), metadata(endpoint = null), 0)
            }

        assertPar(error)
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `WhenAdvertised with a provider that requires PAR but advertises no endpoint is ProviderUnsupported`() = runTest {
        // A plain request is one the provider will refuse; fail closed, naming the capability.
        val error = thrown<VersolaError.Configuration> {
                starter().start(request(), metadata(endpoint = null, required = true), 0)
            }

        assertPar(error)
    }

    @Test
    fun `WhenAdvertised without an endpoint falls back to the plain request`() = runTest {
        val request = request()

        val started = starter().start(request, metadata(endpoint = null), nowEpochMillis = 7)

        assertEquals(request.toUri("https://id.example.com/authorize"), started.browserUri)
        assertEquals(request.codeVerifier.value, started.pending.codeVerifier)
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `Never sends the plain request even when an endpoint is advertised`() = runTest {
        val request = request()

        val started = starter(PushedAuthorization.Never).start(request, metadata(), nowEpochMillis = 7)

        assertEquals(request.toUri("https://id.example.com/authorize"), started.browserUri)
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `a 400 with an OAuth error is AuthorizationRejected before any browser URI exists`() = runTest {
        server.enqueue(
            MockResponse.Builder()
                .code(400)
                .setHeader("Content-Type", "application/json")
                .body("""{"error":"invalid_request","error_description":"redirect_uri is not registered"}""")
                .build(),
        )

        val error = thrown<VersolaError.Configuration> {
                starter().start(request(), metadata(), 0)
            }

        assertEquals(
            VersolaError.Configuration.Detail.AuthorizationRejected("invalid_request", "redirect_uri is not registered"),
            error.detail,
        )
    }

    @Test
    fun `a 401 or 403 carrying an OAuth error is AuthorizationRejected with that code`() = runTest {
        // RFC 9126 §2.3 via RFC 6749 §5.2: `invalid_client` comes with a 401; a client not
        // allowed to push gets a 403 from some providers. The code is what the app is promised.
        server.enqueue(
            MockResponse.Builder().code(401).setHeader("Content-Type", "application/json")
                .body("""{"error":"invalid_client"}""").build(),
        )
        server.enqueue(
            MockResponse.Builder().code(403).setHeader("Content-Type", "application/json")
                .body("""{"error":"access_denied","error_description":"PAR not allowed for this client"}""").build(),
        )

        val unauthorized = thrown<VersolaError.Configuration> { starter().start(request(), metadata(), 0) }
        val forbidden = thrown<VersolaError.Configuration> { starter().start(request(), metadata(), 0) }

        assertEquals(VersolaError.Configuration.Detail.AuthorizationRejected("invalid_client", null), unauthorized.detail)
        assertEquals(VersolaError.Configuration.Detail.AuthorizationRejected("access_denied", "PAR not allowed for this client"), forbidden.detail)
    }

    @Test
    fun `a 400 that is not an OAuth error is a misconfigured endpoint`() = runTest {
        server.enqueue(MockResponse.Builder().code(400).body("<html>bad</html>").build())

        val error = thrown<VersolaError.Configuration> {
                starter().start(request(), metadata(), 0)
            }

        assertEquals(
            VersolaError.Configuration.Detail.InvalidConfiguration("PAR endpoint answered 400"),
            error.detail,
        )
    }

    @Test
    fun `any other status is InvalidConfiguration naming it, and a redirect is not followed`() = runTest {
        server.enqueue(
            MockResponse.Builder().code(307).setHeader("Location", server.url("/elsewhere").toString()).build(),
        )

        val error = thrown<VersolaError.Configuration> {
                starter().start(request(), metadata(), 0)
            }

        assertEquals(
            VersolaError.Configuration.Detail.InvalidConfiguration("PAR endpoint answered 307"),
            error.detail,
        )
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `a 2xx answer without a request_uri or a positive expires_in is refused`() = runTest {
        for (body in listOf("""{"expires_in":60}""", """{"request_uri":"urn:x:1"}""", """{"request_uri":"urn:x:1","expires_in":0}""", "not json")) {
            server.enqueue(MockResponse.Builder().code(201).body(body).build())

            val error = thrown<VersolaError.Configuration> {
                starter().start(request(), metadata(), 0)
            }

            assertTrue(body, error.detail is VersolaError.Configuration.Detail.InvalidConfiguration)
        }
    }

    @Test
    fun `a provider having a bad moment is a recoverable server failure with its status, not a configuration fault`() = runTest {
        server.enqueue(MockResponse.Builder().code(503).build())

        val error = thrown<VersolaError.Recoverable> {
                starter().start(request(), metadata(), 0)
            }

        assertTrue(error.reason is VersolaError.Recoverable.Cause.Server)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `an unreachable endpoint is a recoverable network failure and is not retried here`() = runTest {
        server.close()

        val error = thrown<VersolaError.Recoverable> {
                starter().start(request(), metadata(), 0)
            }

        assertTrue(error.reason is VersolaError.Recoverable.Cause.Network)
        assertTrue(error.cause is IOException)
    }

    // ---- scenario 34, unit tier: a push is repeated under the operation's budget -------------

    @Test
    fun `a 500, 503 or 429 on the push is repeated three times and the body is still intact each time`() = runTest {
        for (status in listOf(500, 503, 429)) {
            repeat(3) { server.enqueue(MockResponse.Builder().code(status).build()) }
            val before = server.requestCount

            val error = failure { RetryScope(RetryPolicy(), { testScheduler.currentTime }, Random(1)).operation { starter().start(request(), metadata(), 0) } } as VersolaError.Recoverable

            val cause = error.reason as VersolaError.Recoverable.Cause.Server
            assertEquals(status, cause.status)
            assertEquals(3, cause.attempts)
            assertEquals("$status", 3, server.requestCount - before)
            // A repeat sends the same form: zeroing the body after the first attempt would send
            // three requests, two of them empty.
            repeat(3) {
                val body = server.takeRequest().body!!.utf8()
                assertTrue("empty body on a repeat: '$body'", body.contains("code_challenge="))
            }
        }
    }

    @Test
    fun `a push that answers 503 once and then 201 succeeds`() = runTest {
        server.enqueue(MockResponse.Builder().code(503).build())
        server.enqueue(pushed())

        val started = RetryScope(RetryPolicy(), { testScheduler.currentTime }, Random(1)).operation { starter().start(request(), metadata(), 0) }

        assertTrue(started.browserUri.toString().contains("request_uri"))
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `a push refused with an OAuth error is never repeated`() = runTest {
        server.enqueue(
            MockResponse.Builder().code(400).setHeader("Content-Type", "application/json")
                .body("""{"error":"invalid_request"}""").build(),
        )

        val error = failure { RetryScope(RetryPolicy(), { testScheduler.currentTime }, Random(1)).operation { starter().start(request(), metadata(), 0) } }

        assertTrue(error is VersolaError.Configuration)
        assertEquals(1, server.requestCount)
    }
}
