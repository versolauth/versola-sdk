package versola.oauth.core

import java.io.File
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
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

private fun document(
    issuer: String,
    extra: String = "",
) = """
{
  "issuer": "$issuer",
  "authorization_endpoint": "$issuer/authorize",
  "token_endpoint": "$issuer/token",
  "userinfo_endpoint": "$issuer/userinfo",
  "dpop_signing_alg_values_supported": ["ES256", "PS256"],
  "authorization_response_iss_parameter_supported": true,
  "an_extension_field_the_sdk_does_not_know": 42
  $extra
}
""".trimIndent()

/** `assertThrows` cannot take a suspending block; this can. */
internal suspend fun failure(block: suspend () -> Unit): Throwable =
    runCatching { block() }.exceptionOrNull() ?: throw AssertionError("expected a failure")

class DiscoveryTest {

    @get:Rule
    val folder: TemporaryFolder = TemporaryFolder()

    private lateinit var server: MockWebServer
    private lateinit var client: HttpDiscoveryClient
    private lateinit var issuer: String

    @Before
    fun start() {
        server = MockWebServer()
        server.start()
        issuer = server.url("/").toString().trimEnd('/')
        client = HttpDiscoveryClient(OkHttpClient())
    }

    @After
    fun stop() {
        server.close()
    }

    private fun cache() = FileProviderMetadataCache(File(folder.newFolder(), "provider-metadata.json"))

    @Test
    fun `the well-known path is appended to the issuer`() = runTest {
        server.enqueue(MockResponse.Builder().code(200).body(document(issuer)).build())

        client.fetch(issuer)

        assertEquals("/.well-known/openid-configuration", server.takeRequest().target)
    }

    @Test
    fun `a document carrying fields the SDK does not know is still accepted`() = runTest {
        // auth's ServedMetadata derives several fields this SDK has no use for; rejecting
        // unknown fields would make the core unusable against a conforming provider.
        server.enqueue(MockResponse.Builder().code(200).body(document(issuer)).build())

        val metadata = client.fetch(issuer)

        assertEquals("$issuer/authorize", metadata.authorizationEndpoint)
        assertEquals("$issuer/token", metadata.tokenEndpoint)
        assertTrue(metadata.authorizationResponseIssParameterSupported)
    }

    @Test
    fun `advertised DPoP algorithms turn DPoP on`() = runTest {
        server.enqueue(MockResponse.Builder().code(200).body(document(issuer)).build())

        assertTrue(client.fetch(issuer).supportsDpop)
    }

    @Test
    fun `a document without dpop_signing_alg_values_supported is the bearer fallback, not a failure`() = runTest {
        // spec/errors.md is explicit: a missing dpop_signing_alg_values_supported is not a
        // missing required field. It means bearer, logged, not failed (scenario 07).
        val body = """
            {
              "issuer": "$issuer",
              "authorization_endpoint": "$issuer/authorize",
              "token_endpoint": "$issuer/token"
            }
        """.trimIndent()
        server.enqueue(MockResponse.Builder().code(200).body(body).build())

        val metadata = client.fetch(issuer)

        assertFalse(metadata.supportsDpop)
        assertFalse(metadata.authorizationResponseIssParameterSupported)
    }

    @Test
    fun `a document naming a different issuer is refused`() = runTest {
        // OpenID Connect Discovery §4.3 — the mix-up precondition.
        server.enqueue(MockResponse.Builder().code(200).body(document("https://evil.example")).build())

        val error = failure { client.fetch(issuer) } as VersolaError.Configuration

        assertTrue(error.detail is VersolaError.Configuration.Detail.DiscoveryIssuerMismatch)
    }

    @Test
    fun `a document missing a required field names the field`() = runTest {
        val body = """{"issuer": "$issuer", "authorization_endpoint": "$issuer/authorize"}"""
        server.enqueue(MockResponse.Builder().code(200).body(body).build())

        val error = failure { client.fetch(issuer) } as VersolaError.Configuration

        assertEquals(
            VersolaError.Configuration.Detail.DiscoveryFieldMissing("token_endpoint"),
            error.detail,
        )
    }

    @Test
    fun `a 404 is a deployment mistake, not something to retry`() = runTest {
        server.enqueue(MockResponse.Builder().code(404).build())

        val error = failure { client.fetch(issuer) } as VersolaError.Configuration

        assertTrue(error.detail is VersolaError.Configuration.Detail.InvalidConfiguration)
    }

    @Test
    fun `a 5xx is a Server failure and stays recoverable`() = runTest {
        server.enqueue(MockResponse.Builder().code(503).build())

        val error = failure { client.fetch(issuer) } as VersolaError.Recoverable

        assertTrue(error.reason is VersolaError.Recoverable.Cause.Server)
    }

    @Test
    fun `a body that is not the metadata document is Configuration`() = runTest {
        server.enqueue(MockResponse.Builder().code(200).body("<html>not json</html>").build())

        val error = failure { client.fetch(issuer) } as VersolaError.Configuration

        assertTrue(error.detail is VersolaError.Configuration.Detail.DiscoveryMalformed)
    }

    @Test
    fun `the document is fetched once and then served from memory`() = runTest {
        server.enqueue(MockResponse.Builder().code(200).body(document(issuer)).build())
        val service = DiscoveryService(issuer, client, cache())

        service.metadata()
        service.metadata()

        assertEquals(1, server.requestCount)
    }

    @Test
    fun `a cached document survives into a new process`() = runTest {
        // The persistence table keeps discovery metadata on disk across restarts and across
        // logout: it is not credential material, and a re-login should not need a round trip.
        server.enqueue(MockResponse.Builder().code(200).body(document(issuer)).build())
        val cache = cache()

        DiscoveryService(issuer, client, cache).metadata()
        val second = DiscoveryService(issuer, client, cache).metadata()

        assertEquals(1, server.requestCount)
        assertEquals("$issuer/token", second.tokenEndpoint)
    }

    @Test
    fun `a cached document differing only by a trailing slash is still a cache hit`() = runTest {
        // `ProviderMetadata.validate` already accepts this on the way in (`<issuer>/` passes
        // fetch validation); the cache-hit comparison must accept it the same way, or every
        // metadata document saved with a trailing slash is unusable after the process restarts
        // that DiscoveryService instance, defeating the disk cache entirely.
        val cache = cache()
        cache.save(
            discoveryJson.decodeFromString(ProviderMetadata.serializer(), document("$issuer/")),
        )

        val metadata = DiscoveryService(issuer, client, cache).metadata()

        assertEquals(0, server.requestCount)
        assertEquals("$issuer/", metadata.issuer)
    }

    @Test
    fun `a cached document belonging to another issuer is ignored`() = runTest {
        val cache = cache()
        cache.save(
            discoveryJson.decodeFromString(
                ProviderMetadata.serializer(),
                document("https://id.other.example"),
            ),
        )
        server.enqueue(MockResponse.Builder().code(200).body(document(issuer)).build())

        val metadata = DiscoveryService(issuer, client, cache).metadata()

        assertEquals(issuer, metadata.issuer)
    }

    @Test
    fun `a corrupt cache file is a miss rather than a failure`() = runTest {
        val file = File(folder.newFolder(), "provider-metadata.json")
        file.writeText("{ truncated")
        val cache = FileProviderMetadataCache(file)

        assertNull(cache.load())
        assertFalse(file.exists())
    }

    @Test
    fun `forcing a refresh goes back to the network`() = runTest {
        server.enqueue(MockResponse.Builder().code(200).body(document(issuer)).build())
        server.enqueue(MockResponse.Builder().code(200).body(document(issuer)).build())
        val service = DiscoveryService(issuer, client, cache())

        service.metadata()
        service.metadata(forceRefresh = true)

        assertEquals(2, server.requestCount)
    }

    // ---- endpoints are https (or cleartext on the developer's own machine), wherever they are hosted ----

    /** The test document with [overrides] replacing or adding members; a value of null removes one. */
    private fun documentWith(vararg overrides: Pair<String, String?>): String {
        val members = linkedMapOf(
            "issuer" to issuer,
            "authorization_endpoint" to "$issuer/authorize",
            "token_endpoint" to "$issuer/token",
        )
        overrides.forEach { (name, value) -> if (value == null) members.remove(name) else members[name] = value }
        return members.entries.joinToString(",", "{", "}") { (name, value) -> "\"$name\":\"$value\"" }
    }

    @Test
    fun `an endpoint that is not https is refused wherever it points, naming the member`() = runTest {
        for (field in listOf(
            "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "revocation_endpoint",
            "end_session_endpoint", "jwks_uri", "pushed_authorization_request_endpoint",
        )) {
            for (bad in listOf("http://idp.example.com/x", "ftp://idp.example.com/x", "/relative", "javascript:alert(1)", "https:///nohost")) {
                server.enqueue(MockResponse.Builder().code(200).body(documentWith(field to bad)).build())

                val error = failure { client.fetch(issuer) } as VersolaError.Configuration

                val detail = error.detail as VersolaError.Configuration.Detail.DiscoveryMalformed
                assertTrue("$field=$bad: ${detail.detail}", field in detail.detail)
            }
        }
    }

    @Test
    fun `an mTLS alias that is not https is refused too`() = runTest {
        val body = documentWith().dropLast(1) + ""","mtls_endpoint_aliases":{"token_endpoint":"http://idp.example.com/token"}}"""
        server.enqueue(MockResponse.Builder().code(200).body(body).build())

        val error = failure { client.fetch(issuer) } as VersolaError.Configuration

        assertTrue((error.detail as VersolaError.Configuration.Detail.DiscoveryMalformed).detail.contains("token_endpoint"))
    }

    @Test
    fun `https endpoints on another origin than the issuer are legitimate and accepted`() = runTest {
        server.enqueue(
            MockResponse.Builder().code(200).body(
                documentWith("token_endpoint" to "https://login.other.example/token", "jwks_uri" to "https://keys.other.example/jwks"),
            ).build(),
        )

        val metadata = client.fetch(issuer)

        assertEquals("https://login.other.example/token", metadata.tokenEndpoint)
    }

    @Test
    fun `cleartext is accepted only on the three loopback hosts, not the emulator alias or a LAN address`() = runTest {
        for (host in listOf("localhost", "127.0.0.1", "[::1]")) {
            server.enqueue(MockResponse.Builder().code(200).body(documentWith("token_endpoint" to "http://$host:9003/token")).build())
            assertEquals("http://$host:9003/token", client.fetch(issuer).tokenEndpoint)
        }
        for (host in listOf("10.0.2.2", "192.168.0.2")) {
            server.enqueue(MockResponse.Builder().code(200).body(documentWith("token_endpoint" to "http://$host:9003/token")).build())
            assertTrue(host, failure { client.fetch(issuer) } is VersolaError.Configuration)
        }
    }

    @Test
    fun `a cached document whose endpoint is no longer acceptable is a miss and is fetched again`() = runTest {
        val cache = cache()
        cache.save(discoveryJson.decodeFromString(ProviderMetadata.serializer(), documentWith("token_endpoint" to "http://idp.example.com/token")))
        server.enqueue(MockResponse.Builder().code(200).body(document(issuer)).build())

        val metadata = DiscoveryService(issuer, client, cache).metadata()

        assertEquals("$issuer/token", metadata.tokenEndpoint)
        assertEquals(1, server.requestCount)
    }

    // ---- the cache expires: 24 hours in memory and on disk -------------------------------------

    private val day = 24L * 60 * 60 * 1000

    @Test
    fun `a document older than 24 hours is fetched again, in memory and from the disk copy`() = runTest {
        server.enqueue(MockResponse.Builder().code(200).body(document(issuer)).build())
        server.enqueue(MockResponse.Builder().code(200).body(document(issuer)).build())
        server.enqueue(MockResponse.Builder().code(200).body(document(issuer)).build())
        var now = 1_000_000_000_000L
        val file = File(folder.newFolder(), "provider-metadata.json")
        val service = DiscoveryService(issuer, client, FileProviderMetadataCache(file)) { now }

        service.metadata()
        now += day - 1
        service.metadata()
        assertEquals("still fresh one millisecond before the day is out", 1, server.requestCount)

        now += 1
        service.metadata()
        assertEquals("expired in memory", 2, server.requestCount)

        // A new process finds the disk copy; its age is the file's, not the process's.
        file.setLastModified(now - day - 1)
        DiscoveryService(issuer, client, FileProviderMetadataCache(file)) { now }.metadata()
        assertEquals("expired on disk", 3, server.requestCount)
    }

    @Test
    fun `a disk copy younger than 24 hours is used by a new process, whatever its own start time`() = runTest {
        server.enqueue(MockResponse.Builder().code(200).body(document(issuer)).build())
        val now = 1_000_000_000_000L
        val file = File(folder.newFolder(), "provider-metadata.json")
        val cache = FileProviderMetadataCache(file)
        cache.save(discoveryJson.decodeFromString(ProviderMetadata.serializer(), document(issuer)))
        file.setLastModified(now - day + 60_000)

        DiscoveryService(issuer, client, cache) { now }.metadata()

        assertEquals(0, server.requestCount)
    }

    @Test
    fun `a clock moved back past the fetch is an expired document, not one from tomorrow`() = runTest {
        server.enqueue(MockResponse.Builder().code(200).body(document(issuer)).build())
        server.enqueue(MockResponse.Builder().code(200).body(document(issuer)).build())
        var now = 1_000_000_000_000L
        val service = DiscoveryService(issuer, client, cache()) { now }

        service.metadata()
        now -= 60_000
        service.metadata()

        assertEquals(2, server.requestCount)
    }

    @Test
    fun `an expired document is served once more when the provider cannot be reached`() = runTest {
        server.enqueue(MockResponse.Builder().code(200).body(document(issuer)).build())
        var now = 1_000_000_000_000L
        val service = DiscoveryService(issuer, client, cache()) { now }
        val first = service.metadata()

        now += day
        server.enqueue(MockResponse.Builder().code(503).build())
        val second = service.metadata()

        // Outside an operation there is no retry budget, so one request failed and the old
        // document answered; the next call asks again.
        assertEquals(first, second)
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `an expired document is not served when the refetch is answered with something wrong`() = runTest {
        server.enqueue(MockResponse.Builder().code(200).body(document(issuer)).build())
        var now = 1_000_000_000_000L
        val service = DiscoveryService(issuer, client, cache()) { now }
        service.metadata()

        now += day
        server.enqueue(MockResponse.Builder().code(200).body(documentWith("token_endpoint" to "http://idp.example.com/token")).build())

        assertTrue(failure { service.metadata() } is VersolaError.Configuration)
    }

    // ---- scenario 34, unit tier: discovery is repeated under the operation's budget ----------

    @Test
    fun `a 500, 503 or 429 is repeated three times under the operation and surfaced with its status`() = runTest {
        for (status in listOf(500, 503, 429)) {
            repeat(3) { server.enqueue(MockResponse.Builder().code(status).build()) }
            val before = server.requestCount

            val error = failure { RetryScope(RetryPolicy(), { testScheduler.currentTime }, Random(1)).operation { client.fetch(issuer) } } as VersolaError.Recoverable

            val cause = error.reason as VersolaError.Recoverable.Cause.Server
            assertEquals(status, cause.status)
            assertEquals(3, cause.attempts)
            assertEquals("$status", 3, server.requestCount - before)
        }
    }

    @Test
    fun `a 503 that then answers 200 succeeds on the second request`() = runTest {
        server.enqueue(MockResponse.Builder().code(503).build())
        server.enqueue(MockResponse.Builder().code(200).body(document(issuer)).build())

        RetryScope(RetryPolicy(), { testScheduler.currentTime }, Random(1)).operation { client.fetch(issuer) }

        assertEquals(2, server.requestCount)
    }

    @Test
    fun `a 429 with Retry-After is waited out and then repeated`() = runTest {
        server.enqueue(MockResponse.Builder().code(429).addHeader("Retry-After", "3").build())
        server.enqueue(MockResponse.Builder().code(200).body(document(issuer)).build())

        RetryScope(RetryPolicy(), { testScheduler.currentTime }, Random(1)).operation { client.fetch(issuer) }

        assertEquals(2, server.requestCount)
        assertTrue("waited ${testScheduler.currentTime}ms", testScheduler.currentTime in 3_000..3_300)
    }

    @Test
    fun `a 429 is not a missing document and is never Configuration`() = runTest {
        server.enqueue(MockResponse.Builder().code(429).build())

        val error = failure { client.fetch(issuer) }

        assertTrue(error is VersolaError.Recoverable)
    }

    @Test
    fun `a 404 is still a configuration fault and is not repeated`() = runTest {
        server.enqueue(MockResponse.Builder().code(404).build())

        val noRedirects = HttpDiscoveryClient(OkHttpClient.Builder().followRedirects(false).build())

        val error = failure { RetryScope(RetryPolicy(), { testScheduler.currentTime }, Random(1)).operation { noRedirects.fetch(issuer) } }

        assertTrue(error is VersolaError.Configuration)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `a redirect from the discovery endpoint is a configuration fault and is not repeated`() = runTest {
        server.enqueue(MockResponse.Builder().code(302).addHeader("Location", "https://elsewhere.example.com/").build())
        val noRedirects = HttpDiscoveryClient(OkHttpClient.Builder().followRedirects(false).build())

        val error = failure { RetryScope(RetryPolicy(), { testScheduler.currentTime }, Random(1)).operation { noRedirects.fetch(issuer) } }

        assertTrue(error is VersolaError.Configuration)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `a 501 is surfaced after one request`() = runTest {
        server.enqueue(MockResponse.Builder().code(501).build())

        failure { RetryScope(RetryPolicy(), { testScheduler.currentTime }, Random(1)).operation { client.fetch(issuer) } }

        assertEquals(1, server.requestCount)
    }
}
