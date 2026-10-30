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

        val error = failure { RetryScope(RetryPolicy(), { testScheduler.currentTime }, Random(1)).operation { client.fetch(issuer) } }

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
