package versola.oauth.core

import java.io.File
import kotlinx.coroutines.test.runTest
import kotlin.random.Random
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

class JwksTest {

    @get:Rule
    val folder: TemporaryFolder = TemporaryFolder()

    private lateinit var server: MockWebServer
    private lateinit var uri: String

    @Before
    fun start() {
        server = MockWebServer()
        server.start()
        uri = server.url("/jwks.json").toString()
    }

    @After
    fun stop() {
        server.close()
    }

    private fun serve(body: String, code: Int = 200) {
        server.enqueue(MockResponse.Builder().code(code).body(body).build())
    }

    private val document = Jose.jwks(
        Jose.jwk(Jose.rsa, "rsa"),
        Jose.jwk(Jose.p256, "p256"),
        Jose.jwk(Jose.p384, "p384"),
        Jose.jwk(Jose.p521, "p521"),
    )

    @Test
    fun `RSA and EC P-256 P-384 and P-521 keys parse into the public keys they were made from`() {
        val set = JsonWebKeySet.parse(document)

        assertEquals(listOf("rsa", "p256", "p384", "p521"), set.keys.map { it.keyId })
        assertArrayEquals(Jose.rsa.public.encoded, set.keys[0].publicKey.encoded)
        assertArrayEquals(Jose.p256.public.encoded, set.keys[1].publicKey.encoded)
        assertArrayEquals(Jose.p384.public.encoded, set.keys[2].publicKey.encoded)
        assertArrayEquals(Jose.p521.public.encoded, set.keys[3].publicKey.encoded)
    }

    @Test
    fun `kty alg and use are carried and absent members are null`() {
        val set = JsonWebKeySet.parse(
            Jose.jwks(Jose.jwk(Jose.rsa, "a", alg = "RS256", extra = "\"use\":\"sig\""), Jose.jwk(Jose.p256, null)),
        )

        assertEquals("RSA", set.keys[0].keyType)
        assertEquals("RS256", set.keys[0].algorithm)
        assertEquals("sig", set.keys[0].use)
        assertNull(set.keys[1].keyId)
        assertNull(set.keys[1].algorithm)
        assertNull(set.keys[1].use)
    }

    @Test
    fun `keys the SDK cannot use are skipped and the usable ones kept`() {
        val set = JsonWebKeySet.parse(
            Jose.jwks(
                """{"kty":"oct","k":"AAAA","kid":"secret"}""",
                """{"kty":"EC","crv":"secp256k1","x":"AA","y":"AA","kid":"odd-curve"}""",
                """{"kty":"RSA","n":"!!","e":"AQAB","kid":"bad-base64"}""",
                """{"kty":"EC","crv":"P-256","x":"AA","y":"AA","kid":"short-coordinates"}""",
                """{"kid":"no-kty"}""",
                Jose.jwk(Jose.p256, "good"),
            ),
        )

        assertEquals(listOf("good"), set.keys.map { it.keyId })
    }

    @Test
    fun `an EC point that is not on the curve is skipped`() {
        val good = Jose.jwk(Jose.p256, "x")
        val offCurve = good.replace("\"kid\":\"x\"", "\"kid\":\"off\"").let {
            // Swap y for x's own value: a valid-width coordinate that is not this point's y.
            val x = Regex("\"x\":\"([^\"]+)\"").find(it)!!.groupValues[1]
            it.replace(Regex("\"y\":\"[^\"]+\""), "\"y\":\"$x\"")
        }

        assertTrue(JsonWebKeySet.parse(Jose.jwks(offCurve)).keys.isEmpty())
    }

    @Test
    fun `a document that is not JSON or has no keys array is not a JWK Set`() {
        for (bad in listOf("nope", "[]", """{"keys":{}}""", """{"other":[]}""")) {
            try {
                JsonWebKeySet.parse(bad)
                throw AssertionError("accepted $bad")
            } catch (e: IllegalArgumentException) {
                // expected
            }
        }
    }

    @Test
    fun `the client GETs jwks_uri and then answers from memory`() = runTest {
        serve(document)
        val client = JwksClient(OkHttpClient())

        val first = client.keys(uri, forceRefresh = false)
        val second = client.keys(uri, forceRefresh = false)

        assertTrue(first.fetched)
        assertFalse(second.fetched)
        assertEquals(4, second.keys.keys.size)
        assertEquals(1, server.requestCount)
        val request = server.takeRequest()
        assertEquals("GET", request.method)
        assertEquals("/jwks.json", request.target)
    }

    @Test
    fun `forcing a refresh fetches again and replaces the keys`() = runTest {
        serve(Jose.jwks(Jose.jwk(Jose.rsa, "old")))
        serve(Jose.jwks(Jose.jwk(Jose.rsa, "new")))
        val client = JwksClient(OkHttpClient())

        client.keys(uri, forceRefresh = false)
        val refreshed = client.keys(uri, forceRefresh = true)

        assertEquals(listOf("new"), refreshed.keys.keys.map { it.keyId })
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `a file cache serves a later client without any request`() = runTest {
        val file = File(folder.newFolder(), "jwks.json")
        serve(document)
        JwksClient(OkHttpClient(), FileJwksCache(file)).keys(uri, forceRefresh = false)

        val later = JwksClient(OkHttpClient(), FileJwksCache(file)).keys(uri, forceRefresh = false)

        assertFalse(later.fetched)
        assertEquals(4, later.keys.keys.size)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `a corrupt cache is dropped and the keys are fetched`() = runTest {
        val file = File(folder.newFolder(), "jwks.json")
        file.writeText("}{ not a key set")
        // Unexpired, so that it is the parse and not the age that drops it.
        file.setLastModified(System.currentTimeMillis() + 3_600_000)
        serve(document)

        val loaded = JwksClient(OkHttpClient(), FileJwksCache(file)).keys(uri, forceRefresh = false)

        assertTrue(loaded.fetched)
        assertEquals(1, server.requestCount)
        assertEquals(document, file.readText())
    }

    @Test
    fun `a malformed answer is DiscoveryMalformed and does not replace the cache`() = runTest {
        val cache = MemoryJwksCache().also { it.save(document, 3_600_000) }
        serve("<html>not keys</html>")

        val error = failure { JwksClient(OkHttpClient(), cache).keys(uri, forceRefresh = true) }

        val configuration = error as VersolaError.Configuration
        assertTrue(configuration.detail is VersolaError.Configuration.Detail.DiscoveryMalformed)
        assertEquals(document, cache.load())
    }

    @Test
    fun `a 5xx is a Server failure with its status`() = runTest {
        serve("", code = 503)

        val error = failure { JwksClient(OkHttpClient()).keys(uri, forceRefresh = false) }

        val recoverable = error as VersolaError.Recoverable
        assertTrue(recoverable.reason is VersolaError.Recoverable.Cause.Server)
    }

    @Test
    fun `an unreachable provider is a Network failure`() = runTest {
        val dead = server.url("/jwks.json").toString()
        server.close()

        val error = failure { JwksClient(OkHttpClient()).keys(dead, forceRefresh = false) }

        val recoverable = error as VersolaError.Recoverable
        assertTrue(recoverable.reason is VersolaError.Recoverable.Cause.Network)
    }

    @Test
    fun `a redirect is not followed`() = runTest {
        server.enqueue(MockResponse.Builder().code(302).addHeader("Location", server.url("/elsewhere").toString()).build())
        serve(document)

        val error = failure { JwksClient(OkHttpClient()).keys(uri, forceRefresh = false) }

        val configuration = error as VersolaError.Configuration
        assertTrue(configuration.detail is VersolaError.Configuration.Detail.DiscoveryMalformed)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `the memory cache saves loads and clears`() = runTest {
        val cache = MemoryJwksCache()
        assertNull(cache.load())

        cache.save("x", 3_600_000)
        assertEquals("x", cache.load())

        cache.clear()
        assertNull(cache.load())
    }

    @Test
    fun `the file cache saves loads and clears`() = runTest {
        val cache = FileJwksCache(File(folder.newFolder(), "nested/jwks.json"))
        assertNull(cache.load())

        cache.save("""{"keys":[]}""", 3_600_000)
        assertEquals("""{"keys":[]}""", cache.load())

        cache.clear()
        assertNull(cache.load())
    }

    // ---- the key set expires: a withdrawn key must not stay trusted -----------------------------

    private val minute = 60_000L
    private val hour = 60 * minute

    private fun serveWith(body: String, vararg headers: Pair<String, String>) {
        server.enqueue(
            MockResponse.Builder().code(200).body(body).apply { headers.forEach { (name, value) -> setHeader(name, value) } }.build(),
        )
    }

    /** Fetches once, then asks again after each of [afterMillis] and reports how many requests the asks cost. */
    private suspend fun requestsAfter(vararg headers: Pair<String, String>, afterMillis: Long): Int {
        serveWith(document, *headers)
        serveWith(document, *headers)
        var now = 1_000_000_000_000L
        val client = JwksClient(OkHttpClient(), MemoryJwksCache { now }) { now }
        client.keys(uri, forceRefresh = false)
        now += afterMillis
        client.keys(uri, forceRefresh = false)
        return server.requestCount
    }

    @Test
    fun `with no Cache-Control the key set lives 24 hours and is then fetched again`() = runTest {
        assertEquals(1, requestsAfter(afterMillis = 24 * hour - 1))
        server.close(); start()
        assertEquals(2, requestsAfter(afterMillis = 24 * hour))
    }

    @Test
    fun `a Cache-Control max-age shorter than a day is honoured`() = runTest {
        assertEquals(1, requestsAfter("Cache-Control" to "public, max-age=3600", afterMillis = hour - 1))
        server.close(); start()
        assertEquals(2, requestsAfter("Cache-Control" to "public, max-age=3600", afterMillis = hour))
    }

    @Test
    fun `a max-age below five minutes or no-store is raised to five minutes, and one past a day lowered to a day`() = runTest {
        assertEquals(1, requestsAfter("Cache-Control" to "max-age=1", afterMillis = 5 * minute - 1))
        server.close(); start()
        assertEquals(2, requestsAfter("Cache-Control" to "no-store", afterMillis = 5 * minute))
        server.close(); start()
        assertEquals(2, requestsAfter("Cache-Control" to "max-age=31536000", afterMillis = 24 * hour))
    }

    @Test
    fun `Expires is honoured against the response's own Date when there is no max-age`() = runTest {
        // Wall clock here is a year-2001 instant; the provider's Date and Expires are what count.
        val date = "Sun, 06 Nov 1994 08:49:37 GMT"
        val expires = "Sun, 06 Nov 1994 09:49:37 GMT"
        assertEquals(1, requestsAfter("Date" to date, "Expires" to expires, afterMillis = hour - 1))
        server.close(); start()
        assertEquals(2, requestsAfter("Date" to date, "Expires" to expires, afterMillis = hour))
    }

    @Test
    fun `an Expires that does not parse is already past and gets the shortest lifetime`() = runTest {
        assertEquals(2, requestsAfter("Expires" to "0", afterMillis = 5 * minute))
    }

    @Test
    fun `an expired file copy is not read by a new process, and the lifetime survives the restart`() = runTest {
        var now = 1_000_000_000_000L
        val file = File(folder.newFolder(), "jwks.json")
        serveWith(document, "Cache-Control" to "max-age=3600")
        serveWith(document, "Cache-Control" to "max-age=3600")
        JwksClient(OkHttpClient(), FileJwksCache(file) { now }) { now }.keys(uri, forceRefresh = false)

        now += hour - 1
        JwksClient(OkHttpClient(), FileJwksCache(file) { now }) { now }.keys(uri, forceRefresh = false)
        assertEquals("a restart inside the lifetime asks nothing", 1, server.requestCount)

        now += 1
        JwksClient(OkHttpClient(), FileJwksCache(file) { now }) { now }.keys(uri, forceRefresh = false)
        assertEquals("a restart after it fetches", 2, server.requestCount)
    }

    @Test
    fun `a copy written before keys expired reads as expired once, and is replaced`() = runTest {
        val file = File(folder.newFolder(), "jwks.json")
        file.writeText(document)
        file.setLastModified(System.currentTimeMillis() - 7 * 24 * hour)
        serve(document)

        val loaded = JwksClient(OkHttpClient(), FileJwksCache(file)).keys(uri, forceRefresh = false)

        assertTrue(loaded.fetched)
        assertTrue("replaced with a fresh stamp", file.lastModified() > System.currentTimeMillis())
    }

    @Test
    fun `a clock moved back past the fetch makes the copy expired rather than good for years`() = runTest {
        var now = 1_000_000_000_000L
        serve(document)
        serve(document)
        val client = JwksClient(OkHttpClient(), MemoryJwksCache { now }) { now }
        client.keys(uri, forceRefresh = false)

        now -= 2 * 24 * hour
        client.keys(uri, forceRefresh = false)

        assertEquals(2, server.requestCount)
    }

    @Test
    fun `an expired key set is not served when the refetch fails`() = runTest {
        var now = 1_000_000_000_000L
        serve(document)
        val client = JwksClient(OkHttpClient(), MemoryJwksCache { now }) { now }
        client.keys(uri, forceRefresh = false)

        now += 24 * hour
        server.enqueue(MockResponse.Builder().code(503).build())

        // A key the provider withdrew is what a stale copy would go on vouching for.
        val error = failure { client.keys(uri, forceRefresh = false) }
        assertTrue(error is VersolaError.Recoverable)
    }

    // ---- scenario 34, unit tier: the key set is repeated under the operation's budget -------

    @Test
    fun `a 500, 503 or 429 on the key set is repeated three times under the operation`() = runTest {
        for (status in listOf(500, 503, 429)) {
            repeat(3) { serve("", code = status) }
            val before = server.requestCount

            val error = failure { RetryScope(RetryPolicy(), { testScheduler.currentTime }, Random(1)).operation { JwksClient(OkHttpClient()).keys(uri, forceRefresh = false) } } as VersolaError.Recoverable

            val cause = error.reason as VersolaError.Recoverable.Cause.Server
            assertEquals(status, cause.status)
            assertEquals(3, cause.attempts)
            assertEquals("$status", 3, server.requestCount - before)
        }
    }

    @Test
    fun `a key set that answers 503 once and then the document is fetched`() = runTest {
        serve("", code = 503)
        serve(document)

        RetryScope(RetryPolicy(), { testScheduler.currentTime }, Random(1)).operation { JwksClient(OkHttpClient()).keys(uri, forceRefresh = false) }

        assertEquals(2, server.requestCount)
    }

    @Test
    fun `a 404 on the key set is surfaced after one request`() = runTest {
        serve("", code = 404)

        val error = failure { RetryScope(RetryPolicy(), { testScheduler.currentTime }, Random(1)).operation { JwksClient(OkHttpClient()).keys(uri, forceRefresh = false) } }

        assertTrue(error is VersolaError.Recoverable)
        assertEquals(1, server.requestCount)
    }
}
