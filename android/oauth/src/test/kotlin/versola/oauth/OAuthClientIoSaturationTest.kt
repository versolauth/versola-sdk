package versola.oauth

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import mockwebserver3.Dispatcher
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import okhttp3.Request
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner

/**
 * An app that runs `authenticatedClient().newCall().execute()` itself, from coroutines on
 * `Dispatchers.IO`, with the access token stale. [CALLERS] callers hold every thread of that
 * dispatcher's default view (and 16 queue behind them), each blocked in the interceptor on the one
 * refresh they share; the refresh, the discovery and key-set caches and the DataStore behind it
 * need threads of their own to run, and they get them from the SDK's own dispatcher rather than
 * from the dispatcher the app has just exhausted. Were they dispatched to `Dispatchers.IO`, the
 * refresh would never start and the process would hang.
 *
 * Unlike [OAuthClientConcurrencyTest], which goes through `OAuthClient.call()`, nothing here
 * protects the callers: this is the path of an app that owns its own call sites.
 * Its own file because that hang, were it to come back, would take every other test of the
 * module's JVM with it; the hard timeout turns it into a failure instead.
 */
@RunWith(RobolectricTestRunner::class)
class OAuthClientIoSaturationTest {

    private val application = ApplicationProvider.getApplicationContext<Application>()
    private lateinit var server: MockWebServer
    private lateinit var provider: TestProvider
    private lateinit var browser: FakeBrowser

    /** The first [IO_THREADS] requests wait here until all have arrived, so every thread of the default view of IO holds a caller when its 401 comes. */
    private val allArrived = CountDownLatch(IO_THREADS)
    private val refreshes = java.util.concurrent.atomic.AtomicInteger()

    @Before
    fun start() {
        server = MockWebServer()
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse = when (request.url.encodedPath) {
                "/.well-known/openid-configuration" -> provider.json(provider.discovery())
                "/jwks" -> provider.json(provider.jwks())
                "/token" -> {
                    val refreshing = request.body?.utf8()?.contains("grant_type=refresh_token") == true
                    if (refreshing) refreshes.incrementAndGet()
                    val idToken = provider.idToken(nonce = checkNotNull(browser.nonceSeen), audience = "io-saturation-client")
                    provider.json(
                        """{"access_token":"${if (refreshing) "fresh" else "stale"}","token_type":"Bearer","expires_in":3600,"id_token":"$idToken","refresh_token":"rt"}""",
                    )
                }
                "/api" -> if (request.headers["Authorization"] == "Bearer fresh") {
                    MockResponse.Builder().code(200).body("ok").build()
                } else {
                    allArrived.countDown()
                    allArrived.await(30, TimeUnit.SECONDS)
                    MockResponse.Builder().code(401).build()
                }
                else -> MockResponse.Builder().code(404).build()
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

    @Test
    fun `callers that hold every thread of IO on a stale token do not starve the refresh they wait for`() {
        val client = OAuthClient.create(
            application,
            OAuthConfiguration(
                issuer = provider.issuer,
                clientId = "io-saturation-client",
                redirectUri = REDIRECT_URI,
                protectedOrigins = setOf(provider.issuer),
            ),
            browser = browser,
            keyProvider = ReversingKeyProvider,
        )

        // On a thread of its own and awaited with a hard timeout: a coroutine timeout cannot cancel a
        // call blocked in `execute()`, so were the refresh starved, `runBlocking` here would hang the
        // build instead of failing it.
        val outcome = java.util.concurrent.CompletableFuture.supplyAsync {
            runBlocking {
                client.login()
                val http = client.authenticatedClient()
                List(CALLERS) {
                    async(Dispatchers.IO) { http.newCall(Request.Builder().url("${provider.issuer}/api").build()).execute().use { it.code } }
                }.awaitAll()
            }
        }
        val codes = try {
            outcome.get(40, TimeUnit.SECONDS)
        } catch (e: java.util.concurrent.TimeoutException) {
            null
        }

        assertNotNull("the calls never finished: the refresh was starved of a thread", codes)
        assertEquals(List(CALLERS) { 200 }, codes)
        assertEquals("one refresh for all of them", 1, refreshes.get())
    }

    private companion object {
        /** The size of `Dispatchers.IO`'s default view: 64, or the core count when that is larger. */
        val IO_THREADS: Int = maxOf(64, Runtime.getRuntime().availableProcessors())

        /** More callers than threads, so that some are queued behind the ones that hold them. */
        val CALLERS: Int = IO_THREADS + 16
    }
}
