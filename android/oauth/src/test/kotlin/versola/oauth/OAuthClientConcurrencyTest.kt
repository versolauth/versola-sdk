package versola.oauth

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
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
 * 100 concurrent `OAuthClient.call()`s that all hit a 401 on the same stale token.
 *
 * Each call blocks a thread inside the interceptor (`runBlocking`) while the refresh it waits on
 * runs on `Dispatchers.IO` (the token request, the DataStore read). If the blocked calls are
 * themselves on `Dispatchers.IO`, 64 of them hold every thread of its default view and the
 * refresh can never be dispatched: the process hangs (`.claude/rules/android-kotlin.md`, F2).
 * Its own file because that hang, were it to come back, would take every other test of the
 * module's JVM with it.
 */
@RunWith(RobolectricTestRunner::class)
class OAuthClientConcurrencyTest {

    private val application = ApplicationProvider.getApplicationContext<Application>()
    private lateinit var server: MockWebServer
    private lateinit var provider: TestProvider
    private lateinit var browser: FakeBrowser

    /** The first [CALLERS] requests wait here until all have arrived, so every caller holds a thread when its 401 comes. */
    private val allArrived = CountDownLatch(CALLERS)
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
                    val idToken = provider.idToken(nonce = checkNotNull(browser.nonceSeen), audience = "concurrency-client")
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
    fun `calls blocked on a stale token do not starve the refresh they wait for`() {
        val client = OAuthClient.create(
            application,
            OAuthConfiguration(
                issuer = provider.issuer,
                clientId = "concurrency-client",
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
                List(CALLERS + 16) {
                    async { client.call(Request.Builder().url("${provider.issuer}/api").build()).use { it.code } }
                }.awaitAll()
            }
        }
        val codes = try {
            outcome.get(40, TimeUnit.SECONDS)
        } catch (e: java.util.concurrent.TimeoutException) {
            null
        }

        assertNotNull("the calls never finished: the refresh was starved of a thread", codes)
        assertEquals(List(CALLERS + 16) { 200 }, codes)
        assertEquals("one refresh for all of them", 1, refreshes.get())
    }

    private companion object {
        const val CALLERS = 64
    }
}
