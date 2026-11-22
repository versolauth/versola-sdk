package versola.sdk

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import versola.oauth.core.RetryPolicy
import versola.oauth.core.SessionState
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaInternalApi
import versola.oauth.core.VersolaLogger

private val ids = AtomicInteger()

private class NamedLogger : VersolaLogger {
    override fun info(message: String) {}
    override fun warn(message: String) {}
}

/**
 * `Versola.create` (`spec/versola-sdk-api.md` section 4): one instance per edge, issuer and client
 * id per process, a second call with a different configuration refused rather than silently given
 * the first one's settings, and no network I/O.
 */
@OptIn(VersolaInternalApi::class)
@RunWith(RobolectricTestRunner::class)
class VersolaCreateTest {

    private val application = ApplicationProvider.getApplicationContext<Application>()
    private val logger = NamedLogger()
    private val http = OkHttpClient()

    // One instance per process outlives a test, so each starts from none.
    @Before
    fun forgetTheInstances() {
        Versola.forgetAll()
    }

    @After
    fun forgetThemAgain() {
        Versola.forgetAll()
    }

    private fun configuration(
        clientId: String = "client-${ids.incrementAndGet()}",
        edgeUrl: String = "https://id.example.com",
        redirectUri: String = "https://app.example.com/oauth",
        retryPolicy: RetryPolicy = RetryPolicy.Default,
        requireHardwareKey: Boolean = false,
        httpClient: OkHttpClient = http,
        logger: VersolaLogger = this.logger,
    ) = VersolaConfiguration(
        edgeUrl = edgeUrl,
        clientId = clientId,
        redirectUri = redirectUri,
        retryPolicy = retryPolicy,
        requireHardwareKey = requireHardwareKey,
        httpClient = httpClient,
        logger = logger,
    )

    private fun assertRefused(what: String, create: () -> Versola) {
        try {
            create()
        } catch (e: VersolaError.Configuration) {
            assertTrue("$what: ${e.detail}", e.detail is VersolaError.Configuration.Detail.InvalidConfiguration)
            return
        }
        fail("$what was accepted")
    }

    @Test
    fun `the same configuration object twice returns the same instance`() {
        val configuration = configuration()

        assertSame(Versola.create(application, configuration), Versola.create(application, configuration))
    }

    @Test
    fun `a configuration equal in every value, with the same client and logger, returns the same instance`() {
        val first = configuration(clientId = "equal")
        val second = configuration(clientId = "equal")

        assertSame(Versola.create(application, first), Versola.create(application, second))
    }

    @Test
    fun `a different redirectUri for the same edge, issuer and client is refused`() {
        Versola.create(application, configuration(clientId = "c"))

        assertRefused("another redirectUri") {
            Versola.create(application, configuration(clientId = "c", redirectUri = "https://app.example.com/other"))
        }
    }

    @Test
    fun `a different retryPolicy for the same edge, issuer and client is refused`() {
        Versola.create(application, configuration(clientId = "c"))

        assertRefused("another retryPolicy") {
            Versola.create(application, configuration(clientId = "c", retryPolicy = RetryPolicy(maxAttemptsPerOrigin = 2)))
        }
    }

    @Test
    fun `a different requireHardwareKey for the same edge, issuer and client is refused`() {
        Versola.create(application, configuration(clientId = "c"))

        assertRefused("another requireHardwareKey") {
            Versola.create(application, configuration(clientId = "c", requireHardwareKey = true))
        }
    }

    @Test
    fun `another OkHttpClient for the same edge, issuer and client is refused`() {
        Versola.create(application, configuration(clientId = "c"))

        assertRefused("another OkHttpClient") {
            Versola.create(application, configuration(clientId = "c", httpClient = OkHttpClient()))
        }
    }

    @Test
    fun `another logger for the same edge, issuer and client is refused`() {
        Versola.create(application, configuration(clientId = "c"))

        assertRefused("another logger") {
            Versola.create(application, configuration(clientId = "c", logger = NamedLogger()))
        }
    }

    @Test
    fun `a refused create leaves the first instance in place`() {
        val first = Versola.create(application, configuration(clientId = "c"))
        assertRefused("another redirectUri") {
            Versola.create(application, configuration(clientId = "c", redirectUri = "https://app.example.com/other"))
        }

        assertSame(first, Versola.create(application, configuration(clientId = "c")))
    }

    @Test
    fun `a different clientId is a different instance`() {
        val first = Versola.create(application, configuration(clientId = "one"))
        val second = Versola.create(application, configuration(clientId = "two"))

        assertNotSame(first, second)
    }

    @Test
    fun `a different edgeUrl is a different instance`() {
        val first = Versola.create(application, configuration(clientId = "c"))
        val second = Versola.create(application, configuration(clientId = "c", edgeUrl = "https://other.example.com"))

        assertNotSame(first, second)
    }

    @Test
    fun `create makes no network request and a fresh install is Unauthenticated`() {
        FakeEdge("c").use { edge ->
            val versola = Versola.create(
                application,
                VersolaConfiguration(edgeUrl = edge.url, clientId = "c", redirectUri = REDIRECT_URI, logger = logger),
                browser = ScriptedBrowser(edge),
                keyProvider = ReversingKeyProvider,
            )

            assertEquals(SessionState.Unauthenticated, runBlocking { versola.currentSessionState() })
            assertEquals(null, versola.claims)
            assertEquals("no request, not even a discovery fetch", emptyList<String>(), edge.requests.map { it.target })
        }
    }
}
