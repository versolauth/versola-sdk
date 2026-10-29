package versola.oauth.conformance

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.flow.first
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import versola.oauth.OAuthClient
import versola.oauth.OAuthConfiguration
import versola.oauth.ProviderEndpoints
import versola.oauth.core.CredentialKeyProvider
import versola.oauth.core.PushedAuthorization
import versola.oauth.core.SessionState
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaLogger

/**
 * What every generic-facade scenario starts from: the provider from the environment (or the
 * whole class skipped), a fresh [ProviderProxy] the SDK is configured with as its issuer, the
 * HTTP browser leg, a [Transcript] on the SDK's client and a [ResourceServer]. Robolectric is
 * here for `OAuthClient.create`'s `Context` only; each test gets its own storage directory
 * from Robolectric and its own proxy port, so no state crosses tests.
 *
 * The scenario files are the assertions' source; a test names the scenario it implements in
 * its KDoc (`testing.md`, Conformance tests).
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
abstract class ProviderConformance {

    protected val application: Application = ApplicationProvider.getApplicationContext()
    protected lateinit var provider: Provider
    protected lateinit var proxy: ProviderProxy
    protected lateinit var browser: HttpLoginBrowser
    protected lateinit var resource: ResourceServer
    protected val transcript = Transcript()
    protected val logger = RecordingLogger()
    protected val httpClient: OkHttpClient = OkHttpClient.Builder().addNetworkInterceptor(transcript).build()

    @Before
    fun stage() {
        val staged = Provider.fromEnvironment()
        assumeTrue("OAUTH_CONFORMANCE_ISSUER is not set: no provider to run against (conformance/README.md)", staged != null)
        provider = staged!!
        // A provider told the proxy's address in advance (Hydra) means the same issuer in
        // every test; the per-process registry would refuse the next test's configuration.
        OAuthClient.forgetAll()
        proxy = ProviderProxy(provider).also { it.start(provider.proxyPort) }
        // The browser leg has its own client: what it sends to the login form is the user's
        // traffic, not the SDK's, and must not appear in the transcript.
        browser = HttpLoginBrowser(OkHttpClient(), provider)
        resource = ResourceServer(provider, proxy).also { it.start() }
    }

    @After
    fun unstage() {
        if (!::proxy.isInitialized) return
        proxy.stop()
        resource.stop()
        // Scenario 01's last assertion holds for every facade: no token, code or verifier at
        // any log level. Every secret the wire carried is checked against every line logged.
        val secrets = transcript.entries.flatMap { entry ->
            listOfNotNull(
                entry.responseJson?.get("access_token")?.toString()?.trim('"'),
                entry.responseJson?.get("refresh_token")?.toString()?.trim('"'),
                entry.responseJson?.get("id_token")?.toString()?.trim('"'),
                entry.form["code"],
                entry.form["code_verifier"],
            )
        }.filter { it.length > 8 }
        logger.lines.forEach { line ->
            secrets.forEach { secret -> assertFalse("a secret reached the log: $line", line.contains(secret)) }
        }
    }

    protected fun configuration(
        clientId: String = Provider.CLIENT_ID,
        endpoints: ProviderEndpoints? = null,
        redirectUri: String = Provider.REDIRECT_URI,
        scopes: Set<String> = provider.scopes,
        protectedOrigins: Set<String> = setOf(resource.origin),
        pushedAuthorization: PushedAuthorization = PushedAuthorization.WhenAdvertised,
    ): OAuthConfiguration = OAuthConfiguration(
        issuer = if (endpoints == null) proxy.issuer else null,
        endpoints = endpoints,
        clientId = clientId,
        redirectUri = redirectUri,
        postLogoutRedirectUri = Provider.POST_LOGOUT_REDIRECT_URI,
        scopes = scopes,
        protectedOrigins = protectedOrigins,
        pushedAuthorization = pushedAuthorization,
        logger = logger,
        httpClient = httpClient,
    )

    protected fun client(configuration: OAuthConfiguration = configuration()): OAuthClient =
        OAuthClient.create(application, configuration, browser = browser, keyProvider = ReversingKeyProvider)

    protected suspend fun OAuthClient.state(): SessionState = sessionState.first()

    /** The one request the SDK made to [pathSuffix], or fails naming how many there were. */
    protected fun theRequest(method: String, pathSuffix: String): Transcript.Entry {
        val matching = transcript.matching(method, pathSuffix)
        assertEquals("requests $method …$pathSuffix: ${transcript.entries}", 1, matching.size)
        return matching.single()
    }

    protected fun assertNoSecretOnTheWire(entry: Transcript.Entry) {
        assertFalse(entry.form.containsKey("client_secret"))
        assertFalse(entry.form.containsKey("client_assertion"))
        assertTrue(entry.header("Authorization") == null || !entry.header("Authorization")!!.startsWith("Basic"))
    }

    /** The typed error a failing operation surfaced, or fails when it succeeded. */
    protected inline fun <reified E : VersolaError> failsWith(block: () -> Unit): E {
        val error = runCatching(block).exceptionOrNull() ?: throw AssertionError("expected ${E::class.simpleName}, the operation succeeded")
        return error as? E ?: throw AssertionError("expected ${E::class.simpleName}, got $error", error)
    }
}

class RecordingLogger : VersolaLogger {
    val lines = java.util.concurrent.CopyOnWriteArrayList<String>()
    val warnings: List<String> get() = lines.filter { it.startsWith("warn: ") }.map { it.removePrefix("warn: ") }
    override fun info(message: String) {
        lines += "info: $message"
    }
    override fun warn(message: String) {
        lines += "warn: $message"
    }
}

/** A JVM stand-in for the Keystore-wrapped key: reversible, never secure, never shipped. */
object ReversingKeyProvider : CredentialKeyProvider {
    override suspend fun wrap(plaintext: ByteArray): ByteArray = plaintext.reversedArray()
    override suspend fun unwrap(blob: ByteArray): ByteArray = blob.reversedArray()
}
