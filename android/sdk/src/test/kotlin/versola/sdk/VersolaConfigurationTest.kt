package versola.sdk

import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaLogger

private object SilentLogger : VersolaLogger {
    override fun info(message: String) {}
    override fun warn(message: String) {}
}

/**
 * `VersolaConfiguration` (`spec/versola-sdk-api.md` section 3): every refusal is raised at
 * construction, as `Configuration(InvalidConfiguration)`, and never behind a login screen. Plain
 * JVM: nothing here touches the platform.
 */
class VersolaConfigurationTest {

    private fun configuration(
        edgeUrl: String = "https://id.example.com",
        clientId: String = "acme-mobile",
        redirectUri: String = "https://app.example.com/oauth",
        issuer: String = edgeUrl,
        postLogoutRedirectUri: String? = null,
        clockSkewTolerance: Duration = 60.seconds,
    ) = VersolaConfiguration(
        edgeUrl = edgeUrl,
        clientId = clientId,
        redirectUri = redirectUri,
        issuer = issuer,
        postLogoutRedirectUri = postLogoutRedirectUri,
        clockSkewTolerance = clockSkewTolerance,
        logger = SilentLogger,
    )

    private fun assertInvalid(what: String, build: () -> Unit) {
        try {
            build()
        } catch (e: VersolaError.Configuration) {
            assertTrue("$what: ${e.detail}", e.detail is VersolaError.Configuration.Detail.InvalidConfiguration)
            return
        }
        fail("$what was accepted")
    }

    // --- edgeUrl ---

    @Test
    fun `an https edgeUrl is accepted`() {
        assertEquals("https://id.example.com", configuration(edgeUrl = "https://id.example.com").edgeUrl)
    }

    @Test
    fun `a trailing slash alone on the edgeUrl is accepted`() {
        val configuration = configuration(edgeUrl = "https://id.example.com/")

        assertEquals("https://id.example.com/", configuration.edgeUrl)
        assertEquals("https://id.example.com", configuration.edgeOrigin)
    }

    @Test
    fun `an edgeUrl that is not a URL is refused`() {
        assertInvalid("a word") { configuration(edgeUrl = "id.example.com", issuer = "https://id.example.com") }
        assertInvalid("an empty string") { configuration(edgeUrl = "", issuer = "https://id.example.com") }
        assertInvalid("another scheme") { configuration(edgeUrl = "ftp://id.example.com", issuer = "https://id.example.com") }
    }

    @Test
    fun `http is refused on a host that is not loopback, 10-0-2-2 included`() {
        assertInvalid("a public host") { configuration(edgeUrl = "http://id.example.com", issuer = "https://id.example.com") }
        assertInvalid("the emulator's alias for the host") { configuration(edgeUrl = "http://10.0.2.2:9005", issuer = "https://id.example.com") }
        assertInvalid("a private address") { configuration(edgeUrl = "http://192.168.1.10:9005", issuer = "https://id.example.com") }
    }

    @Test
    fun `http is accepted on localhost, 127-0-0-1 and the IPv6 loopback`() {
        for (edge in listOf("http://localhost:9005", "http://127.0.0.1:9005", "http://[::1]:9005")) {
            assertEquals(edge, configuration(edgeUrl = edge).edgeUrl)
        }
    }

    @Test
    fun `an edgeUrl with a path, a query, a fragment or credentials is refused`() {
        assertInvalid("a path") { configuration(edgeUrl = "https://id.example.com/edge", issuer = "https://id.example.com") }
        assertInvalid("a query") { configuration(edgeUrl = "https://id.example.com/?tenant=a", issuer = "https://id.example.com") }
        assertInvalid("a fragment") { configuration(edgeUrl = "https://id.example.com/#top", issuer = "https://id.example.com") }
        assertInvalid("userinfo") { configuration(edgeUrl = "https://user:secret@id.example.com", issuer = "https://id.example.com") }
        assertInvalid("a user name alone") { configuration(edgeUrl = "https://user@id.example.com", issuer = "https://id.example.com") }
    }

    // --- issuer ---

    @Test
    fun `the issuer defaults to the edgeUrl as written`() {
        assertEquals("https://id.example.com", configuration(edgeUrl = "https://id.example.com").issuer)
        assertEquals("https://id.example.com/", configuration(edgeUrl = "https://id.example.com/").issuer)
    }

    @Test
    fun `an explicit issuer is kept byte for byte, a trailing slash included`() {
        val configuration = configuration(edgeUrl = "https://edge.partner.example.org", issuer = "https://id.example.com/")

        assertEquals("https://id.example.com/", configuration.issuer)
        assertEquals("https://edge.partner.example.org", configuration.edgeUrl)
    }

    @Test
    fun `an issuer that is not https, or that carries a query, is refused`() {
        assertInvalid("http on a public host") { configuration(issuer = "http://id.example.com") }
        assertInvalid("a query") { configuration(issuer = "https://id.example.com?x=1") }
        assertInvalid("a fragment") { configuration(issuer = "https://id.example.com#x") }
    }

    // --- redirect URIs ---

    @Test
    fun `an https App Link redirect and post-logout redirect are accepted`() {
        val configuration = configuration(postLogoutRedirectUri = "https://app.example.com/signed-out")

        assertEquals("https://app.example.com/oauth", configuration.redirectUri)
        assertEquals("https://app.example.com/signed-out", configuration.postLogoutRedirectUri)
    }

    @Test
    fun `a custom-scheme redirect is refused, because a client fronted by edge cannot register one`() {
        assertInvalid("a private-use scheme") { configuration(redirectUri = "com.example.app:/oauth") }
    }

    @Test
    fun `a loopback http redirect is refused`() {
        assertInvalid("a loopback redirect") { configuration(redirectUri = "http://localhost:8765/oauth") }
        assertInvalid("a literal loopback redirect") { configuration(redirectUri = "http://127.0.0.1:8765/oauth") }
    }

    @Test
    fun `a post-logout redirect that is not https is refused`() {
        assertInvalid("a private-use scheme") { configuration(postLogoutRedirectUri = "com.example.app:/signed-out") }
        assertInvalid("a loopback address") { configuration(postLogoutRedirectUri = "http://localhost:8765/signed-out") }
        assertInvalid("http on a public host") { configuration(postLogoutRedirectUri = "http://app.example.com/signed-out") }
    }

    // --- the rest ---

    @Test
    fun `a blank clientId is refused`() {
        assertInvalid("an empty client id") { configuration(clientId = "") }
        assertInvalid("a blank client id") { configuration(clientId = "   ") }
    }

    @Test
    fun `a clock skew tolerance up to five minutes is accepted, and zero`() {
        assertEquals(5.minutes, configuration(clockSkewTolerance = 5.minutes).clockSkewTolerance)
        assertEquals(Duration.ZERO, configuration(clockSkewTolerance = Duration.ZERO).clockSkewTolerance)
    }

    @Test
    fun `a clock skew tolerance above five minutes is refused`() {
        assertInvalid("5 minutes and a second") { configuration(clockSkewTolerance = 5.minutes + 1.seconds) }
        assertInvalid("an hour") { configuration(clockSkewTolerance = 60.minutes) }
    }

    @Test
    fun `a negative clock skew tolerance is refused`() {
        assertInvalid("minus a second") { configuration(clockSkewTolerance = (-1).seconds) }
    }

    @Test
    fun `the storage key depends on the edge, the issuer and the client, and carries none of them`() {
        val base = configuration()

        assertEquals(base.storageKey, configuration().storageKey)
        assertTrue(base.storageKey != configuration(clientId = "other").storageKey)
        assertTrue(base.storageKey != configuration(edgeUrl = "https://other.example.com").storageKey)
        assertTrue(base.storageKey != configuration(issuer = "https://id.example.com/").storageKey)
        assertTrue(base.storageKey.none { it == '.' || it == '/' || it == ':' })
    }
}
