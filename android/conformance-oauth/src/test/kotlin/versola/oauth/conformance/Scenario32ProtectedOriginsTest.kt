package versola.oauth.conformance

import kotlinx.coroutines.test.runTest
import okhttp3.Request
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import versola.oauth.core.VersolaError

/**
 * `32-protected-origins`: the authenticated client attaches a token only to configured
 * origins and treats them exactly. Two of the scenario's cases are not provable on loopback,
 * where the facade allows `http` (`spec/oauth-sdk-api.md` section 3): "the first origin over
 * http" is indistinguishable from the first origin here, and the DPoP case needs the Keystore
 * (device tier). The non-https refusal is asserted with a non-loopback host instead.
 */
class Scenario32ProtectedOriginsTest : ProviderConformance() {

    @Test
    fun `only the configured origin, with any path and query, carries Authorization`() = runTest {
        val second = ResourceServer(provider, proxy).also { it.start() }
        try {
            val client = client()
            client.login()
            val tokenPath = client.metadata().tokenEndpoint.substringAfter(proxy.origin)

            val configured = client.call(Request.Builder().url(resource.url("/api")).build())
            val withPathAndQuery = client.call(Request.Builder().url(resource.url("/api/items?page=2")).build())
            // The same host on another port, and the same server under another host name.
            val otherPort = client.call(Request.Builder().url(second.url("/api")).build())
            val otherHost = client.call(Request.Builder().url(resource.origin.replace("localhost", "127.0.0.1") + "/api").build())
            listOf(configured, withPathAndQuery, otherPort, otherHost).forEach { it.close() }

            assertEquals(200, configured.code)
            assertEquals(200, withPathAndQuery.code)
            assertEquals(401, otherPort.code)
            assertEquals(401, otherHost.code)
            val sent = transcript.entries.filter { it.url.contains("/api") }
            assertEquals(4, sent.size)
            sent.filter { it.url.startsWith(resource.origin) }.forEach { assertTrue(it.header("Authorization")!!.startsWith("Bearer ")) }
            sent.filter { !it.url.startsWith(resource.origin) }.forEach { assertNull(it.header("Authorization")) }
            // A 401 from an origin that is not protected does not spend the refresh token.
            assertEquals(1, transcript.matching("POST", tokenPath).size)

            // A redirect from the protected origin is returned, not followed.
            val redirected = client.call(Request.Builder().url(resource.url("/redirect")).build())
            redirected.close()
            assertEquals(302, redirected.code)
            assertTrue(transcript.entries.none { it.url.contains("elsewhere.example.com") })
        } finally {
            second.stop()
        }
    }

    @Test
    fun `an empty origin set and a non-https origin are refused with InvalidConfiguration`() = runTest {
        val client = client()

        val empty = failsWith<VersolaError.Configuration> { client.interceptor(emptySet()) }
        assertTrue(empty.detail is VersolaError.Configuration.Detail.InvalidConfiguration)
        val plain = failsWith<VersolaError.Configuration> { client.interceptor(setOf("http://api.example.com")) }
        assertTrue(plain.detail is VersolaError.Configuration.Detail.InvalidConfiguration)
    }
}
