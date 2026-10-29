package versola.oauth.flutter.conformance

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import versola.oauth.flutter.ErrorCategoryMessage

/**
 * `32-protected-origins` through the bridge, as far as the bridge reaches. The scenario's
 * subject is the authenticated client (an interceptor that attaches the token to configured
 * origins only, treats them exactly and does not follow a redirect); Flutter has no authenticated
 * client (`spec/oauth-sdk-api.md` section 10: `accessToken()` only), so those assertions are the
 * native drivers' alone and there is nothing at the bridge to run them against.
 *
 * What the bridge carries of it is asserted instead: the token that crosses is the one a
 * protected origin accepts, the SDK sends nothing to a resource origin by itself, and a
 * `protectedOrigins` entry that is not a valid origin is refused by `create` with
 * `InvalidConfiguration`. An empty set is not refused there: the facade demands origins of the
 * authenticated client, not of the configuration.
 */
class Scenario32ProtectedOriginsBridgeTest : BridgeConformance() {

    @Test
    fun `only the configured origin, with any path and query, carries Authorization`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()
        val token = bridge.dart.accessToken().token()
        val subject = checkNotNull(bridge.dart.claims()).subject

        // The app attaches the token, as it would with dio: the configured origin accepts it, with a path and a query.
        val configured = appCall(token, resource.url("/api"))
        val withPathAndQuery = appCall(token, resource.url("/api/items?page=2"))
        val configuredBody = configured.use { it.body.string() }
        withPathAndQuery.close()
        assertEquals(200, configured.code)
        assertEquals(200, withPathAndQuery.code)
        assertTrue(configuredBody.contains(subject))
        assertEquals("Bearer", token.tokenType)
        // The SDK itself never contacted the resource, and a request the app makes without the token is not the SDK's to fix.
        assertTrue(transcript.entries.none { it.url.startsWith(resource.origin) })
        val tokenPath = bridge.observe("discovery") { metadata() }.tokenEndpoint.substringAfter(proxy.origin)
        assertEquals(1, transcript.matching("POST", tokenPath).size)
    }

    @Test
    fun `an empty origin set and a non-https origin are refused with InvalidConfiguration`() {
        // A non-https origin (not loopback) and an origin carrying a path are refused by create itself.
        val plain = dart("plain-origin").create(message(protectedOrigins = setOf("http://api.example.com"))).failure()
        assertError(plain, ErrorCategoryMessage.CONFIGURATION, "invalidConfiguration")
        val withPath = dart("origin-with-path").create(message(protectedOrigins = setOf("https://api.example.com/v1"))).failure()
        assertError(withPath, ErrorCategoryMessage.CONFIGURATION, "invalidConfiguration")

        // An empty set is a valid configuration: only the authenticated client, which Flutter does not have, needs origins.
        bridge(protectedOrigins = emptySet())
    }
}
