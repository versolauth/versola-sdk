package versola.oauth.flutter.conformance

import kotlinx.serialization.json.jsonPrimitive
import mockwebserver3.MockResponse
import okhttp3.OkHttpClient
import okhttp3.Request
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import versola.oauth.ProviderEndpoints
import versola.oauth.conformance.HarnessSigner
import versola.oauth.conformance.Provider
import versola.oauth.conformance.text
import versola.oauth.flutter.EndpointsMessage
import versola.oauth.flutter.ErrorCategoryMessage
import versola.oauth.flutter.SessionStateMessage

/**
 * `28-explicit-endpoints` through the bridge: a provider without discovery, configured from the
 * explicit endpoints of `EndpointsMessage`. The refused configurations answer `create` itself
 * with the typed error, before any native client exists. Source: `Scenario28ExplicitEndpointsTest`.
 */
class Scenario28ExplicitEndpointsBridgeTest : BridgeConformance() {

    private companion object {
        const val DISCOVERY = "/.well-known/openid-configuration"
    }

    /** The provider's real endpoints, read from its own discovery once and re-rooted at the proxy. */
    private fun endpoints(): ProviderEndpoints {
        val discovery = HarnessSigner.parse(
            OkHttpClient().newCall(Request.Builder().url(provider.issuer + "/.well-known/openid-configuration").build()).execute().text(),
        )
        fun at(name: String): String? = discovery[name]?.jsonPrimitive?.content?.replace(provider.origin, proxy.origin)
        return ProviderEndpoints(
            // As the provider announces it, trailing slash included (Hydra): with explicit
            // endpoints the ID token's iss is held to this value byte for byte.
            issuer = at("issuer")!!,
            authorizationEndpoint = at("authorization_endpoint")!!,
            tokenEndpoint = at("token_endpoint")!!,
            jwksUri = at("jwks_uri")!!,
            userinfoEndpoint = at("userinfo_endpoint"),
            revocationEndpoint = at("revocation_endpoint"),
            // No end_session_endpoint and no PAR endpoint, by the scenario's precondition.
        )
    }

    @Test
    fun `the whole flow runs without ever requesting discovery`() {
        // The discovery document only: a provider may serve its JWKS under /.well-known/ too
        // (Hydra's /.well-known/jwks.json), and that is a configured endpoint here.
        proxy.intercept = { request ->
            if (request.url.encodedPath.endsWith(DISCOVERY)) MockResponse.Builder().code(404).build() else null
        }
        val endpoints = endpoints()
        val bridge = bridge(endpoints = endpoints)

        bridge.dart.login().assertOk()

        assertEquals(SessionStateMessage.AUTHENTICATED, bridge.dart.sessionState())
        assertTrue(transcript.entries.none { it.url.endsWith(DISCOVERY) })
        assertTrue(proxy.requests.none { it.url.encodedPath.endsWith(DISCOVERY) })
        // The ID token was validated against the configured jwksUri (the only one there is).
        assertEquals(1, transcript.matching("GET", endpoints.jwksUri.substringAfter(proxy.origin)).size)
        // PAR was not attempted: the only request before the browser opened was the JWKS one
        // after it, so the first POST is the code exchange.
        val firstPost = transcript.entries.first { it.method == "POST" }
        assertEquals(endpoints.tokenEndpoint, firstPost.url)
        // iss was on the redirect (the provider sends it) and was checked: a login succeeded.
        assertTrue(browser.opened.single().startsWith(endpoints.authorizationEndpoint + "?"))

        assertTokenIsUsableAtTheResource(bridge.dart.accessToken().token(), checkNotNull(bridge.dart.claims()).subject)

        val outcome = bridge.dart.logout()

        assertEquals(1, browser.opened.size)
        assertFalse(outcome.sessionEnded)
        assertTrue(outcome.tokenRevoked)
        assertEquals(1, transcript.matching("POST", endpoints.revocationEndpoint!!.substringAfter(proxy.origin)).size)
        assertEquals(SessionStateMessage.UNAUTHENTICATED, bridge.dart.sessionState())
        assertNull(bridge.dart.claims())
        assertEquals(ErrorCategoryMessage.REAUTHENTICATE, bridge.dart.accessToken().failure().category)
        assertTrue(transcript.entries.none { it.url.endsWith(DISCOVERY) })
    }

    @Test
    fun `issuer together with endpoints, or an endpoint that is not https, is refused at construction`() {
        val endpoints = endpoints()
        val both = dart("issuer-and-endpoints").create(message(endpoints = endpoints, issuer = proxy.issuer)).failure()
        assertError(both, ErrorCategoryMessage.CONFIGURATION, "invalidConfiguration")

        val plain = message(endpoints = ProviderEndpoints(
            issuer = "http://provider.example.com",
            authorizationEndpoint = "http://provider.example.com/authorize",
            tokenEndpoint = "http://provider.example.com/token",
            jwksUri = "http://provider.example.com/jwks",
        ), protectedOrigins = emptySet())
        assertError(dart("plain-endpoints").create(plain).failure(), ErrorCategoryMessage.CONFIGURATION, "invalidConfiguration")
    }
}
