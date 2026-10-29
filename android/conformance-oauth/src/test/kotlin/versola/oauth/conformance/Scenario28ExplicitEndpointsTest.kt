package versola.oauth.conformance

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.jsonPrimitive
import mockwebserver3.MockResponse
import okhttp3.Request
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import versola.oauth.OAuthConfiguration
import versola.oauth.ProviderEndpoints
import versola.oauth.core.SessionState
import versola.oauth.core.VersolaError

/** `28-explicit-endpoints`: a provider without discovery, configured from explicit endpoints. */
class Scenario28ExplicitEndpointsTest : ProviderConformance() {

    /** The provider's real endpoints, read from its own discovery once and re-rooted at the proxy. */
    private fun endpoints(): ProviderEndpoints {
        val discovery = HarnessSigner.parse(
            okhttp3.OkHttpClient().newCall(Request.Builder().url(provider.issuer + "/.well-known/openid-configuration").build()).execute().text(),
        )
        fun at(name: String): String? = discovery[name]?.jsonPrimitive?.content?.replace(provider.origin, proxy.origin)
        return ProviderEndpoints(
            issuer = proxy.issuer,
            authorizationEndpoint = at("authorization_endpoint")!!,
            tokenEndpoint = at("token_endpoint")!!,
            jwksUri = at("jwks_uri")!!,
            userinfoEndpoint = at("userinfo_endpoint"),
            revocationEndpoint = at("revocation_endpoint"),
            // No end_session_endpoint and no PAR endpoint, by the scenario's precondition.
        )
    }

    @Test
    fun `the whole flow runs without ever requesting discovery`() = runTest {
        proxy.intercept = { request ->
            if (request.url.encodedPath.contains("/.well-known/")) MockResponse.Builder().code(404).build() else null
        }
        val endpoints = endpoints()
        val client = client(configuration(endpoints = endpoints))

        client.login()

        assertEquals(SessionState.Authenticated, client.state())
        assertTrue(transcript.entries.none { it.url.contains("/.well-known/") })
        assertTrue(proxy.requests.none { it.url.encodedPath.contains("/.well-known/") })
        // The ID token was validated against the configured jwksUri (the only one there is).
        assertEquals(1, transcript.matching("GET", endpoints.jwksUri.substringAfter(proxy.origin)).size)
        // PAR was not attempted: the only request before the browser opened was the JWKS one
        // after it, so the first POST is the code exchange.
        val firstPost = transcript.entries.first { it.method == "POST" }
        assertEquals(endpoints.tokenEndpoint, firstPost.url)
        // iss was on the redirect (the provider sends it) and was checked: a login succeeded.
        assertTrue(browser.opened.single().startsWith(endpoints.authorizationEndpoint + "?"))

        assertEquals(200, client.call(Request.Builder().url(resource.url("/api")).build()).code)

        val outcome = client.logout()

        assertEquals(1, browser.opened.size)
        assertFalse(outcome.sessionEnded)
        assertTrue(outcome.tokenRevoked)
        assertEquals(1, transcript.matching("POST", endpoints.revocationEndpoint!!.substringAfter(proxy.origin)).size)
        assertEquals(SessionState.Unauthenticated, client.state())
        assertNull(client.claims)
        failsWith<VersolaError.Reauthenticate> { runBlocking { client.accessToken() } }
        assertTrue(transcript.entries.none { it.url.contains("/.well-known/") })
    }

    @Test
    fun `issuer together with endpoints, or an endpoint that is not https, is refused at construction`() {
        val endpoints = endpoints()
        val both = failsWith<VersolaError.Configuration> {
            OAuthConfiguration(issuer = proxy.issuer, endpoints = endpoints, clientId = Provider.CLIENT_ID, redirectUri = Provider.REDIRECT_URI)
        }
        assertTrue(both.detail is VersolaError.Configuration.Detail.InvalidConfiguration)

        val plain = failsWith<VersolaError.Configuration> {
            OAuthConfiguration(
                endpoints = ProviderEndpoints(
                    issuer = "http://provider.example.com",
                    authorizationEndpoint = "http://provider.example.com/authorize",
                    tokenEndpoint = "http://provider.example.com/token",
                    jwksUri = "http://provider.example.com/jwks",
                ),
                clientId = Provider.CLIENT_ID,
                redirectUri = Provider.REDIRECT_URI,
            )
        }
        assertTrue(plain.detail is VersolaError.Configuration.Detail.InvalidConfiguration)
    }
}
