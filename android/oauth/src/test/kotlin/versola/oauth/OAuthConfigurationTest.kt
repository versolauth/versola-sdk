package versola.oauth

import kotlin.time.Duration.Companion.minutes
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import versola.oauth.core.VersolaError

class OAuthConfigurationTest {

    private fun configuration(
        issuer: String? = "https://id.example.com",
        endpoints: ProviderEndpoints? = null,
        block: (OAuthConfiguration) -> Unit = {},
    ) = OAuthConfiguration(issuer = issuer, endpoints = endpoints, clientId = CLIENT_ID, redirectUri = REDIRECT_URI).also(block)

    private val endpoints = ProviderEndpoints(
        issuer = "https://id.example.com",
        authorizationEndpoint = "https://id.example.com/authorize",
        tokenEndpoint = "https://id.example.com/token",
        jwksUri = "https://id.example.com/jwks",
    )

    private fun refused(block: () -> Unit): VersolaError.Configuration =
        assertThrows(VersolaError.Configuration::class.java, block)

    @Test
    fun `exactly one of issuer and endpoints is given`() {
        refused { configuration(issuer = null) }
        refused { configuration(issuer = "https://id.example.com", endpoints = endpoints) }
        configuration(issuer = null, endpoints = endpoints)
    }

    @Test
    fun `openid is always among the scopes sent and a scope is one token`() {
        assertEquals(setOf("openid"), configuration().effectiveScopes)
        assertEquals(setOf("openid", "profile"), OAuthConfiguration(issuer = "https://id.example.com", clientId = CLIENT_ID, redirectUri = REDIRECT_URI, scopes = setOf("profile")).effectiveScopes)
        refused { OAuthConfiguration(issuer = "https://id.example.com", clientId = CLIENT_ID, redirectUri = REDIRECT_URI, scopes = setOf("openid profile")) }
    }

    @Test
    fun `every endpoint, the end-session override and the protected origins are https`() {
        refused { configuration(issuer = null, endpoints = ProviderEndpoints("https://id.example.com", "http://id.example.com/authorize", "https://id.example.com/token", "https://id.example.com/jwks")) }
        refused { OAuthConfiguration(issuer = "https://id.example.com", clientId = CLIENT_ID, redirectUri = REDIRECT_URI, endSessionEndpoint = "http://id.example.com/logout") }
        refused { OAuthConfiguration(issuer = "https://id.example.com", clientId = CLIENT_ID, redirectUri = REDIRECT_URI, protectedOrigins = setOf("http://api.example.com")) }
        refused { OAuthConfiguration(issuer = "https://id.example.com", clientId = CLIENT_ID, redirectUri = REDIRECT_URI, protectedOrigins = setOf("https://api.example.com/v1")) }
        OAuthConfiguration(issuer = "https://id.example.com", clientId = CLIENT_ID, redirectUri = REDIRECT_URI, protectedOrigins = setOf("https://api.example.com", "https://api.example.com:8443/"))
    }

    @Test
    fun `the issuer rules of the core apply, and a trailing slash is not part of the identifier`() {
        refused { configuration(issuer = "http://id.example.com") }
        refused { configuration(issuer = "https://id.example.com/?x=1") }
        assertEquals("https://id.example.com", configuration(issuer = "https://id.example.com/").issuerIdentifier)
    }

    @Test
    fun `clock skew tolerance is bounded`() {
        refused { OAuthConfiguration(issuer = "https://id.example.com", clientId = CLIENT_ID, redirectUri = REDIRECT_URI, clockSkewTolerance = 6.minutes) }
    }

    @Test
    fun `the storage key follows the issuer and client id, the fingerprint everything else`() {
        val a = configuration()
        val b = OAuthConfiguration(issuer = "https://id.example.com", clientId = CLIENT_ID, redirectUri = REDIRECT_URI, scopes = setOf("profile"))
        assertEquals(a.storageKey, b.storageKey)
        assertNotEquals(a.fingerprint, b.fingerprint)
        assertNotEquals(a.storageKey, OAuthConfiguration(issuer = "https://id.example.com", clientId = "other", redirectUri = REDIRECT_URI).storageKey)
        assertTrue(a.storageKey.none { it == '/' || it == '+' || it == '=' })
    }

    @Test
    fun `a reserved extra parameter is refused where the options are built`() {
        refused { LoginOptions(extraParameters = mapOf("redirect_uri" to "https://evil.example.com")) }
        LoginOptions(extraParameters = mapOf("audience" to "https://api.example.com"))
    }
}
