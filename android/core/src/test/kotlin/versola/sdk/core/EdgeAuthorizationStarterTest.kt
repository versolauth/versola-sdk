package versola.sdk.core

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import versola.oauth.core.AuthorizationRequest
import versola.oauth.core.ProviderMetadata
import versola.oauth.core.TokenBinding
import versola.oauth.core.VersolaConfiguration
import versola.oauth.core.VersolaError

private const val ISSUER = "https://id.example.com"

/** Answers like edge's `/native/start`, recording what it was asked. */
private class FakeNative : NativeAuthorizationStarter {
    val requests = mutableListOf<NativeStartRequest>()

    override suspend fun start(request: NativeStartRequest): NativeStart {
        requests += request
        return NativeStart(
            clientId = "mobile-app",
            requestUri = "urn:ietf:params:oauth:request_uri:abc",
            expiresIn = 60,
            authorizationEndpoint = "https://edge-says/authorize",
            state = "edge-state-${requests.size}",
            blob = "sealed-${requests.size}",
            tokenEndpoint = "https://id.example.com:9008/token",
            revocationEndpoint = "https://id.example.com:9008/revoke",
        )
    }
}

class EdgeAuthorizationStarterTest {

    private val configuration = VersolaConfiguration.create(ISSUER, "mobile-app", "https://app.example.com/oauth")
    private val metadata = ProviderMetadata(
        issuer = ISSUER,
        authorizationEndpoint = "$ISSUER/authorize",
        tokenEndpoint = "$ISSUER/token",
        dpopSigningAlgValuesSupported = listOf("ES256"),
    )

    @Test
    fun `edge builds the request, and what is persisted is edge's state and blob under the flow's own nonce`() = runTest {
        val native = FakeNative()
        val starter = EdgeAuthorizationStarter(configuration, TokenBinding.Dpop(), native)
        val request = AuthorizationRequest.create(configuration, setOf("openid"), listOf("mfa"), 300, dpopJkt = null)

        val started = starter.start(request, metadata, nowEpochMillis = 7)

        // What edge was asked: the pass-through parameters, and nothing PKCE-shaped.
        val asked = native.requests.single()
        assertEquals("https://app.example.com/oauth", asked.redirectUri)
        assertEquals(setOf("openid"), asked.scopes)
        assertEquals(request.nonce, asked.nonce)
        assertEquals(listOf("mfa"), asked.acrValues)
        assertEquals(300L, asked.maxAge)
        // The browser opens on discovery's authorization endpoint, the issuer the integrator
        // vouched for, with the request_uri and client_id only.
        assertEquals(
            "$ISSUER/authorize?client_id=mobile-app&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc",
            started.browserUri,
        )
        assertFalse(started.browserUri.contains("edge-says"))
        // Edge's state, no verifier of the flow's own, the blob and the endpoints the exchange
        // signs for, and `iss` required whatever discovery says.
        val pending = started.pending
        assertEquals("edge-state-1", pending.state)
        assertEquals(request.nonce, pending.nonce)
        assertEquals(7L, pending.createdAtEpochMillis)
        assertEquals(
            mapOf(
                EdgeAuthorizationStarter.BLOB to "sealed-1",
                EdgeAuthorizationStarter.TOKEN_ENDPOINT to "https://id.example.com:9008/token",
                EdgeAuthorizationStarter.REVOCATION_ENDPOINT to "https://id.example.com:9008/revoke",
            ),
            pending.extension,
        )
        assertTrue(pending.issRequired)
    }

    @Test
    fun `edge needs a key-bound session and an App Link redirect, refused at wiring time`() {
        assertThrows(VersolaError.Configuration::class.java) {
            EdgeAuthorizationStarter(configuration, TokenBinding.Bearer, FakeNative())
        }
        assertThrows(VersolaError.Configuration::class.java) {
            EdgeAuthorizationStarter(
                VersolaConfiguration.create(ISSUER, "mobile-app", "com.example.app:/oauth"),
                TokenBinding.Dpop(),
                FakeNative(),
            )
        }
    }
}
