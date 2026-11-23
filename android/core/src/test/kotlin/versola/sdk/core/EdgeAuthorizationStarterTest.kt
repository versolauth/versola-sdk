package versola.sdk.core

import java.net.URI
import java.net.URLDecoder
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import versola.oauth.core.AuthorizationParameters
import versola.oauth.core.AuthorizationRequest
import versola.oauth.core.PendingAuthorizationRequest
import versola.oauth.core.ProviderMetadata
import versola.oauth.core.VersolaConfiguration
import versola.oauth.core.VersolaError

private const val ISSUER = "https://id.example.com"

/** Answers like edge's `/native/start`, recording what it was asked. */
private class FakeNative(
    private val authorizationEndpoint: String = "https://edge-says.example.com/authorize",
    private val requestUri: String = "urn:ietf:params:oauth:request_uri:abc",
    private val expiresIn: Long = 60,
) : NativeAuthorizationStarter {
    val requests = mutableListOf<NativeStartRequest>()

    override suspend fun start(request: NativeStartRequest): NativeStart {
        requests += request
        return NativeStart(
            clientId = "mobile-app",
            requestUri = requestUri,
            expiresIn = expiresIn,
            authorizationEndpoint = authorizationEndpoint,
            state = "edge-state-${requests.size}",
            blob = "sealed-${requests.size}",
            tokenEndpoint = "https://id.example.com:9008/token",
            revocationEndpoint = "https://id.example.com:9008/revoke",
        )
    }
}

class EdgeAuthorizationStarterTest {

    private val configuration = VersolaConfiguration.create(ISSUER, "mobile-app", "https://app.example.com/oauth")

    /** Discovery's answer for the facade: an authorization endpoint that must never be the one opened. */
    private val metadata = ProviderMetadata(
        issuer = ISSUER,
        authorizationEndpoint = "$ISSUER/metadata-authorize",
        tokenEndpoint = "$ISSUER/token",
        dpopSigningAlgValuesSupported = listOf("ES256"),
    )

    private fun request(parameters: AuthorizationParameters = AuthorizationParameters()) =
        AuthorizationRequest.create(configuration, setOf("openid"), listOf("mfa"), 300, dpopJkt = null, parameters = parameters)

    private fun queryOf(uri: String): Map<String, String> =
        URI(uri).rawQuery.split('&').associate { pair ->
            val (name, value) = pair.split('=', limit = 2)
            URLDecoder.decode(name, "UTF-8") to URLDecoder.decode(value, "UTF-8")
        }

    @Test
    fun `edge builds the request, and what is persisted is edge's state and blob under the flow's own nonce`() = runTest {
        val native = FakeNative()
        val starter = EdgeAuthorizationStarter(configuration, native)
        val request = request()

        val started = starter.start(request, metadata, nowEpochMillis = 7)

        // What edge was asked: the pass-through parameters, and nothing PKCE-shaped.
        val asked = native.requests.single()
        assertEquals("https://app.example.com/oauth", asked.redirectUri)
        assertEquals(setOf("openid"), asked.scopes)
        assertEquals(request.nonce, asked.nonce)
        assertEquals(listOf("mfa"), asked.acrValues)
        assertEquals(300L, asked.maxAge)
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
    fun `the browser opens the authorization endpoint edge answered with client_id and request_uri only`() = runTest {
        val starter = EdgeAuthorizationStarter(configuration, FakeNative())

        val started = starter.start(request(), metadata, nowEpochMillis = 7)

        assertEquals(
            "https://edge-says.example.com/authorize?client_id=mobile-app" +
                "&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc",
            started.browserUri,
        )
        assertEquals(setOf("client_id", "request_uri"), queryOf(started.browserUri).keys)
    }

    @Test
    fun `the metadata's authorization endpoint is never the one opened`() = runTest {
        val started = EdgeAuthorizationStarter(configuration, FakeNative()).start(request(), metadata, nowEpochMillis = 0)

        assertTrue(started.browserUri.startsWith("https://edge-says.example.com/authorize?"))
        assertFalse(started.browserUri.contains("metadata-authorize"))
        assertFalse(started.browserUri.contains(ISSUER))
    }

    @Test
    fun `a request_uri that names a cell is put in the query and decodes back to the identical string`() = runTest {
        val requestUri = "urn:ietf:params:oauth:request_uri:v1.kz-1.AbC_d-9"
        val starter = EdgeAuthorizationStarter(configuration, FakeNative(requestUri = requestUri))

        val started = starter.start(request(), metadata, nowEpochMillis = 0)

        val query = queryOf(started.browserUri)
        assertEquals(requestUri, query["request_uri"])
        assertEquals("mobile-app", query["client_id"])
        assertFalse("a raw colon in the query value", URI(started.browserUri).rawQuery.contains("request_uri=urn:"))
    }

    @Test
    fun `a request_uri with reserved characters survives the query byte for byte`() = runTest {
        val requestUri = "urn:x:a b&c=d+e/f?g#h%i~j"
        val starter = EdgeAuthorizationStarter(configuration, FakeNative(requestUri = requestUri))

        val started = starter.start(request(), metadata, nowEpochMillis = 0)

        assertEquals(requestUri, queryOf(started.browserUri)["request_uri"])
        assertEquals(setOf("client_id", "request_uri"), queryOf(started.browserUri).keys)
    }

    @Test
    fun `an authorization endpoint that already has a query keeps it and gets the two parameters appended`() = runTest {
        val starter = EdgeAuthorizationStarter(
            configuration,
            FakeNative(authorizationEndpoint = "https://edge-says.example.com/authorize?cell=kz-1"),
        )

        val started = starter.start(request(), metadata, nowEpochMillis = 0)

        assertEquals(
            mapOf("cell" to "kz-1", "client_id" to "mobile-app", "request_uri" to "urn:ietf:params:oauth:request_uri:abc"),
            queryOf(started.browserUri),
        )
    }

    @Test
    fun `the pending request lives expires_in seconds as milliseconds`() = runTest {
        val started = EdgeAuthorizationStarter(configuration, FakeNative(expiresIn = 60))
            .start(request(), metadata, nowEpochMillis = 1_000)

        assertEquals(60_000L, started.pending.lifetimeMillis)
        assertFalse(started.pending.isExpired(1_000 + 59_999))
        assertTrue(started.pending.isExpired(1_000 + 60_000))
    }

    @Test
    fun `a lifetime edge states beyond ten minutes is capped at ten minutes`() = runTest {
        val started = EdgeAuthorizationStarter(configuration, FakeNative(expiresIn = 6000))
            .start(request(), metadata, nowEpochMillis = 0)

        assertEquals(600_000L, started.pending.lifetimeMillis)
        assertEquals(PendingAuthorizationRequest.MAX_AGE_MILLIS, started.pending.lifetimeMillis)
    }

    @Test
    fun `an absurd expires_in is capped without overflowing`() = runTest {
        val started = EdgeAuthorizationStarter(configuration, FakeNative(expiresIn = Long.MAX_VALUE))
            .start(request(), metadata, nowEpochMillis = 0)

        assertEquals(600_000L, started.pending.lifetimeMillis)
    }

    @Test
    fun `claims and authorization_details travel from the extra map and nothing else of it does`() = runTest {
        val native = FakeNative()
        val parameters = AuthorizationParameters(
            extra = mapOf(
                EdgeAuthorizationStarter.CLAIMS to """{"id_token":{"email":null}}""",
                EdgeAuthorizationStarter.AUTHORIZATION_DETAILS to """[{"type":"payment"}]""",
                "audience" to "https://api.example.com",
                "foo" to "bar",
                "acr_hint" to "x",
            ),
        )

        EdgeAuthorizationStarter(configuration, native).start(request(parameters), metadata, nowEpochMillis = 0)

        val asked = native.requests.single()
        assertEquals("""{"id_token":{"email":null}}""", asked.claims)
        assertEquals("""[{"type":"payment"}]""", asked.authorizationDetails)
    }

    @Test
    fun `an extra map with neither claims nor authorization_details forwards neither`() = runTest {
        val native = FakeNative()
        val parameters = AuthorizationParameters(extra = mapOf("foo" to "bar", "audience" to "x"))

        EdgeAuthorizationStarter(configuration, native).start(request(parameters), metadata, nowEpochMillis = 0)

        val asked = native.requests.single()
        assertNull(asked.claims)
        assertNull(asked.authorizationDetails)
    }

    @Test
    fun `prompt, login_hint, ui_locales and resources are forwarded to edge and persisted resources are kept`() = runTest {
        val native = FakeNative()
        val parameters = AuthorizationParameters(
            prompt = AuthorizationParameters.Prompt.Login,
            loginHint = "user@example.com",
            uiLocales = listOf("fr", "en"),
            resources = listOf("https://api.example.com/a", "https://api.example.com/b"),
        )

        val started = EdgeAuthorizationStarter(configuration, native).start(request(parameters), metadata, nowEpochMillis = 0)

        val asked = native.requests.single()
        assertEquals("login", asked.prompt)
        assertEquals("user@example.com", asked.loginHint)
        assertEquals(listOf("fr", "en"), asked.uiLocales)
        assertEquals(listOf("https://api.example.com/a", "https://api.example.com/b"), asked.resources)
        assertEquals(asked.resources, started.pending.resources)
    }

    @Test
    fun `an edge start answers for itself the binding of the dpop key`() {
        assertTrue(EdgeAuthorizationStarter(configuration, FakeNative()).bindsDpopKeyItself)
    }

    @Test
    fun `a custom scheme or loopback redirect is refused at wiring time as InvalidConfiguration`() {
        for (redirect in listOf("com.example.app:/oauth", "http://127.0.0.1:8080/oauth")) {
            val error = assertThrows(redirect, VersolaError.Configuration::class.java) {
                EdgeAuthorizationStarter(VersolaConfiguration.create(ISSUER, "mobile-app", redirect), FakeNative())
            }
            assertTrue(redirect, error.detail is VersolaError.Configuration.Detail.InvalidConfiguration)
        }
    }

    @Test
    fun `an https App Link redirect is accepted`() {
        EdgeAuthorizationStarter(configuration, FakeNative())
    }
}
