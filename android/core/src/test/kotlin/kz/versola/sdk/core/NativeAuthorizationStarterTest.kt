package kz.versola.sdk.core

import kotlinx.coroutines.test.runTest
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** Records the URL each proof was minted for and what each response taught it. */
private class StarterProofSource : DpopProofSource {
    val proofsFor = mutableListOf<String>()
    val observed = mutableListOf<Triple<String, String?, String?>>()

    override suspend fun proof(method: String, url: String, accessToken: String?): String {
        proofsFor += url
        return "proof-${proofsFor.size}"
    }

    override fun observe(url: String, dateHeader: String?, nonceHeader: String?) {
        observed += Triple(url, dateHeader, nonceHeader)
    }
}

class NativeAuthorizationStarterTest {

    private lateinit var server: MockWebServer
    private lateinit var edge: String
    private lateinit var proofs: StarterProofSource

    @Before
    fun start() {
        server = MockWebServer()
        server.start()
        edge = server.url("/").toString().trimEnd('/')
        proofs = StarterProofSource()
    }

    @After
    fun stop() {
        server.close()
    }

    private fun starter(clientId: String = "mobile-app") = HttpNativeAuthorizationStarter(
        configuration = VersolaConfiguration.create("https://id.versola.kz", clientId, "https://app.example.com/oauth"),
        edgeBaseUrl = edge,
        httpClient = OkHttpClient(),
        dpop = proofs,
    )

    private fun request() = NativeStartRequest(
        redirectUri = "https://app.example.com/oauth",
        scopes = setOf("openid", "offline_access"),
        nonce = "the-nonce",
        acrValues = listOf("urn:versola:mfa"),
        maxAge = 300,
    )

    private fun started() = MockResponse.Builder()
        .code(200)
        .setHeader("Content-Type", "application/json")
        .body(
            """{"client_id":"mobile-app","request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":60,""" +
                """"authorization_endpoint":"https://id.versola.kz/authorize","state":"edge-state","blob":"sealed",""" +
                """"token_endpoint":"https://id.versola.kz:9008/token","revocation_endpoint":"https://id.versola.kz:9008/revoke"}""",
        )
        .build()

    @Test
    fun `start posts the pass-through parameters with a proof for edge's own URL and nothing of its own`() = runTest {
        server.enqueue(started())

        val start = starter().start(request())

        val request = server.takeRequest()
        assertEquals("/native/start/mobile-app", request.url.encodedPath)
        assertEquals("proof-1", request.headers["DPoP"])
        assertEquals(listOf("$edge/native/start/mobile-app"), proofs.proofsFor)
        val body = request.body!!.utf8()
        assertTrue(body.contains("redirect_uri=https%3A%2F%2Fapp.example.com%2Foauth"))
        assertTrue(body.contains("scope=openid%20offline_access"))
        assertTrue(body.contains("nonce=the-nonce"))
        assertTrue(body.contains("acr_values=urn%3Aversola%3Amfa"))
        assertTrue(body.contains("max_age=300"))
        // PKCE, `state`, `response_type` and `dpop_jkt` are edge's: the server refuses them
        // from the app, and sending them would claim what only edge can verify.
        assertFalse(body.contains("code_challenge"))
        assertFalse(body.contains("state="))
        assertFalse(body.contains("dpop_jkt"))
        assertFalse(body.contains("client_id"))
        assertEquals("edge-state", start.state)
        assertEquals("sealed", start.blob)
        assertEquals("https://id.versola.kz:9008/token", start.tokenEndpoint)
        assertEquals("urn:ietf:params:oauth:request_uri:abc", start.requestUri)
    }

    @Test
    fun `edge's nonce challenge is answered once, from the 401 shape its proxy uses`() = runTest {
        server.enqueue(
            MockResponse.Builder().code(401)
                .setHeader("WWW-Authenticate", """DPoP error="use_dpop_nonce"""")
                .setHeader("DPoP-Nonce", "edge-nonce-1")
                .build(),
        )
        server.enqueue(started())

        starter().start(request())

        assertEquals(2, server.requestCount)
        // Cached under edge's origin, where the authenticated client's API calls will also
        // find it (scenario 04): the nonce is edge's, and so is the next proof.
        assertEquals("$edge/native/start/mobile-app", proofs.observed.first().first)
        assertEquals("edge-nonce-1", proofs.observed.first().third)
        assertEquals(2, proofs.proofsFor.size)
    }

    @Test
    fun `a second nonce challenge is NonceLoop, not a third attempt`() = runTest {
        repeat(3) {
            server.enqueue(
                MockResponse.Builder().code(401)
                    .setHeader("WWW-Authenticate", """DPoP error="use_dpop_nonce"""")
                    .setHeader("DPoP-Nonce", "n$it")
                    .build(),
            )
        }

        val error = failure { starter().start(request()) } as VersolaError.Recoverable

        assertTrue(error.reason is VersolaError.Recoverable.Cause.NonceLoop)
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `a client edge does not front is named as such`() = runTest {
        server.enqueue(MockResponse.Builder().code(404).build())

        val error = failure { starter("web-app").start(request()) } as VersolaError.Configuration

        assertEquals(VersolaError.Configuration.Detail.EdgeClientUnknown("web-app"), error.detail)
    }

    @Test
    fun `a relayed PAR refusal is the authorization error the browser would have shown`() = runTest {
        server.enqueue(
            MockResponse.Builder().code(400).setHeader("Content-Type", "application/json")
                .body("""{"error":"invalid_scope","error_description":"scope not registered"}""")
                .build(),
        )

        val error = failure { starter().start(request()) } as VersolaError.Configuration

        assertEquals(
            VersolaError.Configuration.Detail.AuthorizationRejected("invalid_scope", "scope not registered"),
            error.detail,
        )
    }

    @Test
    fun `an unavailable edge is Recoverable and a redirect is Configuration`() = runTest {
        server.enqueue(MockResponse.Builder().code(503).build())
        assertTrue(failure { starter().start(request()) } is VersolaError.Recoverable)

        server.enqueue(MockResponse.Builder().code(307).setHeader("Location", "https://elsewhere/").build())
        assertTrue(failure { starter().start(request()) } is VersolaError.Configuration)
        assertNull(server.takeRequest().headers["Idempotency-Key"])
    }

    @Test
    fun `a start response missing what the exchange needs is refused before the browser opens`() = runTest {
        server.enqueue(
            MockResponse.Builder().code(200).setHeader("Content-Type", "application/json")
                .body("""{"request_uri":"urn:x","state":"s","authorization_endpoint":"https://id/authorize"}""")
                .build(),
        )

        val error = failure { starter().start(request()) } as VersolaError.Configuration

        assertTrue(error.detail is VersolaError.Configuration.Detail.TokenResponseMalformed)
    }

    @Test
    fun `a client id with reserved characters is path-encoded`() = runTest {
        server.enqueue(started())

        starter("acme/mobile app").start(request())

        assertEquals("/native/start/acme%2Fmobile%20app", server.takeRequest().url.encodedPath)
    }

    @Test
    fun `the WWW-Authenticate error is read by parameter, never by scheme`() {
        assertEquals("use_dpop_nonce", wwwAuthenticateError(listOf("""DPoP error="use_dpop_nonce"""")))
        assertEquals(
            "insufficient_user_authentication",
            wwwAuthenticateError(listOf("""Bearer error="insufficient_user_authentication", acr_values="x"""")),
        )
        assertEquals("invalid_token", wwwAuthenticateError(listOf("""Bearer realm="UserInfo", error=invalid_token""")))
        assertNull(wwwAuthenticateError(listOf("Basic realm=\"x\"")))
        assertNull(wwwAuthenticateError(emptyList()))
    }
}
