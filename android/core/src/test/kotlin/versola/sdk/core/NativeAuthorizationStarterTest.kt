package versola.sdk.core

import versola.oauth.core.DpopProofSource
import versola.oauth.core.RetryPolicy
import versola.oauth.core.RetryScope
import versola.oauth.core.VersolaConfiguration
import versola.oauth.core.VersolaError
import versola.oauth.core.wwwAuthenticateError
import kotlinx.coroutines.test.runTest
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import java.net.URLDecoder
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** Records the URL each proof was minted for and what each response taught it. */
private class StarterProofSource : DpopProofSource {
    val proofsFor = mutableListOf<String>()
    val observed = mutableListOf<Triple<String, String?, String?>>()

    /** `proof` and `observe` in the order they happened: a corrected clock only helps a proof minted after it. */
    val order = mutableListOf<String>()

    override suspend fun proof(method: String, url: String, accessToken: String?): String {
        proofsFor += url
        order += "proof-${proofsFor.size}"
        return "proof-${proofsFor.size}"
    }

    override fun observe(url: String, dateHeader: String?, nonceHeader: String?) {
        observed += Triple(url, dateHeader, nonceHeader)
        order += "observe"
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
        configuration = VersolaConfiguration.create("https://id.versola.io", clientId, "https://app.example.com/oauth"),
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
                """"authorization_endpoint":"https://id.versola.io/authorize","state":"edge-state","blob":"sealed",""" +
                """"token_endpoint":"https://id.versola.io:9008/token","revocation_endpoint":"https://id.versola.io:9008/revoke"}""",
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
        assertEquals("https://id.versola.io:9008/token", start.tokenEndpoint)
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

    private fun invalidProof(date: String = SERVER_DATE) = MockResponse.Builder().code(400)
        .setHeader("Content-Type", "application/json")
        .setHeader("Date", date)
        .body("""{"error":"invalid_dpop_proof","error_description":"iat outside the window"}""")
        .build()

    // Edge relays auth's refusal as a 400 JSON body. The one recoverable cause is clock skew, and the
    // `Date` of the refusal is what corrects it, so the repeat is a new proof minted after it was observed.
    @Test
    fun `an invalid_dpop_proof is retried once with a new proof minted after the Date was observed`() = runTest {
        server.enqueue(invalidProof())
        server.enqueue(started())

        val start = starter().start(request())

        assertEquals("edge-state", start.state)
        assertEquals(2, server.requestCount)
        assertEquals(listOf("proof-1", "observe", "proof-2", "observe"), proofs.order)
        assertEquals(SERVER_DATE, proofs.observed.first().second)
        val first = server.takeRequest()
        val second = server.takeRequest()
        assertEquals("proof-1", first.headers["DPoP"])
        assertEquals("a new jti: another proof, not the first resent", "proof-2", second.headers["DPoP"])
    }

    @Test
    fun `an invalid_dpop_proof in edge's 401 shape is retried the same way`() = runTest {
        server.enqueue(
            MockResponse.Builder().code(401)
                .setHeader("WWW-Authenticate", """DPoP error="invalid_dpop_proof"""")
                .setHeader("Date", SERVER_DATE)
                .build(),
        )
        server.enqueue(started())

        starter().start(request())

        assertEquals(2, server.requestCount)
    }

    @Test
    fun `a second invalid_dpop_proof is Reauthenticate CredentialsInvalidated after exactly two requests`() = runTest {
        server.enqueue(invalidProof())
        server.enqueue(invalidProof())
        server.enqueue(started())

        val error = failure { starter().start(request()) } as VersolaError.Reauthenticate

        assertSame(VersolaError.Reauthenticate.Reason.CredentialsInvalidated, error.reason)
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `an invalid_request is still a Configuration refusal and is not retried`() = runTest {
        server.enqueue(
            MockResponse.Builder().code(400).setHeader("Content-Type", "application/json")
                .body("""{"error":"invalid_request"}""").build(),
        )

        val error = failure { starter().start(request()) } as VersolaError.Configuration

        assertTrue(error.detail is VersolaError.Configuration.Detail.AuthorizationRejected)
        assertEquals(1, server.requestCount)
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

        assertEquals(EdgeClientUnknown("web-app"), error.detail)
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
    fun `an unavailable edge is Recoverable Server and a redirect is Configuration`() = runTest {
        server.enqueue(MockResponse.Builder().code(503).build())
        val unavailable = failure { starter().start(request()) } as VersolaError.Recoverable
        val cause = unavailable.reason as VersolaError.Recoverable.Cause.Server
        assertEquals(503, cause.status)
        assertNull(cause.retryAfterMillis)

        server.enqueue(MockResponse.Builder().code(307).setHeader("Location", "https://elsewhere/").build())
        assertTrue(failure { starter().start(request()) } is VersolaError.Configuration)
        server.takeRequest()
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

    // ---- the form: every pass-through parameter, and never what only edge may set -------------

    /** The form as the server decodes it: name to every value sent under it, in order. */
    private fun decoded(body: String): Map<String, List<String>> =
        body.split('&').filter { it.isNotEmpty() }
            .map { it.split('=', limit = 2) }
            .groupBy({ URLDecoder.decode(it[0], "UTF-8") }, { URLDecoder.decode(it[1], "UTF-8") })

    private fun fullRequest() = NativeStartRequest(
        redirectUri = "https://app.example.com/oauth",
        scopes = setOf("openid", "offline_access"),
        nonce = "the-nonce",
        acrValues = listOf("urn:versola:mfa", "urn:versola:pwd"),
        maxAge = 300,
        prompt = "login",
        loginHint = "user@example.com",
        uiLocales = listOf("fr-CA", "en"),
        resources = listOf("https://api.example.com/a", "https://api.example.com/b"),
        claims = """{"id_token":{"email":null}}""",
        authorizationDetails = """[{"type":"payment","amount":"1 & 2=3"}]""",
    )

    @Test
    fun `every pass-through parameter is sent as its own form field`() = runTest {
        server.enqueue(started())

        starter().start(fullRequest())

        val form = decoded(server.takeRequest().body!!.utf8())
        assertEquals(listOf("login"), form["prompt"])
        assertEquals(listOf("user@example.com"), form["login_hint"])
        assertEquals(listOf("fr-CA en"), form["ui_locales"])
        assertEquals(listOf("""{"id_token":{"email":null}}"""), form["claims"])
        assertEquals(listOf("""[{"type":"payment","amount":"1 & 2=3"}]"""), form["authorization_details"])
        assertEquals(listOf("urn:versola:mfa urn:versola:pwd"), form["acr_values"])
        assertEquals(listOf("openid offline_access"), form["scope"])
        assertEquals(listOf("300"), form["max_age"])
    }

    @Test
    fun `resource is repeated once per value`() = runTest {
        server.enqueue(started())

        starter().start(fullRequest())

        val body = server.takeRequest().body!!.utf8()
        assertEquals(listOf("https://api.example.com/a", "https://api.example.com/b"), decoded(body)["resource"])
        assertEquals(2, body.split('&').count { it.startsWith("resource=") })
    }

    @Test
    fun `an absent optional parameter is not sent at all`() = runTest {
        server.enqueue(started())

        starter().start(NativeStartRequest("https://app.example.com/oauth", setOf("openid"), "n"))

        val form = decoded(server.takeRequest().body!!.utf8())
        assertEquals(setOf("redirect_uri", "scope", "nonce"), form.keys)
    }

    @Test
    fun `what only edge may set is never sent, however much else is`() = runTest {
        server.enqueue(started())

        starter().start(fullRequest())

        val names = decoded(server.takeRequest().body!!.utf8()).keys
        for (forbidden in listOf(
            "client_id", "state", "response_type", "code_challenge", "code_challenge_method", "dpop_jkt", "id_token_hint",
        )) {
            assertFalse(forbidden, forbidden in names)
        }
    }

    // ---- /native/start answers the flow cannot use -----------------------------------------

    private fun startedWith(vararg replace: Pair<String, String>): MockResponse {
        var text = """{"client_id":"mobile-app","request_uri":"urn:ietf:params:oauth:request_uri:abc","expires_in":60,""" +
            """"authorization_endpoint":"https://id.versola.io/authorize","state":"edge-state","blob":"sealed",""" +
            """"token_endpoint":"https://id.versola.io:9008/token","revocation_endpoint":"https://id.versola.io:9008/revoke"}"""
        for ((from, to) in replace) {
            check(from in text) { from }
            text = text.replace(from, to)
        }
        return MockResponse.Builder().code(200).setHeader("Content-Type", "application/json").body(text).build()
    }

    private suspend fun refusedAsMalformed(response: MockResponse) {
        server.enqueue(response)
        val error = failure { starter().start(request()) } as VersolaError.Configuration
        assertTrue(error.detail.toString(), error.detail is VersolaError.Configuration.Detail.TokenResponseMalformed)
    }

    @Test
    fun `a start answer without an authorization_endpoint is refused before the browser opens`() = runTest {
        refusedAsMalformed(startedWith(""""authorization_endpoint":"https://id.versola.io/authorize",""" to ""))
    }

    @Test
    fun `a start answer without expires_in, or with one that is not positive, is refused`() = runTest {
        refusedAsMalformed(startedWith(""""expires_in":60,""" to ""))
        refusedAsMalformed(startedWith(""""expires_in":60""" to """"expires_in":0"""))
        refusedAsMalformed(startedWith(""""expires_in":60""" to """"expires_in":-5"""))
    }

    @Test
    fun `an authorization_endpoint, token_endpoint or revocation_endpoint that is not https is refused`() = runTest {
        refusedAsMalformed(startedWith("https://id.versola.io/authorize" to "http://id.versola.io/authorize"))
        refusedAsMalformed(startedWith("https://id.versola.io:9008/token" to "http://id.versola.io:9008/token"))
        refusedAsMalformed(startedWith("https://id.versola.io:9008/revoke" to "http://id.versola.io:9008/revoke"))
    }

    @Test
    fun `an endpoint with another scheme, or that is not a URL, is refused`() = runTest {
        refusedAsMalformed(startedWith("https://id.versola.io/authorize" to "javascript:alert(1)"))
        refusedAsMalformed(startedWith("https://id.versola.io/authorize" to "com.example.app://authorize"))
        refusedAsMalformed(startedWith("https://id.versola.io:9008/token" to "not a url"))
    }

    @Test
    fun `cleartext is accepted for localhost, 127_0_0_1 and the IPv6 loopback only`() {
        for (host in listOf("localhost:8080", "127.0.0.1:8080", "[::1]:8080")) {
            val start = NativeStart(
                requestUri = "urn:x", expiresIn = 60, authorizationEndpoint = "http://$host/authorize", state = "s",
                blob = "b", tokenEndpoint = "http://$host/token", revocationEndpoint = "http://$host/revoke",
            )
            assertSame(host, start, start.validate())
        }
        for (host in listOf("10.0.2.2:8080", "192.168.1.5", "id.example.com", "localhost.example.com", "127.0.0.2")) {
            val start = NativeStart(
                requestUri = "urn:x", expiresIn = 60, authorizationEndpoint = "http://$host/authorize", state = "s",
                blob = "b", tokenEndpoint = "https://id.example.com/token", revocationEndpoint = "https://id.example.com/revoke",
            )
            val error = assertThrows(host, VersolaError.Configuration::class.java) { start.validate() }
            assertTrue(host, error.detail is VersolaError.Configuration.Detail.TokenResponseMalformed)
        }
    }

    @Test
    fun `the refusal names the member and never echoes its value`() = runTest {
        server.enqueue(startedWith("https://id.versola.io:9008/token" to "http://secret-host.example.com/token"))

        val error = failure { starter().start(request()) } as VersolaError.Configuration

        val message = error.detail.toString() + error.message
        assertTrue(message, message.contains("token_endpoint"))
        assertFalse(message, message.contains("secret-host"))
    }

    @Test
    fun `a start answer prints without its blob or its state`() {
        val start = NativeStart(
            clientId = "mobile-app", requestUri = "urn:x", expiresIn = 60, authorizationEndpoint = "https://id.example.com/authorize",
            state = "the-state-secret", blob = "the-blob-secret", tokenEndpoint = "https://id.example.com/token",
            revocationEndpoint = "https://id.example.com/revoke",
        )

        val printed = start.toString()

        assertFalse(printed, printed.contains("the-blob-secret"))
        assertFalse(printed, printed.contains("the-state-secret"))
        assertFalse(printed, printed.contains("urn:x"))
    }

    // ---- server faults: 429 and 503 are the server's, read with Retry-After ------------------

    @Test
    fun `a 429 or 503 is Recoverable Server with the Retry-After read in seconds`() = runTest {
        for (status in listOf(429, 503)) {
            server.enqueue(MockResponse.Builder().code(status).setHeader("Retry-After", "7").build())

            val error = failure { starter().start(request()) } as VersolaError.Recoverable

            val cause = error.reason as VersolaError.Recoverable.Cause.Server
            assertEquals(status, cause.status)
            assertEquals("$status", 7_000L, cause.retryAfterMillis)
            assertFalse("$status is the server's, not the network's", error.reason is VersolaError.Recoverable.Cause.Network)
        }
    }

    @Test
    fun `a 500 is Recoverable Server 500 with no Retry-After read`() = runTest {
        server.enqueue(MockResponse.Builder().code(500).setHeader("Retry-After", "7").build())

        val error = failure { starter().start(request()) } as VersolaError.Recoverable

        val cause = error.reason as VersolaError.Recoverable.Cause.Server
        assertEquals(500, cause.status)
        assertNull(cause.retryAfterMillis)
    }

    @Test
    fun `outside any operation a 429 is made once`() = runTest {
        server.enqueue(MockResponse.Builder().code(429).setHeader("Retry-After", "0").build())
        server.enqueue(started())

        val error = failure { starter().start(request()) } as VersolaError.Recoverable

        assertEquals(429, (error.reason as VersolaError.Recoverable.Cause.Server).status)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `inside a retry budget a 429 with Retry-After 0 is repeated and every attempt carries a new proof`() = runTest {
        server.enqueue(MockResponse.Builder().code(429).setHeader("Retry-After", "0").build())
        server.enqueue(MockResponse.Builder().code(429).setHeader("Retry-After", "0").build())
        server.enqueue(started())

        val start = RetryScope(RetryPolicy()).operation { starter().start(request()) }

        assertEquals("edge-state", start.state)
        assertEquals(3, server.requestCount)
        val sent = List(3) { server.takeRequest().headers["DPoP"] }
        assertEquals(listOf("proof-1", "proof-2", "proof-3"), sent)
        assertEquals(3, sent.toSet().size)
        assertEquals(List(3) { "$edge/native/start/mobile-app" }, proofs.proofsFor)
    }

    @Test
    fun `inside a retry budget a 503 with a small Retry-After is repeated and the form is intact each time`() = runTest {
        server.enqueue(MockResponse.Builder().code(503).setHeader("Retry-After", "1").build())
        server.enqueue(started())

        RetryScope(RetryPolicy()).operation { starter().start(fullRequest()) }

        assertEquals(2, server.requestCount)
        val first = server.takeRequest().body!!.utf8()
        val second = server.takeRequest().body!!.utf8()
        assertTrue(first.contains("nonce=the-nonce"))
        assertEquals(first, second)
    }

    @Test
    fun `inside a retry budget a server that keeps answering 503 ends in Recoverable Server after the allowed attempts`() = runTest {
        // No `Retry-After: 0` here: OkHttp itself repeats a 503 that carries one, which would make the count of requests OkHttp's.
        repeat(5) { server.enqueue(MockResponse.Builder().code(503).build()) }

        val error = failure { RetryScope(RetryPolicy()).operation { starter().start(request()) } } as VersolaError.Recoverable

        val cause = error.reason as VersolaError.Recoverable.Cause.Server
        assertEquals(503, cause.status)
        assertEquals(3, cause.attempts)
        assertEquals(3, server.requestCount)
    }

    @Test
    fun `a refusal with an OAuth error is not repeated inside a budget`() = runTest {
        server.enqueue(
            MockResponse.Builder().code(400).setHeader("Content-Type", "application/json")
                .body("""{"error":"invalid_scope"}""").build(),
        )
        server.enqueue(started())

        failure { RetryScope(RetryPolicy()).operation { starter().start(request()) } }

        assertEquals(1, server.requestCount)
    }

    @Test
    fun `a 404 inside a budget is still the unknown client and is not repeated`() = runTest {
        server.enqueue(MockResponse.Builder().code(404).build())
        server.enqueue(started())

        val error = failure { RetryScope(RetryPolicy()).operation { starter().start(request()) } } as VersolaError.Configuration

        assertEquals(EdgeClientUnknown("mobile-app"), error.detail)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `the nonce challenge inside a budget is still answered exactly once and a second is NonceLoop`() = runTest {
        repeat(3) {
            server.enqueue(
                MockResponse.Builder().code(401)
                    .setHeader("WWW-Authenticate", """DPoP error="use_dpop_nonce"""")
                    .setHeader("DPoP-Nonce", "n$it")
                    .build(),
            )
        }

        val error = failure { RetryScope(RetryPolicy()).operation { starter().start(request()) } } as VersolaError.Recoverable

        assertTrue(error.reason is VersolaError.Recoverable.Cause.NonceLoop)
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `the answer to a nonce challenge carries a new proof`() = runTest {
        server.enqueue(
            MockResponse.Builder().code(401)
                .setHeader("WWW-Authenticate", """DPoP error="use_dpop_nonce"""")
                .setHeader("DPoP-Nonce", "edge-nonce-1")
                .build(),
        )
        server.enqueue(started())

        starter().start(request())

        assertEquals("proof-1", server.takeRequest().headers["DPoP"])
        assertEquals("proof-2", server.takeRequest().headers["DPoP"])
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

private const val SERVER_DATE = "Tue, 15 Nov 1994 08:12:31 GMT"
