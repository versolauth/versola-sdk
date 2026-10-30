package versola.oauth.core

import kotlinx.coroutines.test.runTest
import kotlin.random.Random
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

class UserInfoClientTest {

    private lateinit var server: MockWebServer
    private lateinit var endpoint: String
    private lateinit var jwksUri: String

    @Before
    fun start() {
        server = MockWebServer()
        server.start()
        endpoint = server.url("/userinfo").toString()
        jwksUri = server.url("/jwks.json").toString()
    }

    @After
    fun stop() {
        server.close()
    }

    private class RecordingDpop : DpopProofSource {
        val proofs = mutableListOf<Triple<String, String, String?>>()
        val observed = mutableListOf<Triple<String, String?, String?>>()

        override suspend fun proof(method: String, url: String, accessToken: String?): String {
            proofs += Triple(method, url, accessToken)
            return "proof-${proofs.size}"
        }

        override fun observe(url: String, dateHeader: String?, nonceHeader: String?) {
            observed += Triple(url, dateHeader, nonceHeader)
        }
    }

    private fun client(
        endpoint: String? = this.endpoint,
        dpop: DpopProofSource? = null,
    ) = HttpUserInfoClient(
        userinfoEndpoint = { endpoint },
        httpClient = OkHttpClient(),
        dpop = dpop,
        verifier = JwsVerifier({ jwksUri }, { emptyList() }, JwksClient(OkHttpClient())),
    )

    /** A source that hands out one token and, on renewal, the same or another. */
    class FixedTokens(private val token: AccessToken, private val renewed: AccessToken = token) : AccessTokenSource {
        var renewals = 0
        override suspend fun accessToken(): AccessToken = token
        override suspend fun renewAccessToken(): AccessToken {
            renewals++
            return renewed
        }
    }

    private fun tokens(token: AccessToken) = FixedTokens(token)

    private val bearer = AccessToken("token-1", isDpopBound = false)
    private val bound = AccessToken("token-1", isDpopBound = true)
    private val json = """{"sub":"user-1","name":"Alice Example","email_verified":true,"address":{"country":"KZ"}}"""

    private fun serveJson(body: String = json) {
        server.enqueue(MockResponse.Builder().code(200).addHeader("Content-Type", "application/json").body(body).build())
    }

    private fun serveJwt(compact: String, contentType: String = "application/jwt") {
        server.enqueue(MockResponse.Builder().code(200).addHeader("Content-Type", contentType).body(compact).build())
    }

    private fun serveJwks() {
        server.enqueue(MockResponse.Builder().code(200).body(Jose.jwks(Jose.jwk(Jose.rsa, "rsa"), Jose.jwk(Jose.p256, "p256"))).build())
    }

    private fun signed(claims: String = json, key: java.security.KeyPair = Jose.rsa, alg: String = "RS256", kid: String = "rsa") =
        Jose.jws(alg, key.private, claims, kid = kid)

    private suspend fun detail(block: suspend () -> Unit): VersolaError.Configuration.Detail =
        (failure(block) as VersolaError.Configuration).detail

    // --- JSON responses ----------------------------------------------------------------------

    @Test
    fun `a bearer token is sent as Bearer with no proof and the JSON claims come back as strings`() = runTest {
        serveJson()

        val info = client().fetch(tokens(bearer), "user-1")

        assertEquals("user-1", info.subject)
        assertEquals("Alice Example", info.claims["name"])
        assertEquals("true", info.claims["email_verified"])
        assertEquals("""{"country":"KZ"}""", info.claims["address"])
        val request = server.takeRequest()
        assertEquals("GET", request.method)
        assertEquals("/userinfo", request.target)
        assertEquals("Bearer token-1", request.headers["Authorization"])
        assertNull(request.headers["DPoP"])
    }

    @Test
    fun `a DPoP-bound token is sent as DPoP with a proof for GET on the endpoint and the token`() = runTest {
        val dpop = RecordingDpop()
        serveJson()

        client(dpop = dpop).fetch(tokens(bound), "user-1")

        val request = server.takeRequest()
        assertEquals("DPoP token-1", request.headers["Authorization"])
        assertEquals("proof-1", request.headers["DPoP"])
        assertEquals(listOf(Triple("GET", endpoint, "token-1" as String?)), dpop.proofs)
        assertEquals(endpoint, dpop.observed.single().first)
    }

    @Test
    fun `a bearer token is not given a proof even when a proof source is wired`() = runTest {
        val dpop = RecordingDpop()
        serveJson()

        client(dpop = dpop).fetch(tokens(bearer), "user-1")

        assertEquals("Bearer token-1", server.takeRequest().headers["Authorization"])
        assertTrue(dpop.proofs.isEmpty())
    }

    @Test
    fun `a bound token without a proof source is InvalidConfiguration and nothing is sent`() = runTest {
        val reason = detail { client(dpop = null).fetch(tokens(bound), "user-1") }

        assertTrue(reason is VersolaError.Configuration.Detail.InvalidConfiguration)
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `a missing userinfo_endpoint is ProviderUnsupported and nothing is sent`() = runTest {
        val reason = detail { client(endpoint = null).fetch(tokens(bearer), "user-1") }

        assertEquals(VersolaError.Configuration.Detail.ProviderUnsupported("userinfo_endpoint"), reason)
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `a sub that differs from the ID token's is UserInfoRejected without echoing either value`() = runTest {
        serveJson()

        val reason = detail { client().fetch(tokens(bearer), "user-2") }

        val rejected = reason as VersolaError.Configuration.Detail.UserInfoRejected
        assertTrue(rejected.detail.startsWith("sub"))
        assertFalse(rejected.detail.contains("user-1"))
        assertFalse(rejected.detail.contains("user-2"))
    }

    @Test
    fun `a response without sub is UserInfoRejected`() = runTest {
        serveJson("""{"name":"Alice"}""")

        assertTrue(detail { client().fetch(tokens(bearer), "user-1") } is VersolaError.Configuration.Detail.UserInfoRejected)
    }

    @Test
    fun `a sub of the wrong type is UserInfoRejected`() = runTest {
        serveJson("""{"sub":1}""")

        assertTrue(detail { client().fetch(tokens(bearer), "1") } is VersolaError.Configuration.Detail.UserInfoRejected)
    }

    @Test
    fun `a body that is not a JSON object is UserInfoRejected`() = runTest {
        serveJson("<html>oops</html>")

        assertTrue(detail { client().fetch(tokens(bearer), "user-1") } is VersolaError.Configuration.Detail.UserInfoRejected)
    }

    // --- status mapping ----------------------------------------------------------------------

    @Test
    fun `a bare 401 spends one renewal and one replay before it is Reauthenticate`() = runTest {
        server.enqueue(MockResponse.Builder().code(401).addHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"").build())
        server.enqueue(MockResponse.Builder().code(401).addHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"").build())
        val tokens = FixedTokens(bearer, renewed = AccessToken("token-2", isDpopBound = false))

        val reauthenticate = runCatching { client().fetch(tokens, "user-1") }.exceptionOrNull() as VersolaError.Reauthenticate

        assertEquals(VersolaError.Reauthenticate.Reason.SessionRejected, reauthenticate.reason)
        assertEquals(1, tokens.renewals)
        assertEquals(2, server.requestCount)
        server.takeRequest()
        assertEquals("Bearer token-2", server.takeRequest().headers["Authorization"])
    }

    @Test
    fun `a 401 cleared by one renewal answers with the replayed request`() = runTest {
        server.enqueue(MockResponse.Builder().code(401).addHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"").build())
        serveJson("""{"sub":"user-1","name":"Alice"}""")
        val tokens = FixedTokens(bearer, renewed = AccessToken("token-2", isDpopBound = false))

        val info = client().fetch(tokens, "user-1")

        assertEquals("user-1", info.subject)
        assertEquals(1, tokens.renewals)
    }

    @Test
    fun `a 500 is a Server failure and is not retried here`() = runTest {
        server.enqueue(MockResponse.Builder().code(500).build())

        val error = failure { client().fetch(tokens(bearer), "user-1") }

        assertTrue((error as VersolaError.Recoverable).reason is VersolaError.Recoverable.Cause.Server)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `a redirect is not followed and is a Configuration fault, never repeated`() = runTest {
        server.enqueue(MockResponse.Builder().code(302).addHeader("Location", server.url("/elsewhere").toString()).build())
        serveJson()

        val error = failure { RetryScope(RetryPolicy(), { 0L }, kotlin.random.Random(1)).operation { client().fetch(tokens(bearer), "user-1") } }

        assertTrue(error is VersolaError.Configuration)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `a repeated DPoP-bound request carries a fresh proof on every attempt`() = runTest {
        // A proof is single-use (RFC 9449 section 11.1: a resource server detects replay by jti), so a
        // repeat that re-sent the first attempt's proof would be refused as a replay, turning a
        // transient failure into a different, non-transient one.
        server.enqueue(MockResponse.Builder().code(503).build())
        server.enqueue(MockResponse.Builder().code(503).build())
        serveJson()
        val dpop = RecordingDpop()

        RetryScope(RetryPolicy(), { testScheduler.currentTime }, kotlin.random.Random(1))
            .operation { client(dpop = dpop).fetch(tokens(bound), "user-1") }

        assertEquals(3, dpop.proofs.size)
        val sent = (1..3).map { server.takeRequest().headers["DPoP"] }
        assertEquals(listOf("proof-1", "proof-2", "proof-3"), sent)
    }

    @Test
    fun `an unreachable endpoint is a Network failure`() = runTest {
        val dead = endpoint
        server.close()

        val error = failure { client(endpoint = dead).fetch(tokens(bearer), "user-1") }

        assertTrue((error as VersolaError.Recoverable).reason is VersolaError.Recoverable.Cause.Network)
    }

    // --- DPoP nonce --------------------------------------------------------------------------

    @Test
    fun `a use_dpop_nonce challenge is answered once with a fresh proof`() = runTest {
        val dpop = RecordingDpop()
        server.enqueue(
            MockResponse.Builder().code(401)
                .addHeader("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"")
                .addHeader("DPoP-Nonce", "n-1")
                .build(),
        )
        serveJson()

        val info = client(dpop = dpop).fetch(tokens(bound), "user-1")

        assertEquals("user-1", info.subject)
        assertEquals(2, server.requestCount)
        assertEquals(listOf("proof-1", "proof-2"), listOf(server.takeRequest().headers["DPoP"], server.takeRequest().headers["DPoP"]))
        assertEquals("n-1", dpop.observed.first().third)
    }

    @Test
    fun `a second use_dpop_nonce challenge is NonceLoop and ends the exchange`() = runTest {
        val dpop = RecordingDpop()
        repeat(3) {
            server.enqueue(
                MockResponse.Builder().code(401)
                    .addHeader("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"")
                    .addHeader("DPoP-Nonce", "n")
                    .build(),
            )
        }

        val error = failure { client(dpop = dpop).fetch(tokens(bound), "user-1") }

        assertTrue((error as VersolaError.Recoverable).reason is VersolaError.Recoverable.Cause.NonceLoop)
        assertEquals(2, server.requestCount)
    }

    // --- signed responses --------------------------------------------------------------------

    @Test
    fun `an application jwt response is verified against the JWK Set and its payload is used`() = runTest {
        serveJwt(signed())
        serveJwks()

        val info = client().fetch(tokens(bearer), "user-1")

        assertEquals("user-1", info.subject)
        assertEquals("Alice Example", info.claims["name"])
        assertEquals("/userinfo", server.takeRequest().target)
        assertEquals("/jwks.json", server.takeRequest().target)
    }

    @Test
    fun `an ES256 signed response verifies and a content type parameter is tolerated`() = runTest {
        serveJwt(signed(key = Jose.p256, alg = "ES256", kid = "p256"), contentType = "application/jwt; charset=utf-8")
        serveJwks()

        assertEquals("user-1", client().fetch(tokens(bearer), "user-1").subject)
    }

    @Test
    fun `a signed response with a bad signature is UserInfoRejected`() = runTest {
        serveJwt(signed(key = Jose.rsaOther))
        serveJwks()

        val reason = detail { client().fetch(tokens(bearer), "user-1") }

        assertTrue(reason is VersolaError.Configuration.Detail.UserInfoRejected)
    }

    @Test
    fun `a signed response using alg none is UserInfoRejected and the key set is never fetched`() = runTest {
        serveJwt(Jose.jws("none", null, json, header = """{"alg":"none"}"""))

        val reason = detail { client().fetch(tokens(bearer), "user-1") }

        assertTrue(reason is VersolaError.Configuration.Detail.UserInfoRejected)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `a signed response that is not a JWS is UserInfoRejected`() = runTest {
        serveJwt("not.a.jws.at.all")

        assertTrue(detail { client().fetch(tokens(bearer), "user-1") } is VersolaError.Configuration.Detail.UserInfoRejected)
    }

    @Test
    fun `a signed response with a different sub is UserInfoRejected`() = runTest {
        serveJwt(signed())
        serveJwks()

        val reason = detail { client().fetch(tokens(bearer), "user-2") }

        assertTrue(reason is VersolaError.Configuration.Detail.UserInfoRejected)
    }

    @Test
    fun `a signed response whose key set cannot be fetched is a Server failure`() = runTest {
        serveJwt(signed())
        server.enqueue(MockResponse.Builder().code(503).build())

        val error = failure { client().fetch(tokens(bearer), "user-1") }

        assertTrue((error as VersolaError.Recoverable).reason is VersolaError.Recoverable.Cause.Server)
    }

    // --- the value type ----------------------------------------------------------------------

    @Test
    fun `toString prints no claim`() {
        val info = UserInfo("user-1", mapOf("email" to "alice@example.com"))

        assertFalse(info.toString().contains("user-1"))
        assertFalse(info.toString().contains("alice"))
    }

    // ---- scenario 34, unit tier: UserInfo is repeated under the operation's budget -----------

    @Test
    fun `a 500, 503 or 429 on UserInfo is repeated three times and surfaced with its status`() = runTest {
        for (status in listOf(500, 503, 429)) {
            repeat(3) { server.enqueue(MockResponse.Builder().code(status).build()) }
            val before = server.requestCount

            val error = failure { RetryScope(RetryPolicy(), { testScheduler.currentTime }, Random(1)).operation { client().fetch(tokens(bearer), "user-1") } } as VersolaError.Recoverable

            val cause = error.reason as VersolaError.Recoverable.Cause.Server
            assertEquals(status, cause.status)
            assertEquals(3, cause.attempts)
            assertEquals("$status", 3, server.requestCount - before)
        }
    }

    @Test
    fun `UserInfo that answers 503 once and then the document succeeds`() = runTest {
        server.enqueue(MockResponse.Builder().code(503).build())
        serveJson()

        val info = RetryScope(RetryPolicy(), { testScheduler.currentTime }, Random(1)).operation { client().fetch(tokens(bearer), "user-1") }

        assertEquals("user-1", info.subject)
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `a 400, 403 or 404 on UserInfo is a Configuration fault after one request, never repeated`() = runTest {
        for (status in listOf(400, 403, 404)) {
            server.enqueue(MockResponse.Builder().code(status).build())
            val before = server.requestCount

            val error = failure { RetryScope(RetryPolicy(), { testScheduler.currentTime }, kotlin.random.Random(1)).operation { client().fetch(tokens(bearer), "user-1") } }

            val rejected = error as VersolaError.Configuration
            assertTrue("$status", rejected.detail is VersolaError.Configuration.Detail.UserInfoRejected)
            assertEquals("$status", 1, server.requestCount - before)
        }
    }

}
