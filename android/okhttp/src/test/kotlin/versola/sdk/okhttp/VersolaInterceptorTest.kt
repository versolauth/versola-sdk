package versola.sdk.okhttp

import versola.oauth.core.AccessToken
import versola.oauth.core.AccessTokenSource
import versola.oauth.core.DpopProofSource
import versola.oauth.core.VersolaError
import kotlinx.coroutines.runBlocking
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okio.BufferedSink
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import versola.sdk.dpop.ClockSkew
import versola.sdk.dpop.DpopKey
import versola.sdk.dpop.DpopProofFactory
import versola.sdk.dpop.KeyAttestation

/** Hands out tokens on demand and counts what was asked, so a refresh can be asserted absent. */
private class FakeTokenSource(
    private var current: AccessToken = AccessToken("token-0", isDpopBound = true),
) : AccessTokenSource {
    var issued = 0
    var renewals = 0
    var renewalFailure: VersolaError? = null
    var stepUps = 0
    /** A non-VersolaError failure, standing in for a Keystore or DataStore refusing. */
    var unexpectedFailure: Throwable? = null

    override fun stepUpRequired() {
        stepUps++
    }

    /** Runs on every accessToken() call, numbered from 1, so a test can simulate a
     *  concurrent refresh landing in the cache between two calls within one operation. */
    var onAccessToken: ((call: Int) -> Unit)? = null

    override suspend fun accessToken(): AccessToken {
        issued++
        unexpectedFailure?.let { throw it }
        onAccessToken?.invoke(issued)
        val value = current
        afterRead?.invoke()
        return value
    }

    /** Runs after the cached value was read and before it is handed back: a read that has gone stale on arrival. */
    var afterRead: (() -> Unit)? = null

    override suspend fun renewAccessToken(): AccessToken {
        renewals++
        renewalFailure?.let { throw it }
        current = AccessToken("token-$renewals", isDpopBound = current.isDpopBound)
        return current
    }

    fun forceCurrent(token: AccessToken) {
        current = token
    }
}

/** Records the `ath` input and the nonces it was handed, which is what scenario 04 asserts on. */
private class RecordingProofSource : DpopProofSource {
    var proofs = 0
    var failure: VersolaError? = null
    val boundTokens = mutableListOf<String?>()
    val observedNonces = mutableListOf<Pair<String, String?>>()

    override suspend fun proof(method: String, url: String, accessToken: String?): String {
        failure?.let { throw it }
        boundTokens += accessToken
        return "proof-${++proofs}"
    }

    override fun observe(url: String, dateHeader: String?, nonceHeader: String?) {
        observedNonces += url to nonceHeader
    }
}

class VersolaInterceptorTest {

    private lateinit var server: MockWebServer
    private lateinit var edge: HttpUrl
    private lateinit var tokens: FakeTokenSource
    private lateinit var proofs: RecordingProofSource

    @Before
    fun start() {
        server = MockWebServer()
        server.start()
        edge = server.url("/")
        tokens = FakeTokenSource()
        proofs = RecordingProofSource()
    }

    @After
    fun stop() {
        server.close()
    }

    private fun client(
        base: HttpUrl = edge,
        dpop: DpopProofSource? = proofs,
    ): OkHttpClient = OkHttpClient.Builder()
        .addInterceptor(VersolaInterceptor(tokens, base, dpop))
        .build()

    private fun get(path: String = "/resources/r/thing"): Request =
        Request.Builder().url(server.url(path)).build()

    private fun ok() = MockResponse.Builder().code(200).body("served").build()

    private fun status(code: Int) = MockResponse.Builder().code(code).body("upstream").build()

    private fun challenge(
        value: String,
        nonce: String? = null,
    ) = MockResponse.Builder()
        .code(401)
        .setHeader("WWW-Authenticate", value)
        .apply { nonce?.let { setHeader("DPoP-Nonce", it) } }
        .build()

    private fun failure(request: Request = get(), on: OkHttpClient = client()): VersolaError = try {
        on.newCall(request).execute().close()
        throw AssertionError("expected the call to fail")
    } catch (e: VersolaHttpException) {
        e.error
    }

    @Test
    fun `a call to edge carries the token under the DPoP scheme and a proof bound to it`() {
        server.enqueue(ok())

        client().newCall(get()).execute().use { assertEquals(200, it.code) }

        val recorded = server.takeRequest()
        assertEquals("DPoP token-0", recorded.headers["Authorization"])
        assertEquals("proof-1", recorded.headers["DPoP"])
        assertEquals(listOf("token-0"), proofs.boundTokens)
    }

    @Test
    fun `a bearer token is presented as Bearer and carries no proof`() {
        tokens = FakeTokenSource(AccessToken("token-0", isDpopBound = false))
        server.enqueue(ok())

        client().newCall(get()).execute().use { assertEquals(200, it.code) }

        val recorded = server.takeRequest()
        assertEquals("Bearer token-0", recorded.headers["Authorization"])
        assertNull(recorded.headers["DPoP"])
    }

    @Test
    fun `an Authorization and a DPoP header the app set are replaced, never sent beside ours (DPoP token)`() {
        server.enqueue(ok())
        val request = get().newBuilder()
            .addHeader("Authorization", "Bearer app-supplied")
            .addHeader("authorization", "Bearer app-supplied-too")
            .addHeader("DPoP", "app-forged")
            .build()

        client().newCall(request).execute().close()

        val recorded = server.takeRequest()
        assertEquals(listOf("DPoP token-0"), recorded.headers.values("Authorization"))
        assertEquals(listOf("proof-1"), recorded.headers.values("DPoP"))
    }

    @Test
    fun `an Authorization and a DPoP header the app set are replaced or dropped under a bearer token`() {
        tokens = FakeTokenSource(AccessToken("token-0", isDpopBound = false))
        server.enqueue(ok())
        val request = get().newBuilder()
            .addHeader("Authorization", "Bearer app-supplied")
            .addHeader("DPoP", "app-forged")
            .build()

        client().newCall(request).execute().close()

        val recorded = server.takeRequest()
        assertEquals(listOf("Bearer token-0"), recorded.headers.values("Authorization"))
        assertTrue(recorded.headers.values("DPoP").isEmpty())
    }

    @Test
    fun `the headers the app set on a request outside the scope are left as they were`() {
        server.enqueue(ok())
        val other = client(base = server.url("/resources/"))
        val request = get("/oauth/token").newBuilder()
            .addHeader("Authorization", "Bearer app-own-credential")
            .addHeader("DPoP", "app-own-proof")
            .build()

        other.newCall(request).execute().close()

        val recorded = server.takeRequest()
        assertEquals("Bearer app-own-credential", recorded.headers["Authorization"])
        assertEquals("app-own-proof", recorded.headers["DPoP"])
    }

    @Test
    fun `a request outside the edge base URL is passed through untouched`() {
        server.enqueue(ok())

        // The token endpoint lives on this same origin in a staged stack; the interceptor
        // must not authenticate the request that exists to obtain a token.
        val other = client(base = server.url("/resources/"))
        other.newCall(get("/oauth/token")).execute().use { assertEquals(200, it.code) }

        assertNull(server.takeRequest().headers["Authorization"])
        assertEquals(0, tokens.issued)
    }

    @Test
    fun `a path prefix is matched on whole segments, so resources does not claim resources-admin`() {
        server.enqueue(ok())

        client(base = server.url("/resources")).newCall(get("/resources-admin/x")).execute().close()

        assertNull(server.takeRequest().headers["Authorization"])
    }

    @Test
    fun `a nonce demand is answered once, against the nonce the challenge carried`() {
        server.enqueue(challenge("""DPoP error="use_dpop_nonce"""", nonce = "edge-nonce"))
        server.enqueue(ok())

        client().newCall(get()).execute().use { assertEquals(200, it.code) }

        assertEquals(2, server.requestCount)
        assertEquals("edge-nonce", proofs.observedNonces.first().second)
        // The nonce was cached against edge's origin by `observe`, and no token request was
        // made: a nonce demand is not an expiry (scenario 04).
        assertEquals(0, tokens.renewals)
    }

    @Test
    fun `a second nonce demand in one operation is a NonceLoop rather than a third attempt`() {
        server.enqueue(challenge("""DPoP error="use_dpop_nonce"""", nonce = "one"))
        server.enqueue(challenge("""DPoP error="use_dpop_nonce"""", nonce = "two"))

        val error = failure()

        assertTrue(error is VersolaError.Recoverable)
        assertTrue((error as VersolaError.Recoverable).reason is VersolaError.Recoverable.Cause.NonceLoop)
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `a nonce demand carrying no nonce is terminal, because nothing can answer it`() {
        server.enqueue(challenge("""DPoP error="use_dpop_nonce""""))

        val error = failure()

        assertTrue((error as VersolaError.Recoverable).reason is VersolaError.Recoverable.Cause.NonceLoop)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `an invalid proof is retried once with a freshly minted proof`() {
        server.enqueue(challenge("""DPoP error="invalid_dpop_proof""""))
        server.enqueue(ok())

        client().newCall(get()).execute().use { assertEquals(200, it.code) }

        assertEquals(2, proofs.proofs)
        assertEquals(0, tokens.renewals)
    }

    @Test
    fun `a second invalid proof is Reauthenticate, because a refresh reuses the same key`() {
        server.enqueue(challenge("""DPoP error="invalid_dpop_proof""""))
        server.enqueue(challenge("""DPoP error="invalid_dpop_proof""""))

        val error = failure()

        assertEquals(
            VersolaError.Reauthenticate.Reason.CredentialsInvalidated,
            (error as VersolaError.Reauthenticate).reason,
        )
        assertEquals(0, tokens.renewals)
    }

    @Test
    fun `a step-up surfaces its parameters and attempts no refresh`() {
        server.enqueue(
            challenge(
                """Bearer error="insufficient_user_authentication", acr_values="urn:a urn:b", max_age="120"""",
            ),
        )

        val error = failure()

        assertTrue(error is VersolaError.StepUp)
        assertEquals(listOf("urn:a", "urn:b"), (error as VersolaError.StepUp).acrValues)
        assertEquals(120L, error.maxAge)
        assertEquals(0, tokens.renewals)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `a bare 401 refreshes once and replays the call with the new token`() {
        server.enqueue(MockResponse.Builder().code(401).build())
        server.enqueue(ok())

        client().newCall(get()).execute().use { assertEquals(200, it.code) }

        assertEquals(1, tokens.renewals)
        server.takeRequest()
        assertEquals("DPoP token-1", server.takeRequest().headers["Authorization"])
    }

    @Test
    fun `a 401 after a refresh is SessionRejected rather than a second refresh`() {
        server.enqueue(MockResponse.Builder().code(401).build())
        server.enqueue(MockResponse.Builder().code(401).build())

        val error = failure()

        assertEquals(
            VersolaError.Reauthenticate.Reason.SessionRejected,
            (error as VersolaError.Reauthenticate).reason,
        )
        assertEquals(1, tokens.renewals)
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `a one-shot body refreshes but is not replayed, and the 401 is returned as it stands`() {
        server.enqueue(MockResponse.Builder().code(401).build())

        val oneShot = object : RequestBody() {
            override fun contentType() = null
            override fun isOneShot() = true
            override fun writeTo(sink: BufferedSink) {
                sink.writeUtf8("once")
            }
        }
        val request = Request.Builder().url(server.url("/resources/r/thing")).post(oneShot).build()

        client().newCall(request).execute().use { assertEquals(401, it.code) }

        // The refresh still happened, so the app's own retry of the operation — which is the
        // only party able to rebuild the body — starts from a usable token.
        assertEquals(1, tokens.renewals)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `a replayable body is sent again after the refresh`() {
        server.enqueue(MockResponse.Builder().code(401).build())
        server.enqueue(ok())

        val request = Request.Builder()
            .url(server.url("/resources/r/thing"))
            .post("payload".toRequestBody())
            .build()

        client().newCall(request).execute().use { assertEquals(200, it.code) }

        assertEquals("payload", server.takeRequest().body!!.utf8())
        assertEquals("payload", server.takeRequest().body!!.utf8())
    }

    @Test
    fun `403, 404, 429 and 5xx are returned as responses, never converted`() {
        for (code in listOf(403, 404, 429, 500, 503)) {
            server.enqueue(status(code))

            client().newCall(get()).execute().use { response ->
                assertEquals(code, response.code)
                assertEquals("upstream", response.body.string())
            }
        }

        // Nothing was retried and nothing was refreshed: at these statuses edge's own refusal
        // and the application's are indistinguishable, so neither is acted on.
        assertEquals(5, server.requestCount)
        assertEquals(0, tokens.renewals)
    }

    @Test
    fun `an error raised by the session is wrapped as an IOException, not thrown raw`() {
        server.enqueue(MockResponse.Builder().code(401).build())
        tokens.renewalFailure = VersolaError.Reauthenticate(
            VersolaError.Reauthenticate.Reason.GrantRejected,
        )

        val thrown = try {
            client().newCall(get()).execute().close()
            throw AssertionError("expected the call to fail")
        } catch (e: java.io.IOException) {
            e
        }

        // Anything other than an IOException out of an interceptor reaches the dispatcher's
        // uncaught handler on an enqueued call, which on Android ends the process.
        assertTrue(thrown is VersolaHttpException)
        assertEquals(
            VersolaError.Reauthenticate.Reason.GrantRejected,
            ((thrown as VersolaHttpException).error as VersolaError.Reauthenticate).reason,
        )
    }

    @Test
    fun `a DPoP-bound token with no proof source fails closed with InvalidConfiguration and nothing is sent`() {
        server.enqueue(ok())

        val error = failure(on = client(dpop = null))

        assertTrue(error.toString(), error is VersolaError.Configuration && error.detail is VersolaError.Configuration.Detail.InvalidConfiguration)
        assertEquals("not even as a Bearer", 0, server.requestCount)
        assertEquals(0, tokens.renewals)
    }

    @Test
    fun `a bearer token needs no proof source and is sent as Bearer without one`() {
        tokens = FakeTokenSource(AccessToken("token-0", isDpopBound = false))
        server.enqueue(ok())

        client(dpop = null).newCall(get()).execute().close()

        assertEquals("Bearer token-0", server.takeRequest().headers["Authorization"])
    }

    @Test
    fun `a VersolaError raised while signing the request is wrapped, not thrown raw`() {
        proofs.failure = VersolaError.Configuration(
            VersolaError.Configuration.Detail.InvalidConfiguration("no key"),
        )

        val thrown = try {
            client().newCall(get()).execute().close()
            throw AssertionError("expected the call to fail")
        } catch (e: java.io.IOException) {
            e
        }

        // A raw VersolaError here would reach RealCall.AsyncCall as a non-IOException on
        // an enqueued call, which OkHttp rethrows onto the dispatcher thread.
        assertTrue(thrown is VersolaHttpException)
        assertTrue((thrown as VersolaHttpException).error is VersolaError.Configuration)
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `a 401 for a token another call already rotated retries the cache, not a second renewal`() {
        server.enqueue(MockResponse.Builder().code(401).build())
        server.enqueue(ok())
        tokens.onAccessToken = { call ->
            // Simulates a concurrent call's refresh landing in the cache between the token
            // this request was sent with (call 1) and the point where this one re-checks
            // the cache after its 401 (call 2).
            if (call == 2) tokens.forceCurrent(AccessToken("racy-refresh", isDpopBound = true))
        }

        client().newCall(get()).execute().use { assertEquals(200, it.code) }

        assertEquals(0, tokens.renewals)
        server.takeRequest()
        assertEquals("DPoP racy-refresh", server.takeRequest().headers["Authorization"])
    }

    // ---- review findings H3 / M4 --------------------------------------------------------

    @Test
    fun `a failure that is not a VersolaError still reaches the caller as VersolaHttpException`() {
        // Anything else leaving an interceptor is rethrown onto OkHttp's dispatcher thread
        // for an enqueued call, where Android's default handler ends the process.
        tokens.unexpectedFailure = IllegalStateException("There are multiple DataStores active for the same file")

        val error = failure() as VersolaError.Configuration

        assertTrue(error.detail is VersolaError.Configuration.Detail.InvalidConfiguration)
        assertTrue(error.cause is IllegalStateException)
    }

    @Test
    fun `a step-up challenge publishes StepUpRequired before it is surfaced`() {
        server.enqueue(challenge("""Bearer error="insufficient_user_authentication", acr_values="mfa""""))

        val error = failure() as VersolaError.StepUp

        assertEquals(listOf("mfa"), error.acrValues)
        assertEquals(1, tokens.stepUps)
        assertEquals(0, tokens.renewals)
    }

    // AUDIT: C11 - two calls both refused on token-0: each re-reads the cache (still token-0, nobody has
    // rotated yet) and each then renews unconditionally, so one expiry spends two rotations. Under bearer
    // rotation the second is a replay of a refresh token the first already spent.
    @Test
    fun `AUDIT C11 two calls refused on the same token rotate it once`() {
        val seen401 = java.util.concurrent.CountDownLatch(2)
        server.dispatcher = object : mockwebserver3.Dispatcher() {
            override fun dispatch(request: mockwebserver3.RecordedRequest): MockResponse =
                if (request.headers["Authorization"] == "DPoP token-0") status(401) else ok()
        }
        val perThreadCalls = ThreadLocal.withInitial { 0 }
        tokens.afterRead = {
            perThreadCalls.set(perThreadCalls.get() + 1)
            // The second read of each caller is the post-401 cache check: hold both there until each
            // has seen the 401, so neither has rotated when the other looks.
            if (perThreadCalls.get() == 2) {
                seen401.countDown()
                seen401.await(10, java.util.concurrent.TimeUnit.SECONDS)
            }
        }
        val http = client()
        val callers = List(2) {
            Thread { http.newCall(get()).execute().use { check(it.code == 200) } }.apply { start() }
        }
        callers.forEach { it.join(30_000) }

        assertEquals("both refused calls renewed the same rejected token", 1, tokens.renewals)
    }

    // --- audit regressions ---

    /** A key whose signature nobody verifies here: these tests read claims and headers, not trust. */
    private object UnverifiedKey : DpopKey {
        override suspend fun jkt(): String = "unverified-jkt"
        override suspend fun publicJwk(): String = """{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}"""
        override suspend fun attestation(): KeyAttestation = KeyAttestation.Software
        override suspend fun sign(signingInput: ByteArray): ByteArray = ByteArray(64)
    }

    private fun iatOf(proof: String): Long {
        val payload = String(java.util.Base64.getUrlDecoder().decode(proof.split('.')[1]), Charsets.UTF_8)
        return Regex("\"iat\":(\\d+)").find(payload)!!.groupValues[1].toLong()
    }

    @Test
    fun `AUDIT Z5 a Date header from a protected resource server does not move the clock used for the token endpoint's proofs`() = runBlocking {
        // AUDIT: Z5. The interceptor feeds every response's Date into the one shared proof factory, so a
        // resource server whose clock is two days off changes the iat of every later proof, the ones for
        // the authorization server included, which then rejects them.
        val deviceNow = 1_700_000_000_000L
        val factory = DpopProofFactory(UnverifiedKey, clockSkew = ClockSkew { deviceNow })
        // Two days after the device clock (Tue, 14 Nov 2023 22:13:20 GMT).
        server.enqueue(MockResponse.Builder().code(200).setHeader("Date", "Thu, 16 Nov 2023 22:13:20 GMT").body("served").build())

        client(dpop = factory).newCall(get()).execute().close()
        val proofToTokenEndpoint = factory.proof("POST", "https://id.example.com/token")

        assertEquals("the token endpoint's proof must still be stamped from the device clock", deviceNow / 1000, iatOf(proofToTokenEndpoint))
    }

    /**
     * The client as the facades build it: [authenticated], which switches redirects off. A bare
     * interceptor on a client that follows them cannot be made safe (OkHttp follows a `Location`
     * below an application interceptor and re-sends the `DPoP` header, which it does not strip as it
     * does `Authorization`), so that wiring is not public (`AUDIT Z6`).
     */
    private fun redirecting(base: HttpUrl = edge): OkHttpClient = authenticated(
        OkHttpClient.Builder().followRedirects(true).followSslRedirects(true).build(),
        VersolaInterceptor(tokens, RequestScope.origins(setOf("${base.scheme}://${base.host}:${base.port}")), proofs),
    )

    @Test
    fun `AUDIT Z6 a cross-origin redirect is returned to the app and never followed with a proof`() {
        val other = MockWebServer().apply { start() }
        try {
            other.enqueue(ok())
            server.enqueue(MockResponse.Builder().code(302).setHeader("Location", other.url("/landing").toString()).build())

            val response = redirecting().newCall(get()).execute().use { it.code }

            assertEquals("proof-1", server.takeRequest().headers["DPoP"])
            assertEquals("the 302 is the app's to see", 302, response)
            assertEquals("nothing reached the redirect target, neither Authorization nor DPoP", 0, other.requestCount)
        } finally {
            other.close()
        }
    }

    @Test
    fun `AUDIT Z6 a same-origin redirect is returned to the app and the first request's proof is not re-sent`() {
        server.enqueue(MockResponse.Builder().code(302).setHeader("Location", "/resources/r/moved").build())
        server.enqueue(ok())

        val response = redirecting().newCall(get()).execute().use { it.code }

        assertEquals(302, response)
        assertEquals("the redirected request was never made, so no stale proof was re-sent", 1, server.requestCount)
    }

    @Test
    fun `AUDIT Z7 an unexpected failure while signing does not put the request's query into the error text`() {
        // AUDIT: Z7. The interceptor wraps an unexpected exception with e.message, and the DPoP URL checks
        // interpolate the full URL, so `?token=` reached VersolaHttpException (and from there logs and
        // crash reporters). The source here throws what DpopProofFactory throws, with the URL in the message;
        // only the wrapper's own text is asserted, since the cause is the source's to keep clean (see the :dpop test).
        val secret = "SECRET-QUERY-TOKEN-4f2a"
        val leaking = object : DpopProofSource {
            override suspend fun proof(method: String, url: String, accessToken: String?): String =
                throw IllegalArgumentException("a DPoP request URL must be absolute: $url")

            override fun observe(url: String, dateHeader: String?, nonceHeader: String?) {}
        }

        val thrown = try {
            client(dpop = leaking).newCall(get("/resources/r/thing?token=$secret")).execute().close()
            throw AssertionError("expected the call to fail")
        } catch (e: VersolaHttpException) {
            e
        }

        assertTrue("VersolaHttpException text leaks the query: ${thrown.message}", thrown.message?.contains(secret) != true)
        assertTrue("error text leaks the query: ${thrown.error.message}", thrown.error.message?.contains(secret) != true)
    }

}
