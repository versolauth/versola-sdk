package kz.versola.sdk.okhttp

import kz.versola.sdk.core.AccessToken
import kz.versola.sdk.core.AccessTokenSource
import kz.versola.sdk.core.DpopProofSource
import kz.versola.sdk.core.VersolaError
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
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

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
        return current
    }

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
    fun `no proof is attached when the session is not key-bound even on a DPoP-typed token`() {
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
}
