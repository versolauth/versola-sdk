package versola.oauth.core

import java.io.File
import kotlinx.coroutines.test.runTest
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Records what it was asked for, so a test can assert the proof was re-minted per attempt. */
private class RecordingProofSource : DpopProofSource {
    var proofs = 0
    val observed = mutableListOf<Pair<String?, String?>>()

    override suspend fun proof(method: String, url: String, accessToken: String?): String =
        "proof-${++proofs}"

    override fun observe(url: String, dateHeader: String?, nonceHeader: String?) {
        observed += dateHeader to nonceHeader
    }
}

class TokenClientTest {

    @get:Rule
    val folder: TemporaryFolder = TemporaryFolder()

    private lateinit var server: MockWebServer
    private lateinit var issuer: String
    private lateinit var proofSource: RecordingProofSource

    private val refreshToken = "8xLOxBtZp8+refresh/value"

    @Before
    fun start() {
        server = MockWebServer()
        server.start()
        issuer = server.url("/").toString().trimEnd('/')
        proofSource = RecordingProofSource()
    }

    @After
    fun stop() {
        server.close()
    }

    private fun client(
        dpopAdvertised: Boolean = true,
        revocationAdvertised: Boolean = true,
        binding: TokenBinding = TokenBinding.Dpop(),
        dpop: DpopProofSource? = proofSource,
        discoveryFailure: Throwable? = null,
    ): HttpTokenClient {
        val metadata = ProviderMetadata(
            issuer = issuer,
            authorizationEndpoint = "$issuer/authorize",
            tokenEndpoint = "$issuer/token",
            revocationEndpoint = if (revocationAdvertised) "$issuer/revoke" else null,
            dpopSigningAlgValuesSupported = if (dpopAdvertised) listOf("ES256") else emptyList(),
        )
        return HttpTokenClient(
            configuration = VersolaConfiguration.create(
                issuer = "https://id.example.com",
                clientId = "mobile-app",
                redirectUri = "https://app.example.com/oauth",
            ),
            discovery = DiscoveryService(
                issuer = issuer,
                client = object : DiscoveryClient {
                    override suspend fun fetch(issuer: String): ProviderMetadata =
                        discoveryFailure?.let { throw it } ?: metadata
                },
                cache = FileProviderMetadataCache(File(folder.newFolder(), "metadata.json")),
            ),
            httpClient = OkHttpClient(),
            dpop = dpop,
            tokenBinding = binding,
        )
    }

    private fun grant() = AuthorizationGrant(
        code = "the-code",
        codeVerifier = CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        redirectUri = "https://app.example.com/oauth",
        nonce = "the-nonce",
        scopes = setOf("openid", "profile"),
    )

    private fun issued(
        refreshToken: String? = "issued-refresh",
        tokenType: String = "DPoP",
        scope: String? = "openid profile",
    ) = MockResponse.Builder()
        .code(200)
        .setHeader("Content-Type", "application/json")
        .body(
            buildString {
                append("""{"access_token":"at","token_type":"$tokenType","expires_in":3600""")
                refreshToken?.let { append(""","refresh_token":"$it"""") }
                scope?.let { append(""","scope":"$it"""") }
                append("}")
            },
        )
        .build()

    private fun error(code: String, status: Int = 400, nonce: String? = null) = MockResponse.Builder()
        .code(status)
        .setHeader("Content-Type", "application/json")
        .apply { nonce?.let { setHeader("DPoP-Nonce", it) } }
        .body("""{"error":"$code","error_description":"because"}""")
        .build()

    @Test
    fun `a code exchange carries the verifier and no client secret`() = runTest {
        server.enqueue(issued())

        client().exchange(grant())

        val body = server.takeRequest().body!!.utf8()
        assertTrue(body.contains("grant_type=authorization_code"))
        assertTrue(body.contains("code=the-code"))
        assertTrue(body.contains("code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"))
        assertTrue(body.contains("client_id=mobile-app"))
        // Not "the value is empty" — the parameter must not exist at all.
        assertFalse(body.contains("client_secret"))
    }

    @Test
    fun `a code exchange repeats resource once per value the grant carries`() = runTest {
        server.enqueue(issued())
        val grant = AuthorizationGrant(
            code = "the-code",
            codeVerifier = CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            redirectUri = "https://app.example.com/oauth",
            nonce = "the-nonce",
            scopes = setOf("openid"),
            resources = listOf("https://api.example.com/a", "https://api.example.com/b"),
        )

        client().exchange(grant)

        val body = server.takeRequest().body!!.utf8()
        assertTrue(body.contains("resource=https%3A%2F%2Fapi.example.com%2Fa&resource=https%3A%2F%2Fapi.example.com%2Fb"))
        assertEquals(2, body.split('&').count { it.startsWith("resource=") })
    }

    @Test
    fun `a code exchange without resources sends no resource parameter`() = runTest {
        server.enqueue(issued())

        client().exchange(grant())

        assertFalse(server.takeRequest().body!!.utf8().contains("resource"))
    }

    @Test
    fun `a refresh sends no resource, the grant's audience being already fixed`() = runTest {
        server.enqueue(issued())

        client().refresh(refreshToken.toByteArray(), "idem-key-1")

        assertFalse(server.takeRequest().body!!.utf8().contains("resource"))
    }

    @Test
    fun `a refresh carries the idempotency key and a code exchange does not`() = runTest {
        server.enqueue(issued())
        server.enqueue(issued())

        client().refresh(refreshToken.toByteArray(), "idem-key-1")
        client().exchange(grant())

        assertEquals("idem-key-1", server.takeRequest().headers["Idempotency-Key"])
        assertNull(server.takeRequest().headers["Idempotency-Key"])
    }

    @Test
    fun `the refresh token is percent-encoded rather than left to a form library`() = runTest {
        server.enqueue(issued())

        client().refresh(refreshToken.toByteArray(), "idem-key-1")

        // '+' and '/' are legal base64 and legal in a token; unescaped, '+' decodes as a
        // space server-side and the refresh reads as a replay of something never issued.
        val body = server.takeRequest().body!!.utf8()
        assertTrue(body.contains("refresh_token=8xLOxBtZp8%2Brefresh%2Fvalue"))
    }

    @Test
    fun `refresh takes ownership of the buffer and zeroes it`() = runTest {
        server.enqueue(issued())
        val caller = refreshToken.toByteArray()

        client().refresh(caller, "idem-key-1")

        assertArrayEquals(ByteArray(refreshToken.length), caller)
    }

    @Test
    fun `the issued refresh token comes back as bytes`() = runTest {
        server.enqueue(issued())

        val response = client().exchange(grant())

        assertArrayEquals("issued-refresh".toByteArray(), response.refreshToken)
        assertEquals(setOf("openid", "profile"), response.scopes)
        assertEquals(3600, response.expiresInSeconds)
        assertTrue(response.isDpopBound)
    }

    @Test
    fun `a blank refresh token is treated as omitted, never stored as an empty credential`() = runTest {
        server.enqueue(issued(refreshToken = ""))

        val response = client().exchange(grant())

        assertNull(response.refreshToken)
    }

    @Test
    fun `a response that omits the refresh token is not an empty one`() = runTest {
        server.enqueue(issued(refreshToken = null, scope = null))

        val response = client().exchange(grant())

        assertNull(response.refreshToken)
        assertEquals(emptySet<String>(), response.scopes)
    }

    @Test
    fun `a proof is attached when the deployment advertises DPoP`() = runTest {
        server.enqueue(issued())

        client().exchange(grant())

        assertEquals("proof-1", server.takeRequest().headers["DPoP"])
    }

    @Test
    fun `no proof is attached when the deployment does not advertise DPoP`() = runTest {
        // #1 §4's silent fallback: a provider without DPoP is served bearer rather than sent
        // a proof it never asked for and may reject.
        server.enqueue(issued(tokenType = "Bearer"))

        client(dpopAdvertised = false).exchange(grant())

        assertNull(server.takeRequest().headers["DPoP"])
    }

    @Test
    fun `no proof is attached under TokenBinding Bearer`() = runTest {
        server.enqueue(issued(tokenType = "Bearer"))

        client(binding = TokenBinding.Bearer, dpop = null).exchange(grant())

        assertNull(server.takeRequest().headers["DPoP"])
    }

    @Test
    fun `a key-bound client without a proof source is refused at construction`() = runTest {
        // Otherwise the request goes out unbound and `requireHardware` checks a token type
        // the server can answer with whether or not a proof was ever presented.
        val failure = failure {
            client(binding = TokenBinding.Dpop(requireHardware = true), dpop = null)
        } as VersolaError.Configuration

        assertTrue(failure.detail is VersolaError.Configuration.Detail.InvalidConfiguration)
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `every response is observed, not only a challenge`() = runTest {
        // The Date header of a *success* is the cheapest place to learn the clock offset.
        server.enqueue(
            MockResponse.Builder()
                .code(200)
                .setHeader("Content-Type", "application/json")
                .setHeader("Date", "Tue, 23 Sep 2025 10:00:00 GMT")
                .body("""{"access_token":"at","token_type":"DPoP","expires_in":3600}""")
                .build(),
        )

        client().exchange(grant())

        assertEquals(listOf("Tue, 23 Sep 2025 10:00:00 GMT" to null), proofSource.observed)
    }

    @Test
    fun `use_dpop_nonce is retried exactly once, with a freshly minted proof`() = runTest {
        server.enqueue(error("use_dpop_nonce", nonce = "nonce-1"))
        server.enqueue(issued())

        val response = client().exchange(grant())

        assertEquals("at", response.accessToken)
        assertEquals(2, server.requestCount)
        assertEquals("proof-1", server.takeRequest().headers["DPoP"])
        assertEquals("proof-2", server.takeRequest().headers["DPoP"])
        // The nonce reached the proof source off the challenge, which is what the second
        // proof is minted from.
        assertEquals(listOf(null to "nonce-1", null to null), proofSource.observed)
    }

    @Test
    fun `a nonce challenge carrying no nonce is not retried at all`() = runTest {
        // `observe` cached nothing, so a second proof would go out without the nonce the
        // server demands — the same unbounded loop by another route, and for a code exchange
        // a second request that can only burn the grant.
        server.enqueue(error("use_dpop_nonce", nonce = null))

        val failure = failure { client().exchange(grant()) } as VersolaError.Recoverable

        assertTrue(failure.reason is VersolaError.Recoverable.Cause.NonceLoop)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `a second nonce demand terminates rather than looping`() = runTest {
        server.enqueue(error("use_dpop_nonce", nonce = "nonce-1"))
        server.enqueue(error("use_dpop_nonce", nonce = "nonce-2"))

        val failure = failure { client().exchange(grant()) } as VersolaError.Recoverable

        assertTrue(failure.reason is VersolaError.Recoverable.Cause.NonceLoop)
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `invalid_dpop_proof is retried once and then surfaces as a sign-out`() = runTest {
        // First failure is usually clock skew, which the Date header of the rejection
        // corrects. A second means the key does not match the grant.
        server.enqueue(error("invalid_dpop_proof"))
        server.enqueue(error("invalid_dpop_proof"))

        val failure = failure { client().exchange(grant()) } as VersolaError.Reauthenticate

        assertSame(VersolaError.Reauthenticate.Reason.CredentialsInvalidated, failure.reason)
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `invalid_dpop_proof answered by a success is never surfaced`() = runTest {
        server.enqueue(error("invalid_dpop_proof"))
        server.enqueue(issued())

        assertEquals("at", client().exchange(grant()).accessToken)
    }

    @Test
    fun `invalid_grant is a sign-out and is never retried`() = runTest {
        server.enqueue(error("invalid_grant"))

        val failure = failure { client().refresh(refreshToken.toByteArray(), "idem-key-1") }

        assertSame(
            VersolaError.Reauthenticate.Reason.GrantRejected,
            (failure as VersolaError.Reauthenticate).reason,
        )
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `the codes no user action fixes are Configuration`() = runTest {
        for (code in listOf(
            "invalid_request",
            "invalid_client",
            "unauthorized_client",
            "unsupported_grant_type",
            "invalid_scope",
            "invalid_target",
            "invalid_authorization_details",
            "a_code_this_sdk_has_never_heard_of",
        )) {
            server.enqueue(error(code, status = if (code == "invalid_client") 401 else 400))

            val failure = failure { client().exchange(grant()) } as VersolaError.Configuration

            assertEquals(
                VersolaError.Configuration.Detail.TokenRequestRejected(code, "because"),
                failure.detail,
            )
        }
    }

    @Test
    fun `a redirect is refused rather than followed with the credential`() = runTest {
        // 307 and 308 repeat the method and the body by definition, and OkHttp follows
        // redirects by default: one Location header would repost the code — and the proof
        // minted for this origin — somewhere discovery never named.
        val elsewhere = MockWebServer()
        elsewhere.start()
        try {
            elsewhere.enqueue(issued())
            server.enqueue(
                MockResponse.Builder()
                    .code(307)
                    .setHeader("Location", elsewhere.url("/token").toString())
                    .build(),
            )

            val failure = failure { client().exchange(grant()) } as VersolaError.Configuration

            assertTrue(failure.detail is VersolaError.Configuration.Detail.TokenRequestRejected)
            assertEquals(0, elsewhere.requestCount)
            assertEquals(1, server.requestCount)
        } finally {
            elsewhere.close()
        }
    }

    @Test
    fun `5xx is transport-shaped rather than a deployment fault`() = runTest {
        server.enqueue(MockResponse.Builder().code(503).body("<html>upstream is down</html>").build())

        val failure = failure { client().exchange(grant()) } as VersolaError.Recoverable

        assertTrue(failure.reason is VersolaError.Recoverable.Cause.Network)
    }

    @Test
    fun `a 4xx that is not an OAuth error response is a deployment answering the wrong thing`() = runTest {
        server.enqueue(MockResponse.Builder().code(404).body("<html>not found</html>").build())

        val failure = failure { client().exchange(grant()) } as VersolaError.Configuration

        assertTrue(failure.detail is VersolaError.Configuration.Detail.TokenRequestRejected)
    }

    @Test
    fun `a response without token_type is malformed rather than assumed to be Bearer`() = runTest {
        // RFC 6749 §5.1 makes it REQUIRED, and it is the field that says whether the grant is
        // key-bound — the last one to guess a default for.
        server.enqueue(
            MockResponse.Builder()
                .code(200)
                .setHeader("Content-Type", "application/json")
                .body("""{"access_token":"at","expires_in":3600}""")
                .build(),
        )

        val failure = failure { client().exchange(grant()) } as VersolaError.Configuration

        assertEquals(
            VersolaError.Configuration.Detail.TokenResponseMalformed("token_type is missing"),
            failure.detail,
        )
    }

    @Test
    fun `a 200 that is not a token response is a deployment fault, not a retry`() = runTest {
        server.enqueue(
            MockResponse.Builder()
                .code(200)
                .setHeader("Content-Type", "application/json")
                .body("""{"token_type":"DPoP","expires_in":3600}""")
                .build(),
        )

        val failure = failure { client().exchange(grant()) } as VersolaError.Configuration

        assertTrue(failure.detail is VersolaError.Configuration.Detail.TokenResponseMalformed)
    }

    @Test
    fun `requireHardware refuses a bearer token issued for a bound request`() = runTest {
        // The app asserted it cannot run unbound. A server that answers a proof with a bearer
        // token has not bound the grant, whatever the request looked like.
        server.enqueue(issued(tokenType = "Bearer"))

        val failure = failure {
            client(binding = TokenBinding.Dpop(requireHardware = true)).exchange(grant())
        } as VersolaError.Configuration

        assertTrue(failure.detail is VersolaError.Configuration.Detail.HardwareBindingUnavailable)
    }

    @Test
    fun `requireHardware refuses a deployment without DPoP before spending the code`() = runTest {
        // Discovery already said this exchange cannot produce a bound grant. Redeeming the
        // code first and refusing the result afterwards costs the user the code.
        val failure = failure {
            client(
                dpopAdvertised = false,
                binding = TokenBinding.Dpop(requireHardware = true),
            ).exchange(grant())
        } as VersolaError.Configuration

        assertTrue(failure.detail is VersolaError.Configuration.Detail.HardwareBindingUnavailable)
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `a refused response leaves no readable refresh token behind`() {
        // Nothing downstream ever receives this response, so nothing downstream can zero what
        // the parse copied out of it.
        val refused = TokenResponse(
            accessToken = "at",
            tokenType = "Bearer",
            expiresInSeconds = 3600,
            refreshToken = "issued-refresh".toByteArray(),
            idToken = null,
            scopes = emptySet(),
        )

        runCatching { TokenBinding.Dpop(requireHardware = true).acceptIssued(refused) }

        assertArrayEquals(ByteArray("issued-refresh".length), refused.refreshToken)
    }

    @Test
    fun `a transport failure is Recoverable rather than an IOException`() = runTest {
        server.close()

        val failure = failure { client().exchange(grant()) } as VersolaError.Recoverable

        assertTrue(failure.reason is VersolaError.Recoverable.Cause.Network)
    }

    @Test
    fun `a failure before the request still clears the form builder`() = runTest {
        // First-use discovery can fail with the builder already holding the encoded token,
        // before there is any request body to zero.
        val form = FormBody().addBytes("refresh_token", refreshToken.toByteArray())

        failure {
            client(discoveryFailure = IllegalStateException("discovery is unreachable"))
                .post(form, "idem-key-1")
        }

        assertTrue(form.backingBytes().all { it == 0.toByte() })
    }

    @Test
    fun `the form builder keeps no readable copy once cleared`() {
        val form = FormBody().addBytes("refresh_token", refreshToken.toByteArray())

        form.clear()

        assertTrue(form.backingBytes().all { it == 0.toByte() })
    }

    @Test
    fun `an outgrown buffer is zeroed rather than abandoned`() {
        // Growth copies the encoded token into a larger array; the array left behind holds
        // exactly the same bytes and is unreachable to zero later.
        val form = FormBody().addBytes("refresh_token", refreshToken.toByteArray())
        val outgrown = form.backingBytes()

        form.add("padding", "x".repeat(outgrown.size))

        assertNotSame(outgrown, form.backingBytes())
        assertTrue(outgrown.all { it == 0.toByte() })
    }

    // ---- revoke() ----------------------------------------------------------------------

    @Test
    fun `a revocation carries the token, its hint and the client id, and no proof`() = runTest {
        server.enqueue(MockResponse.Builder().code(200).build())
        val token = refreshToken.toByteArray(Charsets.UTF_8)

        client().revoke(token)

        val request = server.takeRequest()
        assertEquals("/revoke", request.url.encodedPath)
        val body = request.body!!.utf8()
        assertTrue(body.contains("token=8xLOxBtZp8%2Brefresh%2Fvalue"))
        assertTrue(body.contains("token_type_hint=refresh_token"))
        assertTrue(body.contains("client_id=mobile-app"))
        assertFalse(body.contains("client_secret"))
        // RFC 9449 does not bind revocation and auth reads no proof there; sending one
        // would only hand a nonce-less proof to a server entitled to reject it.
        assertNull(request.headers["DPoP"])
        assertEquals(0, proofSource.proofs)
        // Taken ownership of, like a refresh.
        assertTrue(token.all { it == 0.toByte() })
    }

    @Test
    fun `a provider that advertises no revocation endpoint is skipped, not failed`() = runTest {
        client(revocationAdvertised = false).revoke(refreshToken.toByteArray(Charsets.UTF_8))

        assertEquals(0, server.requestCount)
    }

    @Test
    fun `a refused revocation is Configuration and an unavailable one is Recoverable`() = runTest {
        server.enqueue(error("invalid_client", status = 401))
        val refused = failure { client().revoke(refreshToken.toByteArray(Charsets.UTF_8)) }
        assertTrue(refused is VersolaError.Configuration)
        assertEquals(
            "invalid_client",
            ((refused as VersolaError.Configuration).detail as VersolaError.Configuration.Detail.TokenRequestRejected).code,
        )

        server.enqueue(MockResponse.Builder().code(503).build())
        val unavailable = failure { client().revoke(refreshToken.toByteArray(Charsets.UTF_8)) }
        assertTrue(unavailable is VersolaError.Recoverable)
    }

    @Test
    fun `408 and 429 are transient, not deployment faults`() = runTest {
        for (status in listOf(408, 429, 503)) {
            server.enqueue(MockResponse.Builder().code(status).build())
            val error = failure { client().refresh(refreshToken.toByteArray(), "idem-key-1") }
            assertTrue("HTTP $status should be Recoverable", error is VersolaError.Recoverable)
        }
        server.enqueue(MockResponse.Builder().code(429).build())
        assertTrue(failure { client().revoke(refreshToken.toByteArray()) } is VersolaError.Recoverable)
    }
}
