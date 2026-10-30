package versola.sdk.core

import versola.oauth.core.AuthorizationGrant
import versola.oauth.core.AuthorizationResponseValidator
import versola.oauth.core.PendingAuthorizationCodec
import versola.oauth.core.CodeVerifier
import versola.oauth.core.DiscoveryClient
import versola.oauth.core.DiscoveryService
import versola.oauth.core.DpopProofSource
import versola.oauth.core.FileProviderMetadataCache
import versola.oauth.core.MtlsEndpointAliases
import versola.oauth.core.ProviderMetadata
import versola.oauth.core.TokenBinding
import versola.oauth.core.TokenResponse
import versola.oauth.core.VersolaConfiguration
import versola.oauth.core.VersolaError
import java.io.File
import kotlinx.coroutines.test.runTest
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

private class EdgeProofSource : DpopProofSource {
    val proofsFor = mutableListOf<String>()
    val observed = mutableListOf<Pair<String, String?>>()

    override suspend fun proof(method: String, url: String, accessToken: String?): String {
        proofsFor += url
        return "proof-${proofsFor.size}"
    }

    override fun observe(url: String, dateHeader: String?, nonceHeader: String?) {
        observed += url to nonceHeader
    }
}

private class MemoryEndpoints(var stored: NativeEndpoints? = null) : NativeEndpointsStore {
    override suspend fun load(): NativeEndpoints? = stored
    override suspend fun save(endpoints: NativeEndpoints) {
        stored = endpoints
    }
}

private const val AUTH_MTLS = "https://id.versola.io:9008"

class EdgeNativeTokenClientTest {

    @get:Rule
    val folder: TemporaryFolder = TemporaryFolder()

    private lateinit var server: MockWebServer
    private lateinit var edge: String
    private lateinit var proofs: EdgeProofSource

    @Before
    fun start() {
        server = MockWebServer()
        server.start()
        edge = server.url("/").toString().trimEnd('/')
        proofs = EdgeProofSource()
    }

    @After
    fun stop() {
        server.close()
    }

    private fun client(
        endpoints: NativeEndpointsStore = MemoryEndpoints(),
        aliases: MtlsEndpointAliases? = null,
        binding: TokenBinding.Dpop = TokenBinding.Dpop(),
    ): EdgeNativeTokenClient {
        val metadata = ProviderMetadata(
            issuer = "https://id.versola.io",
            authorizationEndpoint = "https://id.versola.io/authorize",
            tokenEndpoint = "https://id.versola.io/token",
            revocationEndpoint = "https://id.versola.io/revoke",
            dpopSigningAlgValuesSupported = listOf("ES256"),
            mtlsEndpointAliases = aliases,
        )
        return EdgeNativeTokenClient(
            configuration = VersolaConfiguration.create("https://id.versola.io", "mobile-app", "https://app.example.com/oauth"),
            edgeBaseUrl = edge,
            httpClient = OkHttpClient(),
            dpop = proofs,
            discovery = DiscoveryService(
                issuer = "https://id.versola.io",
                client = object : DiscoveryClient {
                    override suspend fun fetch(issuer: String): ProviderMetadata = metadata
                },
                cache = FileProviderMetadataCache(File(folder.newFolder(), "metadata.json")),
            ),
            endpoints = endpoints,
            tokenBinding = binding,
        )
    }

    private fun edgeGrant() = AuthorizationGrant(
        code = "the-code",
        codeVerifier = CodeVerifier(""),
        redirectUri = "https://app.example.com/oauth",
        nonce = "n",
        scopes = setOf("openid"),
        state = "edge-state",
        iss = "https://id.versola.io",
        extension = mapOf(
            EdgeAuthorizationStarter.BLOB to "sealed",
            EdgeAuthorizationStarter.TOKEN_ENDPOINT to "$AUTH_MTLS/token",
            EdgeAuthorizationStarter.REVOCATION_ENDPOINT to "$AUTH_MTLS/revoke",
        ),
    )

    private fun directGrant() = AuthorizationGrant(
        code = "the-code",
        codeVerifier = CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        redirectUri = "https://app.example.com/oauth",
        nonce = "n",
        scopes = setOf("openid"),
    )

    private fun issued(tokenType: String = "DPoP") = MockResponse.Builder()
        .code(200)
        .setHeader("Content-Type", "application/json")
        .body("""{"access_token":"at","token_type":"$tokenType","expires_in":3600,"refresh_token":"rt"}""")
        .build()

    private fun authError(code: String, nonce: String? = null) = MockResponse.Builder()
        .code(400)
        .setHeader("Content-Type", "application/json")
        .apply { nonce?.let { setHeader("DPoP-Nonce", it) } }
        .body("""{"error":"$code","error_description":"because"}""")
        .build()

    @Test
    fun `complete presents code, state, iss and blob with a proof signed for auth's token endpoint`() = runTest {
        server.enqueue(issued())
        val endpoints = MemoryEndpoints()

        val response = client(endpoints).exchange(edgeGrant())

        val request = server.takeRequest()
        assertEquals("/native/complete/mobile-app", request.url.encodedPath)
        val body = request.body!!.utf8()
        assertTrue(body.contains("code=the-code"))
        assertTrue(body.contains("state=edge-state"))
        assertTrue(body.contains("iss=https%3A%2F%2Fid.versola.io"))
        assertTrue(body.contains("blob=sealed"))
        // No verifier — edge sealed it in the blob — and no client id: the path names the client.
        assertFalse(body.contains("code_verifier"))
        assertFalse(body.contains("client_id"))
        assertNull(request.headers["Idempotency-Key"])
        // The proof is signed for where edge forwards it, not for edge.
        assertEquals("proof-1", request.headers["DPoP"])
        assertEquals(listOf("$AUTH_MTLS/token"), proofs.proofsFor)
        assertTrue(response.isDpopBound)
        // Remembered for the refreshes that follow, in this process and the next.
        assertEquals(NativeEndpoints("$AUTH_MTLS/token", "$AUTH_MTLS/revoke"), endpoints.stored)
    }

    @Test
    fun `a grant restored from a pending record written before the extension existed still reaches edge`() = runTest {
        server.enqueue(issued())
        val endpoints = MemoryEndpoints()
        val legacy = """{"state":"edge-state","nonce":"n","codeVerifier":"","scopes":["openid"],""" +
            """"redirectUri":"https://app.example.com/oauth","acrValues":[],"maxAge":null,"createdAtEpochMillis":1,""" +
            """"blob":"sealed","tokenEndpoint":"$AUTH_MTLS/token","revocationEndpoint":"$AUTH_MTLS/revoke"}"""
        val pending = PendingAuthorizationCodec.decode(legacy.toByteArray())
        val grant = AuthorizationResponseValidator.validate(
            redirect = "https://app.example.com/oauth?code=the-code&state=edge-state&iss=https%3A%2F%2Fid.versola.io",
            pending = pending,
            issuer = "https://id.versola.io",
            issParameterSupported = false,
        )

        client(endpoints).exchange(grant)

        val request = server.takeRequest()
        assertEquals("/native/complete/mobile-app", request.url.encodedPath)
        assertTrue(request.body!!.utf8().contains("blob=sealed"))
        assertEquals(listOf("$AUTH_MTLS/token"), proofs.proofsFor)
        assertEquals(NativeEndpoints("$AUTH_MTLS/token", "$AUTH_MTLS/revoke"), endpoints.stored)
    }

    @Test
    fun `a redirect without iss onto a pending record written before the extension existed is refused before any request`() = runTest {
        // The old record did not say that iss is required, so the validator lets a redirect
        // without one through when discovery does not advertise it; the exchange is the last
        // check before the code would be spent, and it refuses.
        val legacy = """{"state":"edge-state","nonce":"n","codeVerifier":"","scopes":["openid"],""" +
            """"redirectUri":"https://app.example.com/oauth","acrValues":[],"maxAge":null,"createdAtEpochMillis":1,""" +
            """"blob":"sealed","tokenEndpoint":"$AUTH_MTLS/token"}"""
        val pending = PendingAuthorizationCodec.decode(legacy.toByteArray())
        val grant = AuthorizationResponseValidator.validate(
            redirect = "https://app.example.com/oauth?code=the-code&state=edge-state",
            pending = pending,
            issuer = "https://id.versola.io",
            issParameterSupported = false,
        )

        val error = failure { client().exchange(grant) } as VersolaError.Configuration

        assertTrue(error.detail is VersolaError.Configuration.Detail.IssuerMismatch)
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `a grant started directly against auth is refused before the code is spent`() = runTest {
        val error = failure { client().exchange(directGrant()) } as VersolaError.Configuration

        assertTrue(error.detail is VersolaError.Configuration.Detail.InvalidConfiguration)
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `a refresh goes to native token with the idempotency key and a proof for the remembered endpoint`() = runTest {
        server.enqueue(issued())
        val token = "the-refresh".toByteArray()

        client(MemoryEndpoints(NativeEndpoints("$AUTH_MTLS/token", "$AUTH_MTLS/revoke")))
            .refresh(token, "idem-1")

        val request = server.takeRequest()
        assertEquals("/native/token/mobile-app", request.url.encodedPath)
        assertEquals("idem-1", request.headers["Idempotency-Key"])
        val body = request.body!!.utf8()
        assertTrue(body.contains("grant_type=refresh_token"))
        assertTrue(body.contains("refresh_token=the-refresh"))
        assertFalse(body.contains("client_id"))
        assertEquals(listOf("$AUTH_MTLS/token"), proofs.proofsFor)
        assertTrue(token.all { it == 0.toByte() })
    }

    @Test
    fun `auth's relayed nonce challenge is answered once and cached under auth's origin, not edge's`() = runTest {
        server.enqueue(authError("use_dpop_nonce", nonce = "auth-nonce"))
        server.enqueue(issued())

        client(MemoryEndpoints(NativeEndpoints("$AUTH_MTLS/token", "$AUTH_MTLS/revoke")))
            .refresh("rt".toByteArray(), "idem-1")

        assertEquals(2, server.requestCount)
        // Scenario 04 in the other direction: the nonce came from auth, relayed by edge, and
        // the next proof for auth's endpoint must carry it — so it is observed under the
        // `htu`, which is auth's origin, and never under edge's.
        assertEquals("$AUTH_MTLS/token" to "auth-nonce", proofs.observed.first())
        assertEquals(listOf("$AUTH_MTLS/token", "$AUTH_MTLS/token"), proofs.proofsFor)
    }

    @Test
    fun `edge's 401-shaped challenge on a relayed call is read the same way`() = runTest {
        server.enqueue(
            MockResponse.Builder().code(401)
                .setHeader("WWW-Authenticate", """DPoP error="use_dpop_nonce"""")
                .setHeader("DPoP-Nonce", "n1")
                .build(),
        )
        server.enqueue(issued())

        client(MemoryEndpoints(NativeEndpoints("$AUTH_MTLS/token", "$AUTH_MTLS/revoke")))
            .refresh("rt".toByteArray(), "idem-1")

        assertEquals(2, server.requestCount)
    }

    @Test
    fun `invalid_grant is Reauthenticate and a 404 names the client`() = runTest {
        val endpoints = MemoryEndpoints(NativeEndpoints("$AUTH_MTLS/token", "$AUTH_MTLS/revoke"))
        server.enqueue(authError("invalid_grant"))
        val rejected = failure { client(endpoints).refresh("rt".toByteArray(), "k") } as VersolaError.Reauthenticate
        assertSame(VersolaError.Reauthenticate.Reason.GrantRejected, rejected.reason)

        server.enqueue(MockResponse.Builder().code(404).build())
        val unknown = failure { client(endpoints).refresh("rt".toByteArray(), "k") } as VersolaError.Configuration
        assertEquals(EdgeClientUnknown("mobile-app"), unknown.detail)
    }

    @Test
    fun `a bearer answer to a hardware-required session is refused`() = runTest {
        server.enqueue(issued(tokenType = "Bearer"))

        val error = failure {
            client(binding = TokenBinding.Dpop(requireHardware = true)).exchange(edgeGrant())
        } as VersolaError.Configuration

        assertTrue(error.detail is VersolaError.Configuration.Detail.HardwareBindingUnavailable)
    }

    @Test
    fun `revoke goes to native revoke with a proof for the revocation endpoint and no client id`() = runTest {
        server.enqueue(MockResponse.Builder().code(200).build())
        val token = "the-refresh".toByteArray()

        client(MemoryEndpoints(NativeEndpoints("$AUTH_MTLS/token", "$AUTH_MTLS/revoke"))).revoke(token)

        val request = server.takeRequest()
        assertEquals("/native/revoke/mobile-app", request.url.encodedPath)
        val body = request.body!!.utf8()
        assertTrue(body.contains("token=the-refresh"))
        assertTrue(body.contains("token_type_hint=refresh_token"))
        assertFalse(body.contains("client_id"))
        assertEquals(listOf("$AUTH_MTLS/revoke"), proofs.proofsFor)
        assertTrue(token.all { it == 0.toByte() })
    }

    @Test
    fun `without a remembered endpoint the mutual-TLS alias is signed for, then the plain endpoint`() = runTest {
        server.enqueue(issued())
        client(aliases = MtlsEndpointAliases(tokenEndpoint = "https://mtls.id.versola.io/token"))
            .refresh("rt".toByteArray(), "k")
        assertEquals("https://mtls.id.versola.io/token", proofs.proofsFor.last())

        server.enqueue(issued())
        client().refresh("rt".toByteArray(), "k")
        assertEquals("https://id.versola.io/token", proofs.proofsFor.last())
    }

    @Test
    fun `the endpoints file survives a process restart and is read before any inference`() = runTest {
        val file = File(folder.newFolder(), "native-endpoints.json")
        server.enqueue(issued())
        client(FileNativeEndpointsStore(file)).exchange(edgeGrant())
        assertTrue(file.exists())

        server.enqueue(issued())
        client(FileNativeEndpointsStore(file), aliases = MtlsEndpointAliases(tokenEndpoint = "https://other/token"))
            .refresh("rt".toByteArray(), "k")

        assertEquals("$AUTH_MTLS/token", proofs.proofsFor.last())
    }
}
