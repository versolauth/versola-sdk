package versola.oauth.conformance

import java.security.interfaces.ECPublicKey
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import versola.oauth.OAuthConfiguration
import versola.oauth.core.SessionState
import versola.oauth.core.TokenBinding
import versola.oauth.core.VersolaError
import versola.sdk.dpop.KeyAttestation

/**
 * `33-dpop-end-to-end`: DPoP (RFC 9449) proven against a provider that requires it and a
 * resource server that verifies it, observed on the wire. The key is the SDK's own
 * `KeystoreDpopKey` on the JVM's stand-in Keystore ([SoftwareAndroidKeyStore]), so the tier
 * this run proves is **Software**; StrongBox and the TEE are the device tier's and nothing here
 * says anything about them.
 *
 * Skipped, with the reason, on a provider that does not advertise `ES256` DPoP proofs (Hydra
 * 26.2), as scenario 29 skips its PAR tests. Keycloak 26.4 sends no `DPoP-Nonce` of its own;
 * the nonce assertions are therefore made at the resource server, which demands one, and the
 * provider's side is asserted conditionally (a challenge, if one is ever sent, is retried once).
 */
class Scenario33DpopEndToEndTest : ProviderConformance() {

    private val resources = mutableListOf<DpopResourceServer>()

    @Before
    fun requireDpopProvider() {
        val discovery = OkHttpClient().newCall(Request.Builder().url(provider.issuer + "/.well-known/openid-configuration").build()).execute().text()
        val algorithms = kotlinx.serialization.json.Json.parseToJsonElement(discovery).jsonObject["dpop_signing_alg_values_supported"]
            ?.jsonArray?.map { it.jsonPrimitive.content }.orEmpty()
        assumeTrue("${provider.name} does not advertise dpop_signing_alg_values_supported with ES256 (spec/providers.md), so DPoP is not driven", "ES256" in algorithms)
    }

    @After
    fun stopResources() = resources.forEach { it.stop() }

    private fun dpopServer(nonce: String? = null, offered: String? = nonce): DpopResourceServer =
        DpopResourceServer(provider, proxy, nonce, offered = offered).also {
            it.start()
            resources += it
        }

    private fun dpopConfiguration(
        origins: Set<String>,
        binding: TokenBinding = TokenBinding.Dpop(),
        clientId: String = Provider.DPOP_CLIENT_ID,
    ): OAuthConfiguration = configuration(clientId = clientId, tokenBinding = binding, protectedOrigins = origins)

    private fun tokenPath(metadata: versola.oauth.core.ProviderMetadata) = metadata.tokenEndpoint.substringAfter(proxy.origin)

    private fun jwkOf(proof: JsonObject?): JsonObject = checkNotNull(proof)["jwk"]!!.jsonObject

    private fun jktOf(proof: JsonObject?): String = DpopResourceServer.thumbprint(jwkOf(proof))

    @Test
    fun `the token request carries a valid proof and the issued token is DPoP-bound to the SDK's key`() = runTest {
        val rs = dpopServer()
        val client = client(dpopConfiguration(setOf(rs.origin)))
        val metadata = client.metadata()

        client.login()

        assertEquals(SessionState.Authenticated, client.state())
        // The tier is read back, not assumed (security.md): on a JVM it can only be Software.
        assertEquals(KeyAttestation.Software, client.keyAttestation())
        assertTrue(logger.warnings.toString(), logger.warnings.any { it.contains("software-backed") })
        val jkt = DpopResourceServer.thumbprint(keystore.soleKey().public as ECPublicKey)

        // The authorization request commits to the key (RFC 9449 section 10), pushed or not.
        val authorization = if (metadata.pushedAuthorizationRequestEndpoint != null) {
            theRequest("POST", metadata.pushedAuthorizationRequestEndpoint!!.substringAfter(proxy.origin)).form
        } else {
            browser.opened.single().query()
        }
        assertEquals(jkt, authorization["dpop_jkt"])

        val token = theRequest("POST", tokenPath(metadata))
        assertEquals("authorization_code", token.form["grant_type"])
        assertEquals(1, token.headerCount("DPoP"))
        val header = token.proofHeader!!
        val claims = token.proofClaims!!
        assertEquals("dpop+jwt", header["typ"]!!.jsonPrimitive.content)
        assertEquals("ES256", header["alg"]!!.jsonPrimitive.content)
        // A public key only: `d` in a proof's jwk would be the key itself.
        assertEquals(setOf("kty", "crv", "x", "y"), jwkOf(header).keys)
        assertEquals(jkt, jktOf(header))
        assertEquals("POST", claims["htm"]!!.jsonPrimitive.content)
        assertEquals(metadata.tokenEndpoint, claims["htu"]!!.jsonPrimitive.content)
        assertTrue(claims["jti"]!!.jsonPrimitive.content.isNotEmpty())
        assertTrue(kotlin.math.abs(claims["iat"]!!.jsonPrimitive.content.toLong() - token.at / 1000) <= 60)
        // No access token exists yet to hash.
        assertFalse(claims.containsKey("ath"))
        assertNoSecretOnTheWire(token)

        // What the provider issued: a DPoP token whose cnf.jkt is that key's thumbprint.
        assertEquals(200, token.status)
        assertEquals("DPoP", token.responseJson!!["token_type"]!!.jsonPrimitive.content)
        val accessToken = token.responseJson!!["access_token"]!!.jsonPrimitive.content
        assertEquals(jkt, Transcript.decodeJwtPart(accessToken, 1)!!["cnf"]!!.jsonObject["jkt"]!!.jsonPrimitive.content)
        assertTrue(client.accessToken().isDpopBound)

        assertProviderNonceChallengesRetriedOnce(tokenPath(metadata))
    }

    /** Keycloak 26.4 sends none; a provider that does must see exactly one retry carrying it. */
    private fun assertProviderNonceChallengesRetriedOnce(tokenPath: String) {
        val requests = transcript.matching("POST", tokenPath)
        requests.forEachIndexed { index, entry ->
            val nonce = entry.responseHeader("DPoP-Nonce")
            if (entry.status in 400..401 && nonce != null) {
                val retry = requests.getOrNull(index + 1)
                assertNotNull("a use_dpop_nonce challenge was not retried: $entry", retry)
                assertEquals(nonce, retry!!.proofClaims!!["nonce"]?.jsonPrimitive?.content)
                // The retry is the one: it is not itself challenged again.
                assertFalse("retried more than once: $requests", retry.status in 400..401 && retry.responseHeader("DPoP-Nonce") != null)
            }
        }
    }

    @Test
    fun `an authenticated call sends the DPoP scheme and a proof bound to the token, which the resource server accepts`() = runTest {
        val rs = dpopServer()
        val client = client(dpopConfiguration(setOf(rs.origin)))
        client.login()
        val jkt = DpopResourceServer.thumbprint(keystore.soleKey().public as ECPublicKey)
        val subject = checkNotNull(client.claims).subject

        val response = client.call(Request.Builder().url(rs.url("/api/items?page=2")).build())
        val body = response.text()

        assertEquals(body, 200, response.code)
        val sent = transcript.entries.single { it.url.startsWith(rs.origin) }
        val authorization = sent.header("Authorization")!!
        assertTrue(authorization, authorization.startsWith("DPoP "))
        val accessToken = authorization.removePrefix("DPoP ")
        assertEquals(1, sent.headerCount("DPoP"))
        val claims = sent.proofClaims!!
        assertEquals("GET", claims["htm"]!!.jsonPrimitive.content)
        // The URL without its query.
        assertEquals(rs.url("/api/items"), claims["htu"]!!.jsonPrimitive.content)
        assertEquals(DpopResourceServer.sha256Url(accessToken), claims["ath"]!!.jsonPrimitive.content)
        assertEquals(jkt, jktOf(sent.proofHeader))
        assertEquals(jkt, Transcript.decodeJwtPart(accessToken, 1)!!["cnf"]!!.jsonObject["jkt"]!!.jsonPrimitive.content)
        // What the server checked, not only what it answered: signature, htm, htu, iat, jti, ath and cnf.jkt.
        assertEquals(listOf<DpopVerdict>(DpopVerdict.Accepted(jkt, subject)), rs.verdicts("/api/items"))
        assertEquals(1, rs.attempts.size)

        // An origin that is not protected gets neither the token nor a proof.
        client.call(Request.Builder().url(proxy.origin + "/elsewhere").build()).close()
        val elsewhere = transcript.entries.single { it.url == proxy.origin + "/elsewhere" }
        assertNull(elsewhere.header("Authorization"))
        assertNull(elsewhere.header("DPoP"))
    }

    @Test
    fun `a nonce challenge from the resource server is retried once with the nonce and remembered for the origin`() = runTest {
        val rs = dpopServer(nonce = "resource-nonce-1")
        val client = client(dpopConfiguration(setOf(rs.origin)))
        client.login()

        val first = client.call(Request.Builder().url(rs.url("/api")).build())
        first.close()

        assertEquals(200, first.code)
        val sent = transcript.entries.filter { it.url.startsWith(rs.origin) }
        assertEquals("exactly one retry: $sent", 2, sent.size)
        assertEquals(401, sent[0].status)
        assertEquals("resource-nonce-1", sent[0].responseHeader("DPoP-Nonce"))
        assertTrue(sent[0].responseHeader("WWW-Authenticate")!!.contains("use_dpop_nonce"))
        assertNull(sent[0].proofClaims!!["nonce"])
        assertEquals("resource-nonce-1", sent[1].proofClaims!!["nonce"]!!.jsonPrimitive.content)
        // A fresh proof, not the first one resent.
        assertNotEquals(sent[0].proofClaims!!["jti"], sent[1].proofClaims!!["jti"])
        assertEquals(listOf(DpopRefusal.NonceRequired), rs.attempts.map { it.verdict }.filterIsInstance<DpopVerdict.Refused>().map { it.reason })
        assertTrue(rs.attempts.last().verdict is DpopVerdict.Accepted)

        // The nonce is per origin and kept: the next call needs no challenge.
        client.call(Request.Builder().url(rs.url("/api")).build()).close()
        val afterwards = transcript.entries.filter { it.url.startsWith(rs.origin) }
        assertEquals(3, afterwards.size)
        assertEquals("resource-nonce-1", afterwards[2].proofClaims!!["nonce"]!!.jsonPrimitive.content)
        assertEquals(200, afterwards[2].status)
    }

    @Test
    fun `a resource server that keeps challenging gets one retry and then NonceLoop`() = runTest {
        // It offers a nonce it will not accept: a client that retried on every challenge would never return.
        val rs = dpopServer(nonce = "demanded", offered = "offered")
        val client = client(dpopConfiguration(setOf(rs.origin)))
        client.login()

        val error = failsWith<VersolaError.Recoverable> { runBlocking { client.call(Request.Builder().url(rs.url("/api")).build()) } }

        assertTrue(error.toString(), error.reason is VersolaError.Recoverable.Cause.NonceLoop)
        assertEquals("one request and one retry, no more: ${rs.attempts.map { it.verdict }}", 2, rs.attempts.size)
    }

    @Test
    fun `a refresh keeps the key and the new token is bound to it`() = runTest {
        val rs = dpopServer()
        val client = client(dpopConfiguration(setOf(rs.origin)))
        val metadata = client.metadata()
        client.login()
        val jkt = DpopResourceServer.thumbprint(keystore.soleKey().public as ECPublicKey)
        val before = client.accessToken().value

        client.refresh()

        val requests = transcript.matching("POST", tokenPath(metadata))
        assertEquals(2, requests.size)
        val login = requests[0]
        val refresh = requests[1]
        assertEquals("refresh_token", refresh.form["grant_type"])
        assertEquals(1, refresh.headerCount("DPoP"))
        // The same key: the same jwk member for member, hence the same thumbprint, and a new jti.
        assertEquals(jwkOf(login.proofHeader), jwkOf(refresh.proofHeader))
        assertEquals(jkt, jktOf(refresh.proofHeader))
        assertEquals("POST", refresh.proofClaims!!["htm"]!!.jsonPrimitive.content)
        assertEquals(metadata.tokenEndpoint, refresh.proofClaims!!["htu"]!!.jsonPrimitive.content)
        assertNotEquals(login.proofClaims!!["jti"], refresh.proofClaims!!["jti"])
        assertFalse(refresh.proofClaims!!.containsKey("ath"))
        assertEquals(1, keystore.generated.size)

        assertEquals(200, refresh.status)
        assertEquals("DPoP", refresh.responseJson!!["token_type"]!!.jsonPrimitive.content)
        val after = refresh.responseJson!!["access_token"]!!.jsonPrimitive.content
        assertNotEquals(before, after)
        assertEquals(jkt, Transcript.decodeJwtPart(after, 1)!!["cnf"]!!.jsonObject["jkt"]!!.jsonPrimitive.content)
        assertEquals(after, client.accessToken().value)

        // And the resource server takes the new token under the same key.
        val response = client.call(Request.Builder().url(rs.url("/api")).build())
        response.close()
        assertEquals(200, response.code)
        assertEquals(DpopResourceServer.sha256Url(after), transcript.entries.last { it.url.startsWith(rs.origin) }.proofClaims!!["ath"]!!.jsonPrimitive.content)
        assertEquals(DpopVerdict.Accepted(jkt, checkNotNull(client.claims).subject), rs.attempts.single().verdict)
    }

    /**
     * What the binding is for: the access token, once stolen, is useless without the key. Each case
     * changes exactly one thing from a request the resource server accepts (the control), so the
     * refusal is that check's and nothing else's; the verdict's reason, not only the 401, is asserted.
     */
    @Test
    fun `a stolen access token is refused without the key, with another key, and with a proof that does not match`() = runTest {
        val rs = dpopServer()
        val client = client(dpopConfiguration(setOf(rs.origin)))
        client.login()
        val token = client.accessToken().value
        val sdkKey = keystore.soleKey()
        rs.assertStolenTokenIsRefused(token, sdkKey)
        val url = rs.url("/api")
        val http = OkHttpClient()

        fun send(proofs: String): DpopVerdict {
            val before = rs.attempts.size
            http.newCall(Request.Builder().url(url).header("Authorization", "DPoP $token").header("DPoP", proofs).build()).execute().close()
            assertEquals(1, rs.attempts.size - before)
            return rs.attempts.last().verdict
        }

        // A proof the SDK itself sent is single use: replayed, it is refused for its jti alone.
        client.call(Request.Builder().url(url).build()).close()
        val captured = transcript.entries.last { it.url.startsWith(rs.origin) }.header("DPoP")!!
        assertTrue("the SDK's own call", rs.attempts.last().verdict is DpopVerdict.Accepted)
        assertEquals("the SDK's own proof replayed", DpopVerdict.Refused(DpopRefusal.ReplayedJti), send(captured))
    }

    @Test
    fun `requireHardware on a JVM that produces a software key is refused with HardwareBindingUnavailable before any authorization request`() = runTest {
        val client = client(dpopConfiguration(setOf(resource.origin), binding = TokenBinding.Dpop(requireHardware = true)))

        val error = failsWith<VersolaError.Configuration> { runBlocking { client.login() } }

        assertTrue(error.toString(), error.detail is VersolaError.Configuration.Detail.HardwareBindingUnavailable)
        // Nothing went to the authorization endpoint, the PAR endpoint or the token endpoint, and no browser opened.
        assertTrue(browser.opened.toString(), browser.opened.isEmpty())
        val metadata = client.metadata()
        assertTrue(transcript.entries.toString(), transcript.entries.none { entry ->
            val path = entry.path
            path.endsWith(tokenPath(metadata)) || path.endsWith(metadata.authorizationEndpoint.substringAfter(proxy.origin)) ||
                metadata.pushedAuthorizationRequestEndpoint?.let { path.endsWith(it.substringAfter(proxy.origin)) } == true
        })
        assertEquals(SessionState.Unauthenticated, client.state())
        // The key was generated and read back before anything was sent; what it read was Software.
        assertEquals(1, keystore.generated.size)
    }

    @Test
    fun `a client the provider requires DPoP for gets no token from an SDK configured for Bearer`() = runTest {
        val client = client(dpopConfiguration(setOf(resource.origin), binding = TokenBinding.Bearer))
        val metadata = client.metadata()

        val error = runCatching { client.login() }.exceptionOrNull()

        assertNotNull("the provider issued a bearer token to a client that requires DPoP", error)
        assertTrue(error.toString(), error is VersolaError)
        val token = transcript.matching("POST", tokenPath(metadata)).single()
        assertNull(token.header("DPoP"))
        assertEquals(token.responseBody, 400, token.status)
        assertFalse(token.responseJson!!.containsKey("access_token"))
        assertNotEquals(SessionState.Authenticated, client.state())
    }

    @Test
    fun `the provider binds the refresh token to the key as well, so without the key it buys nothing`() = runTest {
        val client = client(dpopConfiguration(setOf(resource.origin)))
        val metadata = client.metadata()
        client.login()
        val refreshToken = transcript.matching("POST", tokenPath(metadata)).single().responseJson!!["refresh_token"]!!.jsonPrimitive.content
        val http = OkHttpClient()
        val attacker = DpopResourceServer.newKeyPair()

        fun refresh(proof: String?): okhttp3.Response = http.newCall(
            Request.Builder().url(metadata.tokenEndpoint).apply { proof?.let { header("DPoP", it) } }.post(
                FormBody.Builder().add("grant_type", "refresh_token").add("refresh_token", refreshToken).add("client_id", Provider.DPOP_CLIENT_ID).build(),
            ).build(),
        ).execute()

        val noProof = refresh(null)
        val otherKey = refresh(DpopResourceServer.forgeProof(attacker, "POST", metadata.tokenEndpoint, null))
        assertEquals(noProof.text(), 400, noProof.code)
        assertEquals(otherKey.text(), 400, otherKey.code)

        // Refused attempts did not spend it: the SDK, which holds the key, still refreshes.
        client.refresh()
        assertEquals(SessionState.Authenticated, client.state())
    }
    @Test
    fun `userInfo under DPoP carries the DPoP scheme and a proof bound to the token, and the provider refuses the token without the key`() = runTest {
        val client = client(dpopConfiguration(setOf(resource.origin)))
        val metadata = client.metadata()
        client.login()
        val jkt = DpopResourceServer.thumbprint(keystore.soleKey().public as ECPublicKey)
        val userinfoPath = metadata.userinfoEndpoint!!.substringAfter(proxy.origin)

        val userInfo = client.userInfo()

        assertEquals(checkNotNull(client.claims).subject, userInfo.subject)
        val sent = transcript.matching("GET", userinfoPath).single()
        assertEquals(200, sent.status)
        val authorization = sent.header("Authorization")!!
        assertTrue(authorization, authorization.startsWith("DPoP "))
        val accessToken = authorization.removePrefix("DPoP ")
        val claims = sent.proofClaims!!
        assertEquals("GET", claims["htm"]!!.jsonPrimitive.content)
        assertEquals(metadata.userinfoEndpoint, claims["htu"]!!.jsonPrimitive.content)
        assertEquals(DpopResourceServer.sha256Url(accessToken), claims["ath"]!!.jsonPrimitive.content)
        assertEquals(jkt, jktOf(sent.proofHeader))

        // The provider's own enforcement (Keycloak: "UserInfo requires a valid DPoP proof matching the access token").
        val http = OkHttpClient()
        val sdkKey = keystore.soleKey()
        val attacker = DpopResourceServer.newKeyPair()
        fun userinfo(authorization: String, proof: String?): Int = http.newCall(
            Request.Builder().url(metadata.userinfoEndpoint!!).header("Authorization", authorization).apply { proof?.let { header("DPoP", it) } }.build(),
        ).execute().use { it.code }
        assertEquals("the token with no proof", 401, userinfo("DPoP $accessToken", null))
        assertEquals("the token as a Bearer", 401, userinfo("Bearer $accessToken", null))
        assertEquals(
            "a proof from another key", 401,
            userinfo("DPoP $accessToken", DpopResourceServer.forgeProof(attacker, "GET", metadata.userinfoEndpoint!!, accessToken)),
        )
        assertEquals(
            "the control: the SDK's key, every claim right", 200,
            userinfo("DPoP $accessToken", DpopResourceServer.forgeProof(sdkKey, "GET", metadata.userinfoEndpoint!!, accessToken)),
        )
    }

    @Test
    fun `logout under DPoP revokes the refresh token and the provider then refuses it`() = runTest {
        val client = client(dpopConfiguration(setOf(resource.origin)))
        val metadata = client.metadata()
        client.login()
        val sdkKey = keystore.soleKey()
        val refreshToken = transcript.matching("POST", tokenPath(metadata)).single().responseJson!!["refresh_token"]!!.jsonPrimitive.content

        val outcome = client.logout()

        assertEquals(SessionState.Unauthenticated, client.state())
        val revoke = transcript.matching("POST", metadata.revocationEndpoint!!.substringAfter(proxy.origin)).single()
        // Revocation carries no proof by design (RFC 9449 binds the token endpoint and resources); the provider takes it anyway.
        assertNull(revoke.header("DPoP"))
        assertEquals(200, revoke.status)
        assertTrue("revocation was not taken: ${revoke.status} ${revoke.responseBody}", outcome.tokenRevoked)
        assertEquals(outcome.sessionEnded, metadata.endSessionEndpoint != null)
        // Revoked at the provider: the token, presented with the key that bound it, buys nothing.
        val response = OkHttpClient().newCall(
            Request.Builder().url(metadata.tokenEndpoint).header("DPoP", DpopResourceServer.forgeProof(sdkKey, "POST", metadata.tokenEndpoint, null)).post(
                FormBody.Builder().add("grant_type", "refresh_token").add("refresh_token", refreshToken).add("client_id", Provider.DPOP_CLIENT_ID).build(),
            ).build(),
        ).execute()
        val text = response.text()
        assertEquals(text, 400, response.code)
        assertTrue(text, text.contains("invalid_grant"))
    }

    private fun nonceChallenge(nonce: String) = mockwebserver3.MockResponse.Builder().code(400)
        .setHeader("Content-Type", "application/json").setHeader("DPoP-Nonce", nonce)
        .body("""{"error":"use_dpop_nonce","error_description":"Authorization server requires nonce in DPoP proof"}""").build()

    @Test
    fun `a nonce challenge from the provider's token endpoint is retried once with the nonce and the login completes`() = runTest {
        val client = client(dpopConfiguration(setOf(resource.origin)))
        val metadata = client.metadata()
        val path = tokenPath(metadata)
        val challenges = java.util.concurrent.atomic.AtomicInteger()
        // force-dpop-nonce: the first request to the token endpoint is answered with the challenge, the provider never sees it.
        proxy.intercept = { request -> if (request.url.encodedPath.endsWith(path) && challenges.getAndIncrement() == 0) nonceChallenge("provider-nonce-1") else null }

        client.login()

        assertEquals(SessionState.Authenticated, client.state())
        val requests = transcript.matching("POST", path)
        assertEquals("exactly one retry: $requests", 2, requests.size)
        assertEquals(400, requests[0].status)
        assertNull(requests[0].proofClaims!!["nonce"])
        assertEquals("provider-nonce-1", requests[1].proofClaims!!["nonce"]!!.jsonPrimitive.content)
        assertNotEquals(requests[0].proofClaims!!["jti"], requests[1].proofClaims!!["jti"])
        assertEquals(200, requests[1].status)
        // The provider never saw the challenged request: the harness answered it, the retry is the one Keycloak took.
        assertEquals(2, challenges.get())
    }

    @Test
    fun `a provider that keeps challenging the token request gets one retry and then NonceLoop`() = runTest {
        val client = client(dpopConfiguration(setOf(resource.origin)))
        val metadata = client.metadata()
        val path = tokenPath(metadata)
        // always-demand-dpop-nonce: every request is challenged, retries included.
        proxy.intercept = { request -> if (request.url.encodedPath.endsWith(path)) nonceChallenge("provider-nonce-${System.nanoTime()}") else null }

        val error = failsWith<VersolaError.Recoverable> { runBlocking { client.login() } }

        assertTrue(error.toString(), error.reason is VersolaError.Recoverable.Cause.NonceLoop)
        assertEquals("one request and one retry, no more", 2, transcript.matching("POST", path).size)
        assertNotEquals(SessionState.Authenticated, client.state())
    }

    @Test
    fun `a code bound to the SDK's key is not redeemed with a proof from another key`() = runTest {
        val client = client(dpopConfiguration(setOf(resource.origin)))
        val metadata = client.metadata()
        val path = tokenPath(metadata)
        val attacker = DpopResourceServer.newKeyPair()
        val upstream = OkHttpClient()
        // The thief holds the code (not the SDK's key): the token request goes out with his proof instead of the SDK's.
        proxy.intercept = { request ->
            if (!request.url.encodedPath.endsWith(path)) null else {
                val forged = DpopResourceServer.forgeProof(attacker, "POST", metadata.tokenEndpoint, null)
                val forwarded = Request.Builder().url(provider.origin + request.url.encodedPath)
                    .header("Host", proxy.origin.substringAfter("://")).header("Content-Type", "application/x-www-form-urlencoded").header("DPoP", forged)
                    .post(request.body!!.toByteArray().toRequestBody()).build()
                upstream.newCall(forwarded).execute().use { response ->
                    mockwebserver3.MockResponse.Builder().code(response.code).setHeader("Content-Type", "application/json").body(response.body.string()).build()
                }
            }
        }

        val error = runCatching { client.login() }.exceptionOrNull()

        assertNotNull("the provider redeemed a dpop_jkt-bound code with another key's proof", error)
        val token = transcript.matching("POST", path).first()
        assertEquals(token.responseBody, 400, token.status)
        assertFalse(token.responseJson!!.containsKey("access_token"))
        assertNotEquals(SessionState.Authenticated, client.state())
        // The refusal is typed, with the provider's code: this is the provider enforcing dpop_jkt, not the SDK failing on its own.
        val rejected = (error as VersolaError.Configuration).detail as VersolaError.Configuration.Detail.TokenRequestRejected
        assertEquals("invalid_request", rejected.code)
        assertTrue(rejected.toString(), rejected.description.orEmpty().contains("dpop_jkt"))
    }
}
