package versola.oauth.flutter.conformance

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.FormBody
import okhttp3.OkHttpClient
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Request
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
import versola.oauth.conformance.DpopRefusal
import versola.oauth.conformance.DpopResourceServer
import versola.oauth.conformance.DpopVerdict
import versola.oauth.conformance.Provider
import versola.oauth.conformance.text
import versola.oauth.core.TokenBinding
import versola.oauth.flutter.ErrorCategoryMessage
import versola.oauth.flutter.KeyAttestationFailure
import versola.oauth.flutter.KeyAttestationOk
import versola.oauth.flutter.SessionStateMessage
import java.security.interfaces.ECPublicKey

/**
 * `33-dpop-end-to-end` through the bridge: the plugin's `TokenBindingMessage.dpop` /
 * `dpopRequireHardware` against a provider that requires DPoP and a resource server that verifies
 * it. The assertions are the native driver's (`Scenario33DpopEndToEndTest`); the key is the SDK's
 * own on the JVM's stand-in Keystore, so the tier is **software** and nothing here says anything
 * about StrongBox or the TEE.
 *
 * Flutter mints no proof itself, but it has the authenticated client (`OAuthClient.httpClient()`,
 * `spec/oauth-sdk-api.md` section 10): the tests named `httpRequest` below send the request the way
 * the Dart client does and the plugin runs it with `OAuthClient.call`, so the call's own proof, the
 * resource's nonce challenge and the nonce loop are asserted through the bridge, on the wire and
 * at the resource server, with no token ever handed to Dart. Only the replay of a proof the SDK
 * sent needs the harness to reach the SDK's request and stays the native driver's. The
 * stolen-token requests are made with the token `accessToken()` hands over, which is what a
 * Flutter app holds and cannot present itself.
 */
class Scenario33DpopEndToEndBridgeTest : BridgeConformance() {

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

    private fun jwkOf(proof: JsonObject?): JsonObject = checkNotNull(proof)["jwk"]!!.jsonObject

    @Test
    fun `bridge - the token request carries a valid proof and the issued token is DPoP-bound to the SDK's key`() {
        val bridge = bridge(clientId = Provider.DPOP_CLIENT_ID, tokenBinding = TokenBinding.Dpop())
        val metadata = bridge.observe("discovery") { metadata() }

        bridge.dart.login().assertOk()

        assertEquals(SessionStateMessage.AUTHENTICATED, bridge.dart.sessionState())
        // The tier is read back through the bridge, not assumed (security.md).
        assertEquals("software", (bridge.dart.keyAttestation() as KeyAttestationOk).tier)
        assertTrue(logger.warnings.toString(), logger.warnings.any { it.contains("software-backed") })
        val jkt = DpopResourceServer.thumbprint(keystore.soleKey().public as ECPublicKey)

        val authorization = if (metadata.pushedAuthorizationRequestEndpoint != null) {
            theRequest("POST", metadata.pushedAuthorizationRequestEndpoint!!.substringAfter(proxy.origin)).form
        } else {
            browser.opened.single().queryMap()
        }
        assertEquals(jkt, authorization["dpop_jkt"])

        val token = theRequest("POST", metadata.tokenEndpoint.substringAfter(proxy.origin))
        assertEquals(1, token.headerCount("DPoP"))
        val header = token.proofHeader!!
        val claims = token.proofClaims!!
        assertEquals("dpop+jwt", header["typ"]!!.jsonPrimitive.content)
        assertEquals("ES256", header["alg"]!!.jsonPrimitive.content)
        assertEquals(setOf("kty", "crv", "x", "y"), jwkOf(header).keys)
        assertEquals(jkt, DpopResourceServer.thumbprint(jwkOf(header)))
        assertEquals("POST", claims["htm"]!!.jsonPrimitive.content)
        assertEquals(metadata.tokenEndpoint, claims["htu"]!!.jsonPrimitive.content)
        assertFalse(claims.containsKey("ath"))
        assertNoSecretOnTheWire(token)

        assertEquals("DPoP", token.responseJson!!["token_type"]!!.jsonPrimitive.content)
        val accessToken = token.responseJson!!["access_token"]!!.jsonPrimitive.content
        assertEquals(jkt, versola.oauth.conformance.Transcript.decodeJwtPart(accessToken, 1)!!["cnf"]!!.jsonObject["jkt"]!!.jsonPrimitive.content)
        // What a Flutter app is handed: the token and its type, which it has no way to present.
        val handedOver = bridge.dart.accessToken().token()
        assertEquals(accessToken, handedOver.value)
        assertEquals("DPoP", handedOver.tokenType)
    }

    @Test
    fun `bridge - a refresh keeps the key and the new token is bound to it`() {
        val bridge = bridge(clientId = Provider.DPOP_CLIENT_ID, tokenBinding = TokenBinding.Dpop())
        val metadata = bridge.observe("discovery") { metadata() }
        bridge.dart.login().assertOk()
        val jkt = DpopResourceServer.thumbprint(keystore.soleKey().public as ECPublicKey)
        val before = bridge.dart.accessToken().token().value

        bridge.dart.refresh().assertOk()

        val requests = transcript.matching("POST", metadata.tokenEndpoint.substringAfter(proxy.origin))
        assertEquals(2, requests.size)
        val login = requests[0]
        val refresh = requests[1]
        assertEquals("refresh_token", refresh.form["grant_type"])
        assertEquals(1, refresh.headerCount("DPoP"))
        assertEquals(jwkOf(login.proofHeader), jwkOf(refresh.proofHeader))
        assertEquals(jkt, DpopResourceServer.thumbprint(jwkOf(refresh.proofHeader)))
        assertEquals("POST", refresh.proofClaims!!["htm"]!!.jsonPrimitive.content)
        assertEquals(metadata.tokenEndpoint, refresh.proofClaims!!["htu"]!!.jsonPrimitive.content)
        assertNotEquals(login.proofClaims!!["jti"], refresh.proofClaims!!["jti"])
        assertFalse(refresh.proofClaims!!.containsKey("ath"))
        assertEquals(1, keystore.generated.size)

        assertEquals("DPoP", refresh.responseJson!!["token_type"]!!.jsonPrimitive.content)
        val after = refresh.responseJson!!["access_token"]!!.jsonPrimitive.content
        assertNotEquals(before, after)
        assertEquals(jkt, versola.oauth.conformance.Transcript.decodeJwtPart(after, 1)!!["cnf"]!!.jsonObject["jkt"]!!.jsonPrimitive.content)
        assertEquals(after, bridge.dart.accessToken().token().value)
    }

    @Test
    fun `bridge - a stolen access token is refused without the key, with another key, and with a proof that does not match`() {
        val rs = dpopServer()
        val bridge = bridge(clientId = Provider.DPOP_CLIENT_ID, protectedOrigins = setOf(rs.origin), tokenBinding = TokenBinding.Dpop())
        bridge.dart.login().assertOk()
        val token = bridge.dart.accessToken().token()
        assertEquals("DPoP", token.tokenType)

        rs.assertStolenTokenIsRefused(token.value, keystore.soleKey())
    }

    @Test
    fun `bridge - requireHardware on a JVM that produces a software key is refused with HardwareBindingUnavailable before any authorization request`() {
        val bridge = bridge(clientId = Provider.DPOP_CLIENT_ID, tokenBinding = TokenBinding.Dpop(requireHardware = true))
        val metadata = bridge.observe("discovery") { metadata() }

        val error = bridge.dart.login().failure()

        assertError(error, ErrorCategoryMessage.CONFIGURATION, "hardwareBindingUnavailable")
        assertTrue(browser.opened.toString(), browser.opened.isEmpty())
        assertTrue(transcript.entries.toString(), transcript.entries.none { entry ->
            val path = entry.path
            path.endsWith(metadata.tokenEndpoint.substringAfter(proxy.origin)) || path.endsWith(metadata.authorizationEndpoint.substringAfter(proxy.origin)) ||
                metadata.pushedAuthorizationRequestEndpoint?.let { path.endsWith(it.substringAfter(proxy.origin)) } == true
        })
        assertEquals(SessionStateMessage.UNAUTHENTICATED, bridge.dart.sessionState())
        // Asking for the tier is refused the same way: asking generates the key (flutter.md).
        val attestation = bridge.dart.keyAttestation()
        assertTrue(attestation.toString(), attestation is KeyAttestationFailure)
        assertEquals("hardwareBindingUnavailable", (attestation as KeyAttestationFailure).error.kind)
    }

    @Test
    fun `bridge - a client the provider requires DPoP for gets no token from a client configured for Bearer`() {
        val bridge = bridge(clientId = Provider.DPOP_CLIENT_ID, tokenBinding = TokenBinding.Bearer)
        val metadata = bridge.observe("discovery") { metadata() }

        val error = bridge.dart.login().failure()

        assertNotNull(error)
        val token = transcript.matching("POST", metadata.tokenEndpoint.substringAfter(proxy.origin)).single()
        assertNull(token.header("DPoP"))
        assertEquals(token.responseBody, 400, token.status)
        assertFalse(token.responseJson!!.containsKey("access_token"))
        assertNotEquals(SessionStateMessage.AUTHENTICATED, bridge.dart.sessionState())
    }

    @Test
    fun `bridge - the provider binds the refresh token to the key as well, so without the key it buys nothing`() {
        val bridge = bridge(clientId = Provider.DPOP_CLIENT_ID, tokenBinding = TokenBinding.Dpop())
        val metadata = bridge.observe("discovery") { metadata() }
        bridge.dart.login().assertOk()
        val refreshToken = transcript.matching("POST", metadata.tokenEndpoint.substringAfter(proxy.origin)).single().responseJson!!["refresh_token"]!!.jsonPrimitive.content
        val attacker = DpopResourceServer.newKeyPair()

        fun refresh(proof: String?): okhttp3.Response = app.newCall(
            Request.Builder().url(metadata.tokenEndpoint).apply { proof?.let { header("DPoP", it) } }.post(
                FormBody.Builder().add("grant_type", "refresh_token").add("refresh_token", refreshToken).add("client_id", Provider.DPOP_CLIENT_ID).build(),
            ).build(),
        ).execute()

        val noProof = refresh(null)
        val otherKey = refresh(DpopResourceServer.forgeProof(attacker, "POST", metadata.tokenEndpoint, null))
        assertEquals(noProof.text(), 400, noProof.code)
        assertEquals(otherKey.text(), 400, otherKey.code)

        // Refused attempts did not spend it: the SDK, which holds the key, still refreshes.
        bridge.dart.refresh().assertOk()
        assertEquals(SessionStateMessage.AUTHENTICATED, bridge.dart.sessionState())
    }

    @Test
    fun `bridge - userInfo under DPoP carries the DPoP scheme and a proof bound to the token`() {
        val bridge = bridge(clientId = Provider.DPOP_CLIENT_ID, tokenBinding = TokenBinding.Dpop())
        val metadata = bridge.observe("discovery") { metadata() }
        bridge.dart.login().assertOk()
        val jkt = DpopResourceServer.thumbprint(keystore.soleKey().public as ECPublicKey)

        val subject = bridge.dart.userInfo().subject()

        assertEquals(checkNotNull(bridge.dart.claims()).subject, subject)
        val sent = transcript.matching("GET", metadata.userinfoEndpoint!!.substringAfter(proxy.origin)).single()
        assertEquals(200, sent.status)
        val authorization = sent.header("Authorization")!!
        assertTrue(authorization, authorization.startsWith("DPoP "))
        val claims = sent.proofClaims!!
        assertEquals("GET", claims["htm"]!!.jsonPrimitive.content)
        assertEquals(metadata.userinfoEndpoint, claims["htu"]!!.jsonPrimitive.content)
        assertEquals(DpopResourceServer.sha256Url(authorization.removePrefix("DPoP ")), claims["ath"]!!.jsonPrimitive.content)
        assertEquals(jkt, DpopResourceServer.thumbprint(jwkOf(sent.proofHeader)))
    }

    @Test
    fun `bridge - logout under DPoP revokes the refresh token and the provider then refuses it`() {
        val bridge = bridge(clientId = Provider.DPOP_CLIENT_ID, tokenBinding = TokenBinding.Dpop())
        val metadata = bridge.observe("discovery") { metadata() }
        bridge.dart.login().assertOk()
        val sdkKey = keystore.soleKey()
        val refreshToken = transcript.matching("POST", metadata.tokenEndpoint.substringAfter(proxy.origin)).single().responseJson!!["refresh_token"]!!.jsonPrimitive.content

        val outcome = bridge.dart.logout()

        assertEquals(SessionStateMessage.UNAUTHENTICATED, bridge.dart.sessionState())
        val revoke = transcript.matching("POST", metadata.revocationEndpoint!!.substringAfter(proxy.origin)).single()
        assertNull(revoke.header("DPoP"))
        assertEquals(200, revoke.status)
        assertTrue(outcome.tokenRevoked)
        val response = app.newCall(
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
    fun `bridge - a nonce challenge from the provider's token endpoint is retried once with the nonce and the login completes`() {
        val bridge = bridge(clientId = Provider.DPOP_CLIENT_ID, tokenBinding = TokenBinding.Dpop())
        val metadata = bridge.observe("discovery") { metadata() }
        val path = metadata.tokenEndpoint.substringAfter(proxy.origin)
        val challenges = java.util.concurrent.atomic.AtomicInteger()
        proxy.intercept = { request -> if (request.url.encodedPath.endsWith(path) && challenges.getAndIncrement() == 0) nonceChallenge("provider-nonce-1") else null }

        bridge.dart.login().assertOk()

        assertEquals(SessionStateMessage.AUTHENTICATED, bridge.dart.sessionState())
        val requests = transcript.matching("POST", path)
        assertEquals("exactly one retry: $requests", 2, requests.size)
        assertEquals(400, requests[0].status)
        assertNull(requests[0].proofClaims!!["nonce"])
        assertEquals("provider-nonce-1", requests[1].proofClaims!!["nonce"]!!.jsonPrimitive.content)
        assertNotEquals(requests[0].proofClaims!!["jti"], requests[1].proofClaims!!["jti"])
        assertEquals(200, requests[1].status)
    }

    @Test
    fun `bridge - a provider that keeps challenging the token request gets one retry and then NonceLoop`() {
        val bridge = bridge(clientId = Provider.DPOP_CLIENT_ID, tokenBinding = TokenBinding.Dpop())
        val metadata = bridge.observe("discovery") { metadata() }
        val path = metadata.tokenEndpoint.substringAfter(proxy.origin)
        proxy.intercept = { request -> if (request.url.encodedPath.endsWith(path)) nonceChallenge("provider-nonce-${System.nanoTime()}") else null }

        val error = bridge.dart.login().failure()

        assertError(error, ErrorCategoryMessage.RECOVERABLE, "nonceLoop")
        assertEquals("one request and one retry, no more", 2, transcript.matching("POST", path).size)
        assertNotEquals(SessionStateMessage.AUTHENTICATED, bridge.dart.sessionState())
    }

    @Test
    fun `bridge - a code bound to the SDK's key is not redeemed with a proof from another key`() {
        val bridge = bridge(clientId = Provider.DPOP_CLIENT_ID, tokenBinding = TokenBinding.Dpop())
        val metadata = bridge.observe("discovery") { metadata() }
        val path = metadata.tokenEndpoint.substringAfter(proxy.origin)
        val attacker = DpopResourceServer.newKeyPair()
        val upstream = OkHttpClient()
        proxy.intercept = { request ->
            if (!request.url.encodedPath.endsWith(path)) null else {
                val forwarded = Request.Builder().url(provider.origin + request.url.encodedPath)
                    .header("Host", proxy.origin.substringAfter("://")).header("Content-Type", "application/x-www-form-urlencoded")
                    .header("DPoP", DpopResourceServer.forgeProof(attacker, "POST", metadata.tokenEndpoint, null))
                    .post(request.body!!.toByteArray().toRequestBody()).build()
                upstream.newCall(forwarded).execute().use { response ->
                    mockwebserver3.MockResponse.Builder().code(response.code).setHeader("Content-Type", "application/json").body(response.body.string()).build()
                }
            }
        }

        val error = bridge.dart.login().failure()

        assertError(error, ErrorCategoryMessage.CONFIGURATION, "tokenRequestRejected")
        assertEquals("invalid_request", error.code)
        assertTrue(error.errorDescription.orEmpty(), error.errorDescription.orEmpty().contains("dpop_jkt"))
        val token = transcript.matching("POST", path).first()
        assertEquals(400, token.status)
        assertFalse(token.responseJson!!.containsKey("access_token"))
        assertNotEquals(SessionStateMessage.AUTHENTICATED, bridge.dart.sessionState())
    }

    @Test
    fun `bridge - httpRequest sends the DPoP scheme and a proof bound to the token, which the resource server accepts`() {
        val rs = dpopServer()
        val bridge = bridge(clientId = Provider.DPOP_CLIENT_ID, protectedOrigins = setOf(rs.origin), tokenBinding = TokenBinding.Dpop())
        bridge.dart.login().assertOk()
        val jkt = DpopResourceServer.thumbprint(keystore.soleKey().public as ECPublicKey)
        val subject = checkNotNull(bridge.dart.claims()).subject

        val response = bridge.dart.httpRequest(rs.url("/api/items?page=2")).response()

        assertEquals(String(response.body), 200, response.status)
        val sent = transcript.entries.single { it.url.startsWith(rs.origin) }
        val authorization = sent.header("Authorization")!!
        assertTrue(authorization, authorization.startsWith("DPoP "))
        val accessToken = authorization.removePrefix("DPoP ")
        assertEquals(1, sent.headerCount("DPoP"))
        val claims = sent.proofClaims!!
        assertEquals("GET", claims["htm"]!!.jsonPrimitive.content)
        assertEquals("the URL without its query", rs.url("/api/items"), claims["htu"]!!.jsonPrimitive.content)
        assertEquals(DpopResourceServer.sha256Url(accessToken), claims["ath"]!!.jsonPrimitive.content)
        assertEquals(jkt, DpopResourceServer.thumbprint(jwkOf(sent.proofHeader)))
        assertEquals(listOf<DpopVerdict>(DpopVerdict.Accepted(jkt, subject)), rs.verdicts("/api/items"))
        assertEquals(1, rs.attempts.size)
        // The token itself never crossed: the app did not ask for it, and the response carries none.
        assertFalse(String(response.body).contains(accessToken))
        assertTrue(bridge.dart.receivedAccessTokenReplies.isEmpty())

        // An origin that is not protected gets neither the token nor a proof, whatever the app put in the headers.
        bridge.dart.httpRequest(proxy.origin + "/elsewhere", headers = listOf("DPoP" to "app-own")).response()
        val elsewhere = transcript.entries.single { it.url == proxy.origin + "/elsewhere" }
        assertNull(elsewhere.header("Authorization"))
        assertEquals("app-own", elsewhere.header("DPoP"))
    }

    @Test
    fun `bridge - an Authorization and a DPoP header the app set on the DPoP-protected origin are replaced, the resource sees exactly one of each`() {
        val rs = dpopServer()
        val bridge = bridge(clientId = Provider.DPOP_CLIENT_ID, protectedOrigins = setOf(rs.origin), tokenBinding = TokenBinding.Dpop())
        bridge.dart.login().assertOk()

        val response = bridge.dart.httpRequest(
            rs.url("/api"), headers = listOf("Authorization" to "Bearer app-supplied", "DPoP" to "app-forged", "dpop" to "app-forged-too"),
        ).response()

        assertEquals(String(response.body), 200, response.status)
        val sent = transcript.entries.single { it.url.startsWith(rs.origin) }
        assertEquals(1, sent.headerCount("Authorization"))
        assertTrue(sent.header("Authorization")!!.startsWith("DPoP "))
        assertEquals(1, sent.headerCount("DPoP"))
        assertEquals(listOf<DpopRefusal>(), rs.attempts.map { it.verdict }.filterIsInstance<DpopVerdict.Refused>().map { it.reason })
    }

    @Test
    fun `bridge - httpRequest answers the resource's nonce challenge once with the nonce and remembers it for the origin`() {
        val rs = dpopServer(nonce = "resource-nonce-1")
        val bridge = bridge(clientId = Provider.DPOP_CLIENT_ID, protectedOrigins = setOf(rs.origin), tokenBinding = TokenBinding.Dpop())
        bridge.dart.login().assertOk()

        val first = bridge.dart.httpRequest(rs.url("/api")).response()

        assertEquals(200, first.status)
        val sent = transcript.entries.filter { it.url.startsWith(rs.origin) }
        assertEquals("exactly one retry: $sent", 2, sent.size)
        assertEquals(401, sent[0].status)
        assertEquals("resource-nonce-1", sent[0].responseHeader("DPoP-Nonce"))
        assertNull(sent[0].proofClaims!!["nonce"])
        assertEquals("resource-nonce-1", sent[1].proofClaims!!["nonce"]!!.jsonPrimitive.content)
        assertNotEquals("a fresh proof, not the first one resent", sent[0].proofClaims!!["jti"], sent[1].proofClaims!!["jti"])

        // The nonce is per origin and kept: the next call needs no challenge.
        bridge.dart.httpRequest(rs.url("/api")).response()
        val afterwards = transcript.entries.filter { it.url.startsWith(rs.origin) }
        assertEquals(3, afterwards.size)
        assertEquals("resource-nonce-1", afterwards[2].proofClaims!!["nonce"]!!.jsonPrimitive.content)
    }

    @Test
    fun `bridge - a resource that keeps challenging gets one retry and then NonceLoop through httpRequest`() {
        val rs = dpopServer(nonce = "demanded", offered = "offered")
        val bridge = bridge(clientId = Provider.DPOP_CLIENT_ID, protectedOrigins = setOf(rs.origin), tokenBinding = TokenBinding.Dpop())
        bridge.dart.login().assertOk()

        val error = bridge.dart.httpRequest(rs.url("/api")).failure()

        assertError(error, ErrorCategoryMessage.RECOVERABLE, "nonceLoop")
        assertEquals("one request and one retry, no more: ${rs.attempts.map { it.verdict }}", 2, rs.attempts.size)
    }
}
