package versola.oauth.flutter.conformance

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.FormBody
import okhttp3.OkHttpClient
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
import versola.oauth.conformance.DpopResourceServer
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
 * Flutter has no authenticated client and mints no proof (`spec/oauth-sdk-api.md` section 10), so
 * what a native test proved through the interceptor (the call's own proof, the resource's nonce
 * challenge, the replay of a proof the SDK sent) is the native facades'. The bridge makes the
 * stolen-token requests with the token `accessToken()` hands over, which is what a Flutter app
 * holds and cannot present itself.
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

    private fun dpopServer(): DpopResourceServer = DpopResourceServer(provider, proxy).also {
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
}
