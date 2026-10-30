package versola.oauth.flutter.conformance

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.Headers.Companion.headersOf
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import versola.oauth.conformance.HarnessSigner
import versola.oauth.conformance.HarnessSigner.Companion.with
import versola.oauth.conformance.HarnessSigner.Companion.without
import versola.oauth.conformance.Provider
import versola.oauth.core.ProviderMetadata
import versola.oauth.flutter.ErrorCategoryMessage
import versola.oauth.flutter.LoginOptionsMessage
import versola.oauth.flutter.SessionStateMessage

/**
 * `25-id-token-nonce-mismatch`, `26-id-token-signature-invalid` and `27-id-token-claims-rejected`
 * through the bridge: the proxy re-signs the provider's ID token with the harness's key, served
 * from a substituted JWKS, so that only the claim under test is wrong. The SDK must refuse with
 * the matching reason, persist nothing and settle on the state it had; here the refusal is what
 * the plugin puts on the wire, a `Configuration` error whose case is `idTokenRejected` and whose
 * `idTokenRejection` is the reason in the spelling Dart's `IdTokenRejection` enum reads. The
 * native driver's tests are the source (`Scenario25To27IdTokenValidationTest`), case for case.
 */
class Scenario25To27IdTokenValidationBridgeTest : BridgeConformance() {

    private val signer = HarnessSigner()

    /** Installs the harness JWKS and an ID-token rewrite; returns the metadata the paths came from. */
    private fun fault(bridge: Bridge, alg: String = "RS256", kid: String? = signer.kid, mutate: (JsonObject) -> JsonObject): ProviderMetadata {
        val metadata = bridge.observe("discovery") { metadata() }
        proxy.rewrite(metadata.jwksUri!!.substringAfter(proxy.origin)) { signer.jwks() }
        proxy.rewriteJson(metadata.tokenEndpoint.substringAfter(proxy.origin)) { response ->
            val idToken = response["id_token"]?.jsonPrimitive?.content ?: return@rewriteJson response
            HarnessSigner.withIdToken(response, signer.resign(idToken, alg, kid, mutate))
        }
        return metadata
    }

    /** The reason of the rejection, as the wire spells it: the case name with its first letter lowered. */
    private fun rejected(bridge: Bridge, options: LoginOptionsMessage = DartSide.loginOptions()): String {
        val error = bridge.dart.login(options).failure()
        assertError(error, ErrorCategoryMessage.CONFIGURATION, "idTokenRejected")
        return checkNotNull(error.idTokenRejection) { "idTokenRejected without a reason" }
    }

    /** [since]: the transcript's size when the fault was installed; what came before is not the rejection's. */
    private fun assertNothingPersisted(bridge: Bridge, metadata: ProviderMetadata, since: Int = 0) {
        assertEquals(SessionStateMessage.UNAUTHENTICATED, bridge.dart.sessionState())
        assertNull(bridge.dart.claims())
        // No userinfo and no protected origin after the rejection.
        val after = transcript.entries.drop(since)
        assertTrue(after.none { it.method == "GET" && it.url.startsWith(metadata.userinfoEndpoint!!) })
        assertTrue(after.none { it.url.startsWith(resource.origin) })
        // The refresh token the provider issued for the refused ID token is revoked once, best
        // effort, by the native SDK (`spec/oauth-sdk-api.md` section 11).
        metadata.revocationEndpoint?.let { endpoint ->
            // Detached from the login (the error is delivered first), so awaited here, bounded.
            val deadline = System.currentTimeMillis() + 5_000
            while (transcript.entries.drop(since).none { it.method == "POST" && it.url.startsWith(endpoint) } && System.currentTimeMillis() < deadline) {
                Thread.sleep(25)
            }
            assertEquals(1, transcript.entries.drop(since).count { it.method == "POST" && it.url.startsWith(endpoint) })
        }
        // The store is as it was before login(): nothing to refresh with.
        assertEquals(ErrorCategoryMessage.REAUTHENTICATE, bridge.dart.accessToken().failure().category)
    }

    // ---- 25 ----

    @Test
    fun `25 - an ID token whose nonce is not the one sent is rejected before anything is persisted`() {
        val bridge = bridge()
        val metadata = fault(bridge) { it.with("nonce" to JsonPrimitive("not-the-nonce-the-sdk-sent")) }

        assertEquals("nonce", rejected(bridge))
        assertNothingPersisted(bridge, metadata)
    }

    @Test
    fun `25 - a rejected login over a stored grant leaves the session Authenticated as it was`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()
        val subjectBefore = checkNotNull(bridge.dart.claims()).subject
        fault(bridge) { it.without("nonce") }

        assertEquals("nonce", rejected(bridge))
        assertEquals(SessionStateMessage.AUTHENTICATED, bridge.dart.sessionState())
        assertEquals(subjectBefore, bridge.dart.claims()?.subject)
        // The stored grant still works: the access token comes without a new browser.
        assertNotNull(bridge.dart.accessToken().token())
        assertEquals(2, browser.opened.size)
    }

    // ---- 26 ----

    @Test
    fun `26A - a signature that does not verify is rejected as Signature`() {
        val bridge = bridge()
        val metadata = bridge.observe("discovery") { metadata() }
        // The provider's own keys stay; the token's signature bytes are flipped.
        proxy.rewriteJson(metadata.tokenEndpoint.substringAfter(proxy.origin)) { response ->
            val idToken = response["id_token"]!!.jsonPrimitive.content
            val parts = idToken.split('.')
            val signature = HarnessSigner.b64(java.util.Base64.getUrlDecoder().decode(parts[2]).also { it[0] = (it[0].toInt() xor 0x55).toByte() })
            HarnessSigner.withIdToken(response, "${parts[0]}.${parts[1]}.$signature")
        }

        assertEquals("signature", rejected(bridge))
        assertNothingPersisted(bridge, metadata)
    }

    @Test
    fun `26B - a key absent from jwks_uri causes exactly one refetch, then Signature`() {
        val bridge = bridge()
        val metadata = bridge.observe("discovery") { metadata() }
        val jwksPath = metadata.jwksUri!!.substringAfter(proxy.origin)
        // Warm the key cache with a real login so the refetch is observable as such.
        bridge.dart.login().assertOk()
        bridge.dart.logout()
        val fetchesBefore = transcript.matching("GET", jwksPath).size
        val since = transcript.entries.size
        val other = HarnessSigner(kid = "absent-from-the-set")
        proxy.rewriteJson(metadata.tokenEndpoint.substringAfter(proxy.origin)) { response ->
            HarnessSigner.withIdToken(response, other.resign(response["id_token"]!!.jsonPrimitive.content) { it })
        }

        assertEquals("signature", rejected(bridge))
        assertEquals("JWKS fetches during the rejected login", 1, transcript.matching("GET", jwksPath).size - fetchesBefore)
        assertNothingPersisted(bridge, metadata, since)
    }

    @Test
    fun `26C - alg none with an empty signature is rejected as Algorithm before any key is fetched`() {
        val bridge = bridge()
        val metadata = fault(bridge, alg = "none", kid = null) { it }
        val jwksPath = metadata.jwksUri!!.substringAfter(proxy.origin)
        val fetchesBefore = transcript.matching("GET", jwksPath).size

        assertEquals("algorithm", rejected(bridge))
        assertEquals(fetchesBefore, transcript.matching("GET", jwksPath).size)
        assertNothingPersisted(bridge, metadata)
    }

    @Test
    fun `26D - HS256 signed with the client id as key is rejected as Algorithm`() {
        val bridge = bridge()
        val metadata = fault(bridge, alg = "HS256", kid = null) { it }

        assertEquals("algorithm", rejected(bridge))
        assertNothingPersisted(bridge, metadata)
    }

    // ---- 27 ----

    @Test
    fun `27A - iss differing by a trailing slash is rejected as Issuer`() {
        val bridge = bridge()
        val metadata = fault(bridge) { it.with("iss" to JsonPrimitive(it["iss"]!!.jsonPrimitive.content + "/")) }

        assertEquals("issuer", rejected(bridge))
        assertNothingPersisted(bridge, metadata)
    }

    @Test
    fun `27B - aud equal to another client id is rejected as Audience`() {
        val bridge = bridge()
        val metadata = fault(bridge) { it.with("aud" to JsonPrimitive("some-other-client")) }

        assertEquals("audience", rejected(bridge))
        assertNothingPersisted(bridge, metadata)
    }

    @Test
    fun `27C - a two-element aud without azp is rejected as Audience`() {
        val bridge = bridge()
        val metadata = fault(bridge) {
            it.with("aud" to JsonArray(listOf(JsonPrimitive(Provider.CLIENT_ID), JsonPrimitive("some-other-client")))).without("azp")
        }

        assertEquals("audience", rejected(bridge))
        assertNothingPersisted(bridge, metadata)
    }

    @Test
    fun `27D - exp in the past by the server's Date header beyond the tolerance is rejected as Expired`() {
        val bridge = bridge()
        val now = Instant.now()
        val metadata = fault(bridge) { it.with("exp" to JsonPrimitive(now.epochSecond - 120)) }
        proxy.addHeaders(metadata.tokenEndpoint.substringAfter(proxy.origin), headersOf("Date", httpDate(now)))

        assertEquals("expired", rejected(bridge))
        assertNothingPersisted(bridge, metadata)
    }

    @Test
    fun `27D - a token live by the server's Date header is accepted although the device clock would expire it`() {
        val bridge = bridge()
        val serverNow = Instant.now().minusSeconds(600)
        val metadata = fault(bridge) {
            it.with(
                "iat" to JsonPrimitive(serverNow.epochSecond),
                "auth_time" to JsonPrimitive(serverNow.epochSecond),
                "exp" to JsonPrimitive(serverNow.epochSecond + 60),
            )
        }
        proxy.addHeaders(metadata.tokenEndpoint.substringAfter(proxy.origin), headersOf("Date", httpDate(serverNow)))

        bridge.dart.login().assertOk()

        assertEquals(SessionStateMessage.AUTHENTICATED, bridge.dart.sessionState())
        assertEquals(serverNow.epochSecond + 60, bridge.dart.claims()?.expiresAtEpochSeconds)
    }

    @Test
    fun `27E - a missing iat is rejected as IssuedAt`() {
        val bridge = bridge()
        val metadata = fault(bridge) { it.without("iat") }

        assertEquals("issuedAt", rejected(bridge))
        assertNothingPersisted(bridge, metadata)
    }

    @Test
    fun `27F - auth_time older than the max_age requested is rejected as AuthTime`() {
        val bridge = bridge()
        val metadata = fault(bridge) { it.with("auth_time" to JsonPrimitive(Instant.now().epochSecond - 3600)) }

        assertEquals("authTime", rejected(bridge, DartSide.loginOptions(maxAge = 60)))
        assertNothingPersisted(bridge, metadata)
    }

    private fun httpDate(instant: Instant): String =
        DateTimeFormatter.RFC_1123_DATE_TIME.format(instant.atOffset(ZoneOffset.UTC))
}
