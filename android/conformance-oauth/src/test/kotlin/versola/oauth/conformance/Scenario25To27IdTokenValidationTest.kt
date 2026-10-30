package versola.oauth.conformance

import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
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
import versola.oauth.LoginOptions
import versola.oauth.OAuthClient
import versola.oauth.conformance.HarnessSigner.Companion.with
import versola.oauth.conformance.HarnessSigner.Companion.without
import versola.oauth.core.IdTokenRejection
import versola.oauth.core.ProviderMetadata
import versola.oauth.core.SessionState
import versola.oauth.core.VersolaError

/**
 * `25-id-token-nonce-mismatch`, `26-id-token-signature-invalid` and `27-id-token-claims-rejected`:
 * the proxy re-signs the provider's ID token with the harness's key, served from a substituted
 * JWKS, so that only the claim under test is wrong; the SDK must refuse with the matching
 * reason, persist nothing and settle on the state it had.
 *
 * Case D of scenario 27 moves the server's clock rather than the device's: the device clock
 * cannot be moved from a JVM test, and the `Date` header the proxy adds is how the SDK learns
 * the server's time, so a token that is expired by the device clock but live by the server's
 * is accepted, and one expired by both is not.
 */
class Scenario25To27IdTokenValidationTest : ProviderConformance() {

    private val signer = HarnessSigner()

    /** Installs the harness JWKS and an ID-token rewrite; returns the metadata the paths came from. */
    private suspend fun fault(client: OAuthClient, alg: String = "RS256", kid: String? = signer.kid, mutate: (JsonObject) -> JsonObject): ProviderMetadata {
        val metadata = client.metadata()
        proxy.rewrite(metadata.jwksUri!!.substringAfter(proxy.origin)) { signer.jwks() }
        proxy.rewriteJson(metadata.tokenEndpoint.substringAfter(proxy.origin)) { response ->
            val idToken = response["id_token"]?.jsonPrimitive?.content ?: return@rewriteJson response
            HarnessSigner.withIdToken(response, signer.resign(idToken, alg, kid, mutate))
        }
        return metadata
    }

    private suspend fun rejected(client: OAuthClient, options: LoginOptions = LoginOptions.Default): IdTokenRejection {
        val error = failsWith<VersolaError.Configuration> { runBlocking { client.login(options) } }
        val detail = error.detail as? VersolaError.Configuration.Detail.IdTokenRejected
            ?: throw AssertionError("expected IdTokenRejected, got ${error.detail}")
        return detail.reason
    }

    /** [since]: the transcript's size when the fault was installed; what came before is not the rejection's. */
    private suspend fun assertNothingPersisted(client: OAuthClient, metadata: ProviderMetadata, since: Int = 0) {
        assertEquals(SessionState.Unauthenticated, client.state())
        assertNull(client.claims)
        // No userinfo and no protected origin after the rejection.
        val after = transcript.entries.drop(since)
        assertTrue(after.none { it.method == "GET" && it.url.startsWith(metadata.userinfoEndpoint!!) })
        assertTrue(after.none { it.url.startsWith(resource.origin) })
        // The refresh token the provider issued for the refused ID token is a live credential no
        // device holds, so it is revoked once, best effort and detached from the login (`spec/oauth-sdk-api.md` section 11).
        metadata.revocationEndpoint?.let { endpoint ->
            // Detached from the login (the error is delivered first), so awaited here, bounded.
            val deadline = System.currentTimeMillis() + 5_000
            while (transcript.entries.drop(since).none { it.method == "POST" && it.url.startsWith(endpoint) } && System.currentTimeMillis() < deadline) {
                Thread.sleep(25)
            }
            assertEquals(1, transcript.entries.drop(since).count { it.method == "POST" && it.url.startsWith(endpoint) })
        }
        // The store is as it was before login(): nothing to refresh with.
        failsWith<VersolaError.Reauthenticate> { runBlocking { client.accessToken() } }
    }

    // ---- 25 ----

    @Test
    fun `25 - an ID token whose nonce is not the one sent is rejected before anything is persisted`() = runTest {
        val client = client()
        val metadata = fault(client) { it.with("nonce" to JsonPrimitive("not-the-nonce-the-sdk-sent")) }

        assertEquals(IdTokenRejection.Nonce, rejected(client))
        assertNothingPersisted(client, metadata)
    }

    @Test
    fun `25 - a rejected login over a stored grant leaves the session Authenticated as it was`() = runTest {
        val client = client()
        client.login()
        val subjectBefore = checkNotNull(client.claims).subject
        fault(client) { it.without("nonce") }

        assertEquals(IdTokenRejection.Nonce, rejected(client))
        assertEquals(SessionState.Authenticated, client.state())
        assertEquals(subjectBefore, client.claims?.subject)
        // The stored grant still works: the access token comes without a new browser.
        assertNotNull(client.accessToken())
        assertEquals(2, browser.opened.size)
    }

    // ---- 26 ----

    @Test
    fun `26A - a signature that does not verify is rejected as Signature`() = runTest {
        val client = client()
        val metadata = client.metadata()
        // The provider's own keys stay; the token's signature bytes are flipped.
        proxy.rewriteJson(metadata.tokenEndpoint.substringAfter(proxy.origin)) { response ->
            val idToken = response["id_token"]!!.jsonPrimitive.content
            val parts = idToken.split('.')
            val signature = HarnessSigner.b64(java.util.Base64.getUrlDecoder().decode(parts[2]).also { it[0] = (it[0].toInt() xor 0x55).toByte() })
            HarnessSigner.withIdToken(response, "${parts[0]}.${parts[1]}.$signature")
        }

        assertEquals(IdTokenRejection.Signature, rejected(client))
        assertNothingPersisted(client, metadata)
    }

    @Test
    fun `26B - a key absent from jwks_uri causes exactly one refetch, then Signature`() = runTest {
        val client = client()
        val metadata = client.metadata()
        val jwksPath = metadata.jwksUri!!.substringAfter(proxy.origin)
        // Warm the key cache with a real login so the refetch is observable as such.
        client.login()
        client.logout()
        val fetchesBefore = transcript.matching("GET", jwksPath).size
        val since = transcript.entries.size
        val other = HarnessSigner(kid = "absent-from-the-set")
        proxy.rewriteJson(metadata.tokenEndpoint.substringAfter(proxy.origin)) { response ->
            HarnessSigner.withIdToken(response, other.resign(response["id_token"]!!.jsonPrimitive.content) { it })
        }

        assertEquals(IdTokenRejection.Signature, rejected(client))
        assertEquals("JWKS fetches during the rejected login", 1, transcript.matching("GET", jwksPath).size - fetchesBefore)
        assertNothingPersisted(client, metadata, since)
    }

    @Test
    fun `26C - alg none with an empty signature is rejected as Algorithm before any key is fetched`() = runTest {
        val client = client()
        val metadata = fault(client, alg = "none", kid = null) { it }
        val jwksPath = metadata.jwksUri!!.substringAfter(proxy.origin)
        val fetchesBefore = transcript.matching("GET", jwksPath).size

        assertEquals(IdTokenRejection.Algorithm, rejected(client))
        assertEquals(fetchesBefore, transcript.matching("GET", jwksPath).size)
        assertNothingPersisted(client, metadata)
    }

    @Test
    fun `26D - HS256 signed with the client id as key is rejected as Algorithm`() = runTest {
        val client = client()
        val metadata = fault(client, alg = "HS256", kid = null) { it }

        assertEquals(IdTokenRejection.Algorithm, rejected(client))
        assertNothingPersisted(client, metadata)
    }

    // ---- 27 ----

    @Test
    fun `27A - iss differing by a trailing slash is rejected as Issuer`() = runTest {
        val client = client()
        val metadata = fault(client) { it.with("iss" to JsonPrimitive(it["iss"]!!.jsonPrimitive.content + "/")) }

        assertEquals(IdTokenRejection.Issuer, rejected(client))
        assertNothingPersisted(client, metadata)
    }

    @Test
    fun `27B - aud equal to another client id is rejected as Audience`() = runTest {
        val client = client()
        val metadata = fault(client) { it.with("aud" to JsonPrimitive("some-other-client")) }

        assertEquals(IdTokenRejection.Audience, rejected(client))
        assertNothingPersisted(client, metadata)
    }

    @Test
    fun `27C - a two-element aud without azp is rejected as Audience`() = runTest {
        val client = client()
        val metadata = fault(client) {
            it.with("aud" to JsonArray(listOf(JsonPrimitive(Provider.CLIENT_ID), JsonPrimitive("some-other-client")))).without("azp")
        }

        assertEquals(IdTokenRejection.Audience, rejected(client))
        assertNothingPersisted(client, metadata)
    }

    @Test
    fun `27D - exp in the past by the server's Date header beyond the tolerance is rejected as Expired`() = runTest {
        val client = client()
        val now = Instant.now()
        val metadata = fault(client) { it.with("exp" to JsonPrimitive(now.epochSecond - 120)) }
        proxy.addHeaders(metadata.tokenEndpoint.substringAfter(proxy.origin), headersOf("Date", httpDate(now)))

        assertEquals(IdTokenRejection.Expired, rejected(client))
        assertNothingPersisted(client, metadata)
    }

    @Test
    fun `27D - a token live by the server's Date header is accepted although the device clock would expire it`() = runTest {
        val client = client()
        val serverNow = Instant.now().minusSeconds(600)
        val metadata = fault(client) {
            it.with(
                "iat" to JsonPrimitive(serverNow.epochSecond),
                "auth_time" to JsonPrimitive(serverNow.epochSecond),
                "exp" to JsonPrimitive(serverNow.epochSecond + 60),
            )
        }
        proxy.addHeaders(metadata.tokenEndpoint.substringAfter(proxy.origin), headersOf("Date", httpDate(serverNow)))

        client.login()

        assertEquals(SessionState.Authenticated, client.state())
        assertEquals(serverNow.epochSecond + 60, client.claims?.expiresAt?.epochSecond)
    }

    @Test
    fun `27E - a missing iat is rejected as IssuedAt`() = runTest {
        val client = client()
        val metadata = fault(client) { it.without("iat") }

        assertEquals(IdTokenRejection.IssuedAt, rejected(client))
        assertNothingPersisted(client, metadata)
    }

    @Test
    fun `27F - auth_time older than the max_age requested is rejected as AuthTime`() = runTest {
        val client = client()
        val metadata = fault(client) { it.with("auth_time" to JsonPrimitive(Instant.now().epochSecond - 3600)) }

        assertEquals(IdTokenRejection.AuthTime, rejected(client, LoginOptions(maxAge = 60)))
        assertNothingPersisted(client, metadata)
    }

    private fun httpDate(instant: Instant): String =
        DateTimeFormatter.RFC_1123_DATE_TIME.format(instant.atOffset(ZoneOffset.UTC))
}
