package versola.oauth.conformance

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import versola.oauth.core.IdTokenRejection
import versola.oauth.core.SessionState
import versola.oauth.core.VersolaError

/**
 * `37-refresh-id-token-rejected-keeps-rotation`: a refresh whose ID token is refused still keeps
 * the refresh token the provider rotated to, because the provider spent the old one the moment it
 * answered. The proxy flips the signature of the id_token in the refresh answer; the next, clean
 * refresh must present what the first was answered with.
 *
 * A provider that does not rotate passes without proving the point (the scenario says so); one
 * that does (Hydra, and Keycloak with `revokeRefreshToken`, as the CI realm sets it) is what
 * fails an SDK that dropped the rotation, with `invalid_grant`.
 */
class Scenario37RefreshIdTokenRejectedTest : ProviderConformance() {

    @Test
    fun `37 - a refresh whose ID token is rejected keeps the refresh token the provider rotated to`() = runTest {
        val client = client()
        client.login()
        val claimsBefore = checkNotNull(client.claims)
        val tokenPath = client.metadata().tokenEndpoint.substringAfter(proxy.origin)
        proxy.rewriteJson(tokenPath) { response ->
            val idToken = response["id_token"]?.jsonPrimitive?.content ?: return@rewriteJson response
            val parts = idToken.split('.')
            val flipped = java.util.Base64.getUrlDecoder().decode(parts[2]).also { it[0] = (it[0].toInt() xor 0x55).toByte() }
            HarnessSigner.withIdToken(response, "${parts[0]}.${parts[1]}.${HarnessSigner.b64(flipped)}")
        }
        val since = transcript.entries.size

        val error = failsWith<VersolaError.Configuration> { runBlocking { client.refresh() } }

        assertEquals(IdTokenRejection.Signature, (error.detail as VersolaError.Configuration.Detail.IdTokenRejected).reason)
        val first = transcript.entries.drop(since).single { it.method == "POST" && it.path.endsWith(tokenPath) }
        assertEquals("refresh_token", first.form["grant_type"])
        val rotatedTo = first.responseJson?.get("refresh_token")?.jsonPrimitive?.content
        assertEquals(SessionState.Authenticated, client.state())
        assertSame("the claims held before the refusal stand", claimsBefore, client.claims)

        proxy.clearRewrites()
        client.refresh()

        val second = transcript.entries.drop(since).filter { it.method == "POST" && it.path.endsWith(tokenPath) }[1]
        if (rotatedTo != null && rotatedTo != first.form["refresh_token"]) {
            // The provider rotated: the second refresh spent the new token, not the one it replaced.
            assertEquals(rotatedTo, second.form["refresh_token"])
            assertNotEquals(first.form["refresh_token"], second.form["refresh_token"])
        }
        assertEquals(SessionState.Authenticated, client.state())
        assertTrue("the second refresh succeeded", second.status in 200..299)
        assertEquals("one token request each, nothing retried", 2, transcript.entries.drop(since).count { it.method == "POST" && it.path.endsWith(tokenPath) })
    }
}
