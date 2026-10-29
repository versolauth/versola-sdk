package versola.oauth.conformance

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import mockwebserver3.MockResponse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import versola.oauth.OAuthClient
import versola.oauth.conformance.HarnessSigner.Companion.without
import versola.oauth.core.SessionState
import versola.oauth.core.VersolaError

/** `30-logout-without-end-session`: sign-out revokes, wipes, and says what the server did. */
class Scenario30LogoutTest : ProviderConformance() {

    private val discoveryPath = "/.well-known/openid-configuration"

    private suspend fun assertWiped(client: OAuthClient) {
        assertEquals(SessionState.Unauthenticated, client.state())
        assertNull(client.claims)
        failsWith<VersolaError.Reauthenticate> { runBlocking { client.accessToken() } }
    }

    private fun assertRevocationRequest(entry: Transcript.Entry) {
        assertTrue(entry.form.containsKey("token"))
        assertEquals("refresh_token", entry.form["token_type_hint"])
        assertEquals(Provider.CLIENT_ID, entry.form["client_id"])
        assertNoSecretOnTheWire(entry)
    }

    @Test
    fun `without an end_session_endpoint logout revokes, opens no browser and reports the session not ended`() = runTest {
        proxy.rewriteJson(discoveryPath) { it.without("end_session_endpoint") }
        val client = client()
        client.login()
        val metadata = client.metadata()

        val outcome = client.logout()

        assertEquals(1, browser.opened.size)
        assertFalse(outcome.sessionEnded)
        assertTrue(outcome.tokenRevoked)
        assertRevocationRequest(theRequest("POST", metadata.revocationEndpoint!!.substringAfter(proxy.origin)))
        assertWiped(client)
    }

    @Test
    fun `a revocation endpoint answering 503 leaves tokenRevoked false, within the retry budget, and still wipes`() = runTest {
        proxy.rewriteJson(discoveryPath) { it.without("end_session_endpoint") }
        val client = client()
        client.login()
        val metadata = client.metadata()
        val revocationPath = metadata.revocationEndpoint!!.substringAfter(proxy.origin)
        proxy.intercept = { request ->
            if (request.url.encodedPath.endsWith(revocationPath)) MockResponse.Builder().code(503).build() else null
        }

        val outcome = client.logout()

        assertFalse(outcome.sessionEnded)
        assertFalse(outcome.tokenRevoked)
        val attempts = transcript.matching("POST", revocationPath)
        assertTrue("revocation attempts: ${attempts.size}", attempts.isNotEmpty())
        assertTrue("revocation attempts: ${attempts.size}", attempts.size <= client.configuration.retryPolicy.maxAttemptsPerOrigin)
        attempts.forEach(::assertRevocationRequest)
        assertWiped(client)
    }

    @Test
    fun `the user dismissing the end-session browser leaves sessionEnded false and still wipes`() = runTest {
        val client = client()
        client.login()
        val metadata = client.metadata()
        org.junit.Assume.assumeTrue("the provider advertises no end_session_endpoint", metadata.endSessionEndpoint != null)
        browser.dismissNext = true

        val outcome = client.logout()

        assertEquals(2, browser.opened.size)
        assertTrue(browser.opened.last().startsWith(metadata.endSessionEndpoint!! + "?"))
        assertFalse(outcome.sessionEnded)
        assertTrue(outcome.tokenRevoked)
        assertWiped(client)
    }
}
