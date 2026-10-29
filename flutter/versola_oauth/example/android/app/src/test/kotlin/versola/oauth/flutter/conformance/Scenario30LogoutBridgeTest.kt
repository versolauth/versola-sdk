package versola.oauth.flutter.conformance

import mockwebserver3.MockResponse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import versola.oauth.conformance.HarnessSigner.Companion.without
import versola.oauth.conformance.Provider
import versola.oauth.conformance.Transcript
import versola.oauth.flutter.ErrorCategoryMessage
import versola.oauth.flutter.SessionStateMessage

/**
 * `30-logout-without-end-session` through the bridge: sign-out revokes, wipes, and says what the
 * server did, in `LogoutOutcomeMessage`. Source: `Scenario30LogoutTest`.
 */
class Scenario30LogoutBridgeTest : BridgeConformance() {

    private val discoveryPath = "/.well-known/openid-configuration"

    private fun assertWiped(bridge: Bridge) {
        assertEquals(SessionStateMessage.UNAUTHENTICATED, bridge.dart.sessionState())
        assertNull(bridge.dart.claims())
        assertEquals(ErrorCategoryMessage.REAUTHENTICATE, bridge.dart.accessToken().failure().category)
    }

    private fun assertRevocationRequest(entry: Transcript.Entry) {
        assertTrue(entry.form.containsKey("token"))
        assertEquals("refresh_token", entry.form["token_type_hint"])
        assertEquals(Provider.CLIENT_ID, entry.form["client_id"])
        assertNoSecretOnTheWire(entry)
    }

    @Test
    fun `without an end_session_endpoint logout revokes, opens no browser and reports the session not ended`() {
        proxy.rewriteJson(discoveryPath) { it.without("end_session_endpoint") }
        val bridge = bridge()
        bridge.dart.login().assertOk()
        val metadata = bridge.observe("discovery") { metadata() }

        val outcome = bridge.dart.logout()

        assertEquals(1, browser.opened.size)
        assertFalse(outcome.sessionEnded)
        assertTrue(outcome.tokenRevoked)
        assertRevocationRequest(theRequest("POST", metadata.revocationEndpoint!!.substringAfter(proxy.origin)))
        assertWiped(bridge)
    }

    @Test
    fun `a revocation endpoint answering 503 leaves tokenRevoked false, within the retry budget, and still wipes`() {
        proxy.rewriteJson(discoveryPath) { it.without("end_session_endpoint") }
        val bridge = bridge()
        bridge.dart.login().assertOk()
        val metadata = bridge.observe("discovery") { metadata() }
        val revocationPath = metadata.revocationEndpoint!!.substringAfter(proxy.origin)
        proxy.intercept = { request ->
            if (request.url.encodedPath.endsWith(revocationPath)) MockResponse.Builder().code(503).build() else null
        }

        val outcome = bridge.dart.logout()

        assertFalse(outcome.sessionEnded)
        assertFalse(outcome.tokenRevoked)
        val attempts = transcript.matching("POST", revocationPath)
        assertTrue("revocation attempts: ${attempts.size}", attempts.isNotEmpty())
        // The default policy: the configuration message carries no retry policy, so the bridge must not have invented one.
        assertTrue("revocation attempts: ${attempts.size}", attempts.size <= bridge.native.configuration.retryPolicy.maxAttemptsPerOrigin)
        attempts.forEach(::assertRevocationRequest)
        assertWiped(bridge)
    }

    @Test
    fun `the user dismissing the end-session browser leaves sessionEnded false and still wipes`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()
        val metadata = bridge.observe("discovery") { metadata() }
        assumeTrue("the provider advertises no end_session_endpoint", metadata.endSessionEndpoint != null)
        browser.dismissNext = true

        val outcome = bridge.dart.logout()

        assertEquals(2, browser.opened.size)
        assertTrue(browser.opened.last().startsWith(metadata.endSessionEndpoint!! + "?"))
        assertFalse(outcome.sessionEnded)
        assertTrue(outcome.tokenRevoked)
        assertWiped(bridge)
    }
}
