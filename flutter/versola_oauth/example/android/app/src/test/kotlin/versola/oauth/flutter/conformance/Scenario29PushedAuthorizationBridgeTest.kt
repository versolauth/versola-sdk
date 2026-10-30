package versola.oauth.flutter.conformance

import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import versola.oauth.conformance.HarnessSigner.Companion.with
import versola.oauth.conformance.HarnessSigner.Companion.without
import versola.oauth.conformance.Provider
import versola.oauth.core.PushedAuthorization
import versola.oauth.flutter.ErrorCategoryMessage
import versola.oauth.flutter.SessionStateMessage

/**
 * `29-pushed-authorization-request` through the bridge: PAR when advertised, required when the
 * provider says so, and the policy (`PushedAuthorizationMessage`) honoured as the native facade
 * honours it. Source: `Scenario29PushedAuthorizationTest`.
 */
class Scenario29PushedAuthorizationBridgeTest : BridgeConformance() {

    private val discoveryPath = "/.well-known/openid-configuration"

    @Test
    fun `login pushes the request and opens the browser with client_id and request_uri only`() {
        val bridge = bridge()
        val metadata = bridge.observe("discovery") { metadata() }
        assumeTrue("the provider advertises no PAR endpoint", metadata.pushedAuthorizationRequestEndpoint != null)
        // The moment the browser opens: the state (Authorizing only once the pending request is
        // persisted), how much of the transcript preceded it, and when. The state is asked through
        // the bridge, from the browser leg's thread.
        var stateAtOpen: SessionStateMessage? = null
        var transcriptAtOpen = -1
        var openedAt = 0L
        browser.onOpen = {
            stateAtOpen = bridge.dart.sessionState()
            transcriptAtOpen = transcript.entries.size
            openedAt = System.currentTimeMillis()
        }

        bridge.dart.login().assertOk()

        val pushed = theRequest("POST", metadata.pushedAuthorizationRequestEndpoint!!.substringAfter(proxy.origin))
        // Persisted after the PAR response and before the browser opened.
        assertEquals(SessionStateMessage.AUTHORIZING, stateAtOpen)
        assertTrue(transcript.entries.indexOf(pushed) < transcriptAtOpen)
        // The request_uri was used once, within the lifetime the PAR response gave it.
        val expiresIn = pushed.responseJson!!["expires_in"]!!.toString().trim('"').toLong()
        assertTrue("opened ${openedAt - pushed.at} ms after a PAR response valid for $expiresIn s", openedAt - pushed.at < expiresIn * 1000)
        assertEquals(1, browser.opened.count { it.contains("request_uri=") })
        assertTrue(pushed.form.containsKey("code_challenge"))
        assertTrue(pushed.form.containsKey("state"))
        assertTrue(pushed.form.containsKey("nonce"))
        assertEquals(Provider.REDIRECT_URI, pushed.form["redirect_uri"])
        assertNoSecretOnTheWire(pushed)
        val opened = browser.opened.single()
        assertTrue(opened.startsWith(metadata.authorizationEndpoint + "?"))
        assertEquals(setOf("client_id", "request_uri"), opened.queryMap().keys)
        assertEquals(SessionStateMessage.AUTHENTICATED, bridge.dart.sessionState())
    }

    @Test
    fun `a PAR rejection surfaces as AuthorizationRejected before the browser opens`() {
        // An unregistered redirect URI: the provider's PAR endpoint refuses it with invalid_request.
        val bridge = bridge(redirectUri = "https://conformance.example.com/not-registered")
        assumeTrue("the provider advertises no PAR endpoint", bridge.observe("discovery") { metadata() }.pushedAuthorizationRequestEndpoint != null)

        val error = bridge.dart.login().failure()

        assertError(error, ErrorCategoryMessage.CONFIGURATION, "authorizationRejected")
        assertEquals("invalid_request", error.code)
        assertTrue(browser.opened.isEmpty())
        // No pending request persisted: the state is not Authorizing.
        assertEquals(SessionStateMessage.UNAUTHENTICATED, bridge.dart.sessionState())
    }

    @Test
    fun `a provider that requires PAR under a policy of Never is ProviderUnsupported naming par`() {
        proxy.rewriteJson(discoveryPath) { it.with("require_pushed_authorization_requests" to JsonPrimitive(true)) }
        val bridge = bridge(pushedAuthorization = PushedAuthorization.Never)
        val metadata = bridge.observe("discovery") { metadata() }

        val error = bridge.dart.login().failure()

        assertError(error, ErrorCategoryMessage.CONFIGURATION, "providerUnsupported")
        assertEquals("par", error.capability)
        assertTrue(browser.opened.isEmpty())
        assertTrue(transcript.entries.none { it.url.startsWith(metadata.authorizationEndpoint) })
        // Nothing was pushed either, where there is an endpoint to push to.
        metadata.pushedAuthorizationRequestEndpoint?.let { assertTrue(transcript.matching("POST", it.substringAfter(proxy.origin)).isEmpty()) }
    }

    @Test
    fun `a provider without a PAR endpoint under a policy of Required is ProviderUnsupported naming par`() {
        proxy.rewriteJson(discoveryPath) { it.without("pushed_authorization_request_endpoint") }
        val bridge = bridge(pushedAuthorization = PushedAuthorization.Required)

        val error = bridge.dart.login().failure()

        assertError(error, ErrorCategoryMessage.CONFIGURATION, "providerUnsupported")
        assertEquals("par", error.capability)
        assertTrue(browser.opened.isEmpty())
    }
}
