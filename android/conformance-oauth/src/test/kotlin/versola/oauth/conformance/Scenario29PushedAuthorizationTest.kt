package versola.oauth.conformance

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import versola.oauth.conformance.HarnessSigner.Companion.with
import versola.oauth.conformance.HarnessSigner.Companion.without
import versola.oauth.core.PushedAuthorization
import versola.oauth.core.SessionState
import versola.oauth.core.VersolaError

/** `29-pushed-authorization-request`: PAR when advertised, required when the provider says so. */
class Scenario29PushedAuthorizationTest : ProviderConformance() {

    private val discoveryPath = "/.well-known/openid-configuration"

    @Test
    fun `login pushes the request and opens the browser with client_id and request_uri only`() = runTest {
        val client = client()
        val metadata = client.metadata()
        assumeTrue("the provider advertises no PAR endpoint", metadata.pushedAuthorizationRequestEndpoint != null)
        // The moment the browser opens: the state (Authorizing only once the pending request
        // is persisted), how much of the transcript preceded it, and when.
        var stateAtOpen: SessionState? = null
        var transcriptAtOpen = -1
        var openedAt = 0L
        browser.onOpen = {
            stateAtOpen = kotlinx.coroutines.runBlocking { client.state() }
            transcriptAtOpen = transcript.entries.size
            openedAt = System.currentTimeMillis()
        }

        client.login()

        val pushed = theRequest("POST", metadata.pushedAuthorizationRequestEndpoint!!.substringAfter(proxy.origin))
        // Persisted after the PAR response and before the browser opened.
        assertEquals(SessionState.Authorizing, stateAtOpen)
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
        assertEquals(setOf("client_id", "request_uri"), opened.query().keys)
        assertEquals(SessionState.Authenticated, client.state())
    }

    @Test
    fun `a PAR rejection surfaces as AuthorizationRejected before the browser opens`() = runTest {
        // An unregistered redirect URI: the provider's PAR endpoint refuses it with invalid_request.
        val client = client(configuration(redirectUri = "https://conformance.example.com/not-registered"))
        assumeTrue("the provider advertises no PAR endpoint", client.metadata().pushedAuthorizationRequestEndpoint != null)

        val error = failsWith<VersolaError.Configuration> { runBlocking { client.login() } }

        val detail = error.detail as? VersolaError.Configuration.Detail.AuthorizationRejected
            ?: throw AssertionError("expected AuthorizationRejected, got ${error.detail}")
        assertEquals("invalid_request", detail.code)
        assertTrue(browser.opened.isEmpty())
        // No pending request persisted: the state is not Authorizing.
        assertEquals(SessionState.Unauthenticated, client.state())
    }

    @Test
    fun `a provider that requires PAR under a policy of Never is ProviderUnsupported naming par`() = runTest {
        proxy.rewriteJson(discoveryPath) { it.with("require_pushed_authorization_requests" to JsonPrimitive(true)) }
        val client = client(configuration(pushedAuthorization = PushedAuthorization.Never))
        val metadata = client.metadata()

        val error = failsWith<VersolaError.Configuration> { runBlocking { client.login() } }

        assertEquals(VersolaError.Configuration.Detail.ProviderUnsupported("par"), error.detail)
        assertTrue(browser.opened.isEmpty())
        assertTrue(transcript.entries.none { it.url.startsWith(metadata.authorizationEndpoint) })
        assertTrue(transcript.matching("POST", metadata.pushedAuthorizationRequestEndpoint!!.substringAfter(proxy.origin)).isEmpty())
    }

    @Test
    fun `a provider without a PAR endpoint under a policy of Required is ProviderUnsupported naming par`() = runTest {
        proxy.rewriteJson(discoveryPath) { it.without("pushed_authorization_request_endpoint") }
        val client = client(configuration(pushedAuthorization = PushedAuthorization.Required))

        val error = failsWith<VersolaError.Configuration> { runBlocking { client.login() } }

        assertEquals(VersolaError.Configuration.Detail.ProviderUnsupported("par"), error.detail)
        assertTrue(browser.opened.isEmpty())
    }
}
