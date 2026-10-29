package versola.oauth.conformance

import kotlin.time.Duration.Companion.minutes
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.jsonObject
import okhttp3.Request
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import versola.oauth.core.SessionState
import versola.oauth.core.VersolaError

/**
 * `31-session-without-refresh-token`: a client the provider issues no refresh token for
 * (`conformance-app-norefresh`, ten-second access tokens). The scenario's clock step is real
 * time here: the device clock cannot be moved from a JVM test, so the realm issues tokens
 * short enough to expire within the test, and the wait is bounded, not fixed.
 *
 * Whichever path observes the expiry first (`accessToken()` or the authenticated client) gets
 * `SessionExpired`; the session is wiped by then, so a later ask in `Unauthenticated` is
 * `Reauthenticate` too, with `GrantRejected` (nothing to refresh with). The scenario's "the
 * same Reauthenticate" is held to the category in the second test and to the reason in the first.
 */
class Scenario31SessionWithoutRefreshTokenTest : ProviderConformance() {

    @Test
    fun `the session ends at access-token expiry with Reauthenticate SessionExpired and no token request`() = runTest(timeout = 2.minutes) {
        val client = client(configuration(clientId = Provider.NO_REFRESH_CLIENT_ID))
        client.login()
        val metadata = client.metadata()
        val tokenPath = metadata.tokenEndpoint.substringAfter(proxy.origin)

        assertEquals(SessionState.Authenticated, client.state())
        val issued = theRequest("POST", tokenPath).responseJson!!
        assertNull("the realm must issue no refresh token to this client", issued["refresh_token"])
        assertEquals(200, client.call(Request.Builder().url(resource.url("/api")).build()).code)
        assertEquals(logger.warnings.toString(), 1, logger.warnings.count { it.contains("issued no refresh token") })

        // Past the token's expiry (its lifetime minus the refresh skew): the next ask ends the session.
        val expiry = failsWith<VersolaError.Reauthenticate> {
            runBlocking {
                repeat(40) {
                    client.accessToken()
                    withContext(Dispatchers.Default) { delay(1000) }
                }
            }
        }
        assertEquals(VersolaError.Reauthenticate.Reason.SessionExpired, expiry.reason)
        assertEquals("token requests", 1, transcript.matching("POST", tokenPath).size)
        assertEquals(SessionState.Unauthenticated, client.state())
        assertNull(client.claims)

        // The authenticated client makes no refresh attempt and surfaces Reauthenticate too.
        val call = failsWith<VersolaError.Reauthenticate> {
            runBlocking { client.call(Request.Builder().url(resource.url("/api")).build()) }
        }
        assertEquals(VersolaError.Reauthenticate.Reason.GrantRejected, call.reason)
        assertEquals(1, transcript.matching("POST", tokenPath).size)
        assertEquals(1, browser.opened.size)
        assertFalse(transcript.entries.any { it.url.startsWith(metadata.authorizationEndpoint) })
    }

    @Test
    fun `the authenticated client observing the expiry first surfaces SessionExpired without a refresh attempt`() = runTest(timeout = 2.minutes) {
        val client = client(configuration(clientId = Provider.NO_REFRESH_CLIENT_ID))
        client.login()
        val tokenPath = client.metadata().tokenEndpoint.substringAfter(proxy.origin)
        val request = Request.Builder().url(resource.url("/api")).build()

        val expiry = failsWith<VersolaError.Reauthenticate> {
            runBlocking {
                repeat(40) {
                    client.call(request).close()
                    withContext(Dispatchers.Default) { delay(1000) }
                }
            }
        }

        assertEquals(VersolaError.Reauthenticate.Reason.SessionExpired, expiry.reason)
        assertEquals(1, transcript.matching("POST", tokenPath).size)
        assertEquals(SessionState.Unauthenticated, client.state())
        assertNull(client.claims)
        assertEquals(1, browser.opened.size)
    }
}
