package versola.oauth.flutter.conformance

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import versola.oauth.conformance.Provider
import versola.oauth.flutter.AccessTokenFailure
import versola.oauth.flutter.ErrorCategoryMessage
import versola.oauth.flutter.ErrorMessage
import versola.oauth.flutter.SessionStateMessage
import versola.oauth.flutter.UserInfoFailure

/**
 * `31-session-without-refresh-token` through the bridge: a client the provider issues no refresh
 * token for (`conformance-app-norefresh`, ten-second access tokens). The scenario's clock step is
 * real time here, as in the native driver: the realm issues tokens short enough to expire within
 * the test, and the wait is bounded, not fixed (`Scenario31SessionWithoutRefreshTokenTest`).
 *
 * Flutter has no authenticated client to observe the expiry through, so the two paths that ask
 * the SDK for a live access token are the two that take its place: `accessToken()` in the first
 * test, `userInfo()` (which needs a live token as well) in the second.
 */
class Scenario31SessionWithoutRefreshTokenBridgeTest : BridgeConformance() {

    /** Asks until the SDK answers with an error (the session expired); at most ~40 s, a second apart. */
    private fun expiryObservedBy(ask: () -> ErrorMessage?): ErrorMessage {
        repeat(40) {
            ask()?.let { return it }
            Thread.sleep(1000)
        }
        throw AssertionError("the session did not end within the access token's lifetime")
    }

    @Test
    fun `the session ends at access-token expiry with Reauthenticate SessionExpired and no token request`() {
        val bridge = bridge(clientId = Provider.NO_REFRESH_CLIENT_ID, scopes = provider.noRefreshScopes)
        bridge.dart.login().assertOk()
        val metadata = bridge.observe("discovery") { metadata() }
        val tokenPath = metadata.tokenEndpoint.substringAfter(proxy.origin)

        assertEquals(SessionStateMessage.AUTHENTICATED, bridge.dart.sessionState())
        val issued = theRequest("POST", tokenPath).responseJson!!
        assertNull("the realm must issue no refresh token to this client", issued["refresh_token"])
        assertTokenIsUsableAtTheResource(bridge.dart.accessToken().token(), checkNotNull(bridge.dart.claims()).subject)
        assertEquals(logger.warnings.toString(), 1, logger.warnings.count { it.contains("issued no refresh token") })

        // Past the token's expiry (its lifetime minus the refresh skew): the next ask ends the session.
        val expiry = expiryObservedBy { (bridge.dart.accessToken() as? AccessTokenFailure)?.error }
        assertError(expiry, ErrorCategoryMessage.REAUTHENTICATE, "sessionExpired")
        assertEquals("token requests", 1, transcript.matching("POST", tokenPath).size)
        assertEquals(SessionStateMessage.UNAUTHENTICATED, bridge.dart.sessionState())
        assertNull(bridge.dart.claims())

        // A later ask makes no refresh attempt and surfaces Reauthenticate too: nothing to refresh with.
        val later = bridge.dart.accessToken().failure()
        assertError(later, ErrorCategoryMessage.REAUTHENTICATE, "grantRejected")
        assertEquals(1, transcript.matching("POST", tokenPath).size)
        assertEquals(1, browser.opened.size)
        assertFalse(transcript.entries.any { it.url.startsWith(metadata.authorizationEndpoint) })
    }

    @Test
    fun `bridge - the session ending observed through userInfo() first surfaces SessionExpired without a refresh attempt`() {
        val bridge = bridge(clientId = Provider.NO_REFRESH_CLIENT_ID, scopes = provider.noRefreshScopes)
        bridge.dart.login().assertOk()
        val tokenPath = bridge.observe("discovery") { metadata() }.tokenEndpoint.substringAfter(proxy.origin)

        val expiry = expiryObservedBy { (bridge.dart.userInfo() as? UserInfoFailure)?.error }

        assertError(expiry, ErrorCategoryMessage.REAUTHENTICATE, "sessionExpired")
        assertEquals(1, transcript.matching("POST", tokenPath).size)
        assertEquals(SessionStateMessage.UNAUTHENTICATED, bridge.dart.sessionState())
        assertNull(bridge.dart.claims())
        assertEquals(1, browser.opened.size)
    }
}
