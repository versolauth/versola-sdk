package versola.oauth.flutter.conformance

import kotlin.time.Duration.Companion.seconds
import mockwebserver3.MockResponse
import mockwebserver3.RecordedRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import versola.oauth.OAuthClient
import versola.oauth.core.RetryPolicy
import versola.oauth.flutter.ErrorCategoryMessage
import versola.oauth.flutter.ErrorMessage
import versola.oauth.flutter.SessionStateMessage

/**
 * `34-server-error-per-operation`, `35-retry-after` and `36-retry-after-cooldown` through the
 * bridge. Source: `Scenario34To36ServerErrorsTest`, case for case; the proxy answers one operation
 * by method and path (`respond-with-status`) and forwards the rest, and what Dart reads is the
 * typed `server` cause on the wire (`ErrorMessage` kind `server`: `status`, `retryAfterMillis`,
 * `attempts`), which `errorFromMessage` rebuilds as `RecoverableError(RecoverableCause.server, ...)`
 * (`mapping_test.dart` proves that half; this file proves the native half of the wire).
 *
 * Request counts are the SDK's own transcript, as in the native test. The bridge carries the retry
 * policy (`RetryPolicyMessage`), which the cooldown-expiry case uses.
 *
 * **Elsewhere:** the authenticated client passing a 503 through (scenario 34's last case) is
 * `Scenario32ProtectedOriginsBridgeTest`'s 503 test, which sends the request through the bridge's
 * `httpRequest` (Flutter's `OAuthClient.httpClient()`); `Scenario34To36ServerErrorsTest` proves it
 * for the native facades.
 */
class Scenario34To36ServerErrorsBridgeTest : BridgeConformance() {

    private val discoveryPath = "/.well-known/openid-configuration"

    /** `respond-with-status`: answers matching requests, for [times] of them (all when null), and forwards the rest. */
    private fun respondWith(
        status: Int,
        headers: Map<String, String> = emptyMap(),
        times: Int? = null,
        matches: (RecordedRequest) -> Boolean,
    ) {
        var left = times
        proxy.intercept = { request ->
            if (!matches(request) || (left != null && left!! <= 0)) {
                null
            } else {
                left = left?.minus(1)
                MockResponse.Builder().code(status).apply { headers.forEach { (n, v) -> setHeader(n, v) } }.build()
            }
        }
    }

    private fun path(suffix: String): (RecordedRequest) -> Boolean = { it.url.encodedPath.endsWith(suffix) }

    private fun Bridge.tokenPath(): String = observe("discovery") { metadata() }.tokenEndpoint.substringAfter(proxy.origin)

    private fun Bridge.refreshGrant(): (RecordedRequest) -> Boolean {
        val token = tokenPath()
        return { it.url.encodedPath.endsWith(token) && it.body?.utf8()?.contains("grant_type=refresh_token") == true }
    }

    private fun Bridge.refreshRequests() =
        transcript.matching("POST", tokenPath()).filter { it.form["grant_type"] == "refresh_token" }

    /** What Dart receives for a `server` cause: category `recoverable`, kind `server`, the status, and what the cooldown or the budget counted. */
    private fun server(error: ErrorMessage): ErrorMessage {
        assertError(error, ErrorCategoryMessage.RECOVERABLE, "server")
        return error
    }

    private fun fresh(retryPolicy: RetryPolicy = RetryPolicy.Default): Bridge {
        OAuthClient.forgetAll()
        return bridge(retryPolicy = retryPolicy)
    }

    private val httpDate = java.text.SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss 'GMT'", java.util.Locale.US)
        .apply { timeZone = java.util.TimeZone.getTimeZone("GMT") }

    // ---- 34 ---------------------------------------------------------------------------------

    @Test
    fun `34 a refresh is repeated three times when the provider did not take it up, and made once when it may have`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()
        // The generic facade sends no Idempotency-Key, so only what provably was not processed is
        // repeated (429, 503); a 500, 502 or 504 may have come after the provider rotated the token.
        for ((status, expected) in listOf(503 to 3, 429 to 3, 500 to 1, 502 to 1, 504 to 1)) {
            val before = bridge.refreshRequests().size
            respondWith(status, matches = bridge.refreshGrant())

            val error = server(bridge.dart.refresh().failure())

            assertEquals(status.toLong(), error.status)
            assertEquals("$status", expected.toLong(), error.attempts)
            assertNull(error.retryAfterMillis)
            assertEquals("$status", expected, bridge.refreshRequests().size - before)
            assertEquals(SessionStateMessage.AUTHENTICATED, bridge.dart.sessionState())
        }
        // The grant survived all of it: once the provider answers, the same session refreshes.
        proxy.clearRewrites()
        bridge.dart.refresh().assertOk()
        assertEquals(SessionStateMessage.AUTHENTICATED, bridge.dart.sessionState())
    }

    @Test
    fun `34 a 501 is surfaced after one request with no delay`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()
        val before = bridge.refreshRequests().size
        respondWith(501, matches = bridge.refreshGrant())

        val error = server(bridge.dart.refresh().failure())

        assertEquals(501L, error.status)
        assertEquals(1, bridge.refreshRequests().size - before)
        assertEquals(SessionStateMessage.AUTHENTICATED, bridge.dart.sessionState())
    }

    @Test
    fun `34 discovery answered 500, 503 or 429 is repeated three times`() {
        for (status in listOf(500, 503, 429)) {
            val bridge = fresh()
            val before = transcript.matching("GET", discoveryPath).size
            respondWith(status, matches = path(discoveryPath))

            // login() is what makes the SDK discover; nothing else the bridge carries does it first.
            val error = server(bridge.dart.login().failure())

            assertEquals(status.toLong(), error.status)
            assertEquals("$status", 3L, error.attempts)
            assertEquals("$status", 3, transcript.matching("GET", discoveryPath).size - before)
            proxy.clearRewrites()
        }
    }

    @Test
    fun `34 a pushed authorization request answered 503 is repeated three times and the browser never opens`() {
        val bridge = bridge()
        val par = bridge.observe("discovery") { metadata() }.pushedAuthorizationRequestEndpoint
        assumeTrue("the provider advertises no PAR endpoint", par != null)
        val parPath = par!!.substringAfter(proxy.origin)
        respondWith(503, matches = path(parPath))

        val error = server(bridge.dart.login().failure())

        assertEquals(503L, error.status)
        assertEquals(3L, error.attempts)
        assertEquals(3, transcript.matching("POST", parPath).size)
        assertTrue(browser.opened.isEmpty())
        assertEquals(SessionStateMessage.UNAUTHENTICATED, bridge.dart.sessionState())
    }

    @Test
    fun `34 UserInfo answered 503 is repeated three times`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()
        val userinfo = bridge.observe("discovery") { metadata() }.userinfoEndpoint
        assumeTrue("the provider advertises no userinfo_endpoint", userinfo != null)
        val userinfoPath = userinfo!!.substringAfter(proxy.origin)
        respondWith(503, matches = path(userinfoPath))

        val error = server(bridge.dart.userInfo().failure())

        assertEquals(503L, error.status)
        assertEquals(3L, error.attempts)
        assertEquals(3, transcript.matching("GET", userinfoPath).size)
    }

    @Test
    fun `34 a code exchange answered 503 is made once, the login fails, and the next login starts from the browser`() {
        val bridge = bridge()
        val token = bridge.tokenPath()
        respondWith(503, headers = mapOf("Retry-After" to "1"), times = 1) {
            it.url.encodedPath.endsWith(token) && it.body?.utf8()?.contains("grant_type=authorization_code") == true
        }

        val error = server(bridge.dart.login().failure())

        // A single-use code is never replayed, whatever the status and whatever the server asks.
        assertEquals(503L, error.status)
        assertEquals(1, transcript.matching("POST", token).size)
        assertEquals(SessionStateMessage.UNAUTHENTICATED, bridge.dart.sessionState())

        // The Retry-After of 1 s on that exchange holds the origin: the next login() is refused before
        // its browser opens, until it has passed.
        val refused = server(bridge.dart.login().failure())
        assertEquals(0L, refused.attempts)
        assertEquals(1, browser.opened.size)
        android.os.SystemClock.sleep(1_300)

        bridge.dart.login().assertOk()
        assertEquals(2, browser.opened.size)
        assertEquals(SessionStateMessage.AUTHENTICATED, bridge.dart.sessionState())
    }

    // ---- 35 ---------------------------------------------------------------------------------

    @Test
    fun `35 a 429 with Retry-After 2 is waited out before the second request`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()
        respondWith(429, headers = mapOf("Retry-After" to "2"), times = 1, matches = bridge.refreshGrant())

        bridge.dart.refresh().assertOk()

        val attempts = bridge.refreshRequests()
        assertEquals(2, attempts.size)
        val gap = attempts[1].at - attempts[0].at
        // Not the 500 ms backoff, and not past the two seconds plus its tenth of jitter.
        assertTrue("gap ${gap}ms", gap in 2_000..2_900)
        assertEquals(SessionStateMessage.AUTHENTICATED, bridge.dart.sessionState())
    }

    @Test
    fun `35 an HTTP-date Retry-After is measured against the response's Date`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()
        val now = System.currentTimeMillis()
        respondWith(
            503,
            headers = mapOf("Date" to httpDate.format(java.util.Date(now)), "Retry-After" to httpDate.format(java.util.Date(now + 3_000))),
            times = 1,
            matches = bridge.refreshGrant(),
        )

        bridge.dart.refresh().assertOk()

        val attempts = bridge.refreshRequests()
        assertEquals(2, attempts.size)
        val gap = attempts[1].at - attempts[0].at
        assertTrue("gap ${gap}ms", gap in 2_000..3_900)
    }

    @Test
    fun `35 an HTTP-date Retry-After is measured against the response's Date even when the device clock disagrees by an hour`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()
        // The provider's clock is an hour ahead of the device's: against the device clock the date
        // would be an hour away (a day-capped wait that does not fit the budget), against the
        // response's own Date it is three seconds.
        val serverNow = System.currentTimeMillis() + 3_600_000
        respondWith(
            503,
            headers = mapOf("Date" to httpDate.format(java.util.Date(serverNow)), "Retry-After" to httpDate.format(java.util.Date(serverNow + 3_000))),
            times = 1,
            matches = bridge.refreshGrant(),
        )

        bridge.dart.refresh().assertOk()

        val attempts = bridge.refreshRequests()
        assertEquals(2, attempts.size)
        val gap = attempts[1].at - attempts[0].at
        assertTrue("gap ${gap}ms", gap in 2_000..3_900)
    }

    @Test
    fun `35 a Retry-After past the budget, a day long, stops at once with the value`() {
        for ((header, expectedMillis) in listOf("30" to 30_000L, "86400" to 86_400_000L, "999999999" to 86_400_000L)) {
            val bridge = fresh()
            bridge.dart.login().assertOk()
            val before = bridge.refreshRequests().size
            respondWith(429, headers = mapOf("Retry-After" to header), matches = bridge.refreshGrant())

            val error = server(bridge.dart.refresh().failure())

            assertEquals(429L, error.status)
            assertEquals(header, expectedMillis, error.retryAfterMillis)
            assertEquals(header, 1L, error.attempts)
            // One request, no sleeping and no shortening of the wait.
            assertEquals(header, 1, bridge.refreshRequests().size - before)
            proxy.clearRewrites()
        }
    }

    @Test
    fun `35 a malformed Retry-After is ignored with ordinary backoff, three requests and no Configuration`() {
        for (junk in listOf("-1", "1.5", "soon", "")) {
            val bridge = fresh()
            bridge.dart.login().assertOk()
            val before = bridge.refreshRequests().size
            respondWith(503, headers = mapOf("Retry-After" to junk), matches = bridge.refreshGrant())

            val error = server(bridge.dart.refresh().failure())

            assertNull("'$junk'", error.retryAfterMillis)
            assertEquals("'$junk'", 3, bridge.refreshRequests().size - before)
            proxy.clearRewrites()
        }
    }

    @Test
    fun `35 a Retry-After on a 500 is ignored`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()
        respondWith(500, headers = mapOf("Retry-After" to "86400"), matches = bridge.refreshGrant())

        val error = server(bridge.dart.refresh().failure())

        // A 500 is not repeated by a facade with no Idempotency-Key, and its header is not read.
        assertNull(error.retryAfterMillis)
        assertEquals(1L, error.attempts)
    }

    @Test
    fun `35 a Retry-After on a 502 from UserInfo is ignored and the ordinary backoff applies`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()
        val userinfo = bridge.observe("discovery") { metadata() }.userinfoEndpoint
        assumeTrue("the provider advertises no userinfo_endpoint", userinfo != null)
        respondWith(502, headers = mapOf("Retry-After" to "86400"), matches = path(userinfo!!.substringAfter(proxy.origin)))

        val error = server(bridge.dart.userInfo().failure())

        assertNull(error.retryAfterMillis)
        assertEquals(3L, error.attempts)
    }

    // ---- 36 ---------------------------------------------------------------------------------

    @Test
    fun `36 after a Retry-After nothing is sent to the provider until it passes, and logout still wipes`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()
        respondWith(429, headers = mapOf("Retry-After" to "30"), matches = bridge.refreshGrant())
        val first = server(bridge.dart.refresh().failure())
        assertEquals(30_000L, first.retryAfterMillis)
        val sent = transcript.entries.size

        // Inside the window: every one of these fails at once, and none sends a request.
        for (error in listOf(bridge.dart.refresh().failure(), bridge.dart.userInfo().failure())) {
            val cause = server(error)
            assertEquals(429L, cause.status)
            assertEquals(0L, cause.attempts)
            assertTrue("left ${cause.retryAfterMillis}", cause.retryAfterMillis!! in 1..30_000)
        }
        // accessToken() serves the live token from memory: no request to make, so none refused. The
        // expired-token form, where it fails at once with attempts 0, is SessionCoordinatorTest's.
        bridge.dart.accessToken().token()
        assertEquals(sent, transcript.entries.size)
        assertEquals(SessionStateMessage.AUTHENTICATED, bridge.dart.sessionState())

        // The revocation is refused by the cooldown (same origin, nothing sent) and the local wipe
        // happens regardless.
        val outcome = bridge.dart.logout()
        assertEquals(false, outcome.tokenRevoked)
        assertEquals(SessionStateMessage.UNAUTHENTICATED, bridge.dart.sessionState())
        assertEquals(1, bridge.refreshRequests().size)
    }

    @Test
    fun `36 exhausting the budget on 503 without Retry-After starts no cooldown`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()
        respondWith(503, matches = bridge.refreshGrant())
        server(bridge.dart.refresh().failure())
        val afterFirst = bridge.refreshRequests().size

        server(bridge.dart.refresh().failure())

        // A second set of three: the SDK invents no provider policy; the retry loop above it is the app's.
        assertEquals(3, afterFirst)
        assertEquals(6, bridge.refreshRequests().size)
    }

    @Test
    fun `36 the cooldown ends when the Retry-After has passed, and the next refresh goes out`() {
        // A one-second budget makes a two-second Retry-After one that does not fit, so the SDK stops
        // and holds the origin; waiting it out in real time proves the cooldown's end without
        // touching the SDK's clock. The bridge carries the policy in `RetryPolicyMessage`.
        val bridge = bridge(retryPolicy = RetryPolicy(totalBudget = 1.seconds))
        bridge.dart.login().assertOk()
        respondWith(429, headers = mapOf("Retry-After" to "2"), matches = bridge.refreshGrant())
        val first = server(bridge.dart.refresh().failure())
        assertEquals(2_000L, first.retryAfterMillis)
        val sent = bridge.refreshRequests().size

        val refused = server(bridge.dart.refresh().failure())
        val userinfo = server(bridge.dart.userInfo().failure())

        for (error in listOf(refused, userinfo)) {
            assertEquals(0L, error.attempts)
            assertTrue(error.retryAfterMillis!! in 1..2_000)
        }
        assertEquals(sent, bridge.refreshRequests().size)

        proxy.clearRewrites()
        // Robolectric's SystemClock, the clock the cooldown runs on, advances by sleeping.
        android.os.SystemClock.sleep(2_300)
        bridge.dart.refresh().assertOk()

        assertEquals(sent + 1, bridge.refreshRequests().size)
        assertEquals(SessionStateMessage.AUTHENTICATED, bridge.dart.sessionState())
    }
}
