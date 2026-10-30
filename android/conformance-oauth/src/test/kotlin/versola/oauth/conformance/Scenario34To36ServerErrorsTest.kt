package versola.oauth.conformance

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import mockwebserver3.MockResponse
import mockwebserver3.RecordedRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import versola.oauth.OAuthClient
import versola.oauth.core.RetryPolicy
import versola.oauth.core.SessionState
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaError.Recoverable.Cause

/**
 * `34-server-error-per-operation`, `35-retry-after` and `36-retry-after-cooldown`, through the
 * generic facade against the staged provider, with the proxy answering one operation by method and
 * path (`respond-with-status`) while everything else is forwarded.
 *
 * Everything the scenarios assert for the generic facade is here, in real time against the
 * provider: the 501 case, the authenticated client passing a 503 through, the HTTP-date against the
 * response's own `Date` with the device clock an hour off, and the end of a cooldown (a one-second
 * budget makes a two-second Retry-After one that does not fit, so no clock has to be injected).
 */
class Scenario34To36ServerErrorsTest : ProviderConformance() {

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

    private fun tokenPath(client: OAuthClient) = runBlocking { client.metadata() }.tokenEndpoint.substringAfter(proxy.origin)

    private fun refreshGrant(client: OAuthClient): (RecordedRequest) -> Boolean {
        val token = tokenPath(client)
        return { it.url.encodedPath.endsWith(token) && it.body?.utf8()?.contains("grant_type=refresh_token") == true }
    }

    private fun refreshRequests(client: OAuthClient) =
        transcript.matching("POST", tokenPath(client)).filter { it.form["grant_type"] == "refresh_token" }

    private fun serverCause(error: VersolaError.Recoverable): Cause.Server =
        error.reason as? Cause.Server ?: throw AssertionError("expected Server, got ${error.reason}")

    // ---- 34 ---------------------------------------------------------------------------------

    @Test
    fun `34 a refresh is repeated three times when the provider did not take it up, and made once when it may have`() = runTest {
        val client = client()
        client.login()
        // The generic facade sends no Idempotency-Key, so only what provably was not processed is
        // repeated (408, 429, 503; a 408 is left out here because OkHttp itself repeats one on the
        // wire, which would make the request count the HTTP client's and not the SDK's); a 500, 502 or 504 may have come after the provider rotated the
        // token, and a replay of it is what a rotating provider answers by revoking the family.
        for ((status, expected) in listOf(503 to 3, 429 to 3, 500 to 1, 502 to 1, 504 to 1)) {
            val before = refreshRequests(client).size
            respondWith(status, matches = refreshGrant(client))

            val error = failsWith<VersolaError.Recoverable> { runBlocking { client.refresh() } }

            val cause = serverCause(error)
            assertEquals(status, cause.status)
            assertEquals("$status", expected, cause.attempts)
            assertNull(cause.retryAfterMillis)
            assertEquals("$status", expected, refreshRequests(client).size - before)
            assertEquals(SessionState.Authenticated, client.state())
        }
        // The grant survived all of it: once the provider answers, the same session refreshes.
        proxy.clearRewrites()
        client.refresh()
        assertEquals(SessionState.Authenticated, client.state())
    }

    @Test
    fun `34 a 501 is surfaced after one request with no delay`() = runTest {
        val client = client()
        client.login()
        val before = refreshRequests(client).size
        respondWith(501, matches = refreshGrant(client))

        val error = failsWith<VersolaError.Recoverable> { runBlocking { client.refresh() } }

        assertEquals(501, serverCause(error).status)
        assertEquals(1, refreshRequests(client).size - before)
        assertEquals(SessionState.Authenticated, client.state())
    }

    @Test
    fun `34 a request through the authenticated client answering 503 is returned as the response, header intact, after one request`() = runTest {
        val client = client()
        client.login()

        val response = client.call(okhttp3.Request.Builder().url(resource.url("/unavailable")).build())

        assertEquals(503, response.code)
        assertEquals("7", response.header("Retry-After"))
        assertEquals(1, resource.requests.count { it.url.encodedPath == "/unavailable" })
        // Nothing was refreshed, repeated or blocked on its account.
        assertEquals(SessionState.Authenticated, client.state())
        response.close()
    }

    @Test
    fun `34 discovery answered 500, 503 or 429 is repeated three times`() = runTest {
        for (status in listOf(500, 503, 429)) {
            OAuthClient.forgetAll()
            val client = client()
            val before = transcript.matching("GET", discoveryPath).size
            respondWith(status, matches = path(discoveryPath))

            val error = failsWith<VersolaError.Recoverable> { runBlocking { client.metadata() } }

            assertEquals(status, serverCause(error).status)
            assertEquals("$status", 3, transcript.matching("GET", discoveryPath).size - before)
            proxy.clearRewrites()
        }
    }

    @Test
    fun `34 a pushed authorization request answered 503 is repeated three times and the browser never opens`() = runTest {
        val client = client()
        val par = client.metadata().pushedAuthorizationRequestEndpoint
        assumeTrue("the provider advertises no PAR endpoint", par != null)
        val parPath = par!!.substringAfter(proxy.origin)
        respondWith(503, matches = path(parPath))

        val error = failsWith<VersolaError.Recoverable> { runBlocking { client.login() } }

        assertEquals(503, serverCause(error).status)
        assertEquals(3, transcript.matching("POST", parPath).size)
        assertTrue(browser.opened.isEmpty())
        assertEquals(SessionState.Unauthenticated, client.state())
    }

    @Test
    fun `34 UserInfo answered 503 is repeated three times`() = runTest {
        val client = client()
        client.login()
        val userinfo = client.metadata().userinfoEndpoint
        assumeTrue("the provider advertises no userinfo_endpoint", userinfo != null)
        val userinfoPath = userinfo!!.substringAfter(proxy.origin)
        respondWith(503, matches = path(userinfoPath))

        val error = failsWith<VersolaError.Recoverable> { runBlocking { client.userInfo() } }

        assertEquals(503, serverCause(error).status)
        assertEquals(3, transcript.matching("GET", userinfoPath).size)
    }

    @Test
    fun `34 a code exchange answered 503 is made once, the login fails, and the next login starts from the browser`() = runTest {
        val client = client()
        val token = tokenPath(client)
        respondWith(503, headers = mapOf("Retry-After" to "1"), times = 1) {
            it.url.encodedPath.endsWith(token) && it.body?.utf8()?.contains("grant_type=authorization_code") == true
        }

        val error = failsWith<VersolaError.Recoverable> { runBlocking { client.login() } }

        // A single-use code is never replayed, whatever the status and whatever the server asks.
        assertEquals(503, serverCause(error).status)
        assertEquals(1, transcript.matching("POST", token).size)
        assertEquals(SessionState.Unauthenticated, client.state())

        client.login()
        assertEquals(2, browser.opened.size)
        assertEquals(SessionState.Authenticated, client.state())
    }

    // ---- 35 ---------------------------------------------------------------------------------

    @Test
    fun `35 a 429 with Retry-After 2 is waited out before the second request`() = runBlocking {
        val client = client()
        client.login()
        respondWith(429, headers = mapOf("Retry-After" to "2"), times = 1, matches = refreshGrant(client))

        client.refresh()

        val attempts = refreshRequests(client)
        assertEquals(2, attempts.size)
        val gap = attempts[1].at - attempts[0].at
        // Not the 500 ms backoff, and not past the two seconds plus its tenth of jitter.
        assertTrue("gap ${gap}ms", gap in 2_000..2_900)
        assertEquals(SessionState.Authenticated, client.state())
    }

    @Test
    fun `35 an HTTP-date Retry-After is measured against the response's Date`() = runBlocking {
        val client = client()
        client.login()
        val now = System.currentTimeMillis()
        val format = java.text.SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss 'GMT'", java.util.Locale.US)
            .apply { timeZone = java.util.TimeZone.getTimeZone("GMT") }
        respondWith(
            503,
            headers = mapOf("Date" to format.format(java.util.Date(now)), "Retry-After" to format.format(java.util.Date(now + 3_000))),
            times = 1,
            matches = refreshGrant(client),
        )

        client.refresh()

        val attempts = refreshRequests(client)
        assertEquals(2, attempts.size)
        val gap = attempts[1].at - attempts[0].at
        assertTrue("gap ${gap}ms", gap in 2_000..3_900)
    }

    @Test
    fun `35 an HTTP-date Retry-After is measured against the response's Date even when the device clock disagrees by an hour`() = runBlocking {
        val client = client()
        client.login()
        // The provider's clock is an hour ahead of the device's: against the device clock the date
        // would be an hour away (a day-capped wait that does not fit the budget), against the
        // response's own Date it is three seconds.
        val serverNow = System.currentTimeMillis() + 3_600_000
        val format = java.text.SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss 'GMT'", java.util.Locale.US)
            .apply { timeZone = java.util.TimeZone.getTimeZone("GMT") }
        respondWith(
            503,
            headers = mapOf("Date" to format.format(java.util.Date(serverNow)), "Retry-After" to format.format(java.util.Date(serverNow + 3_000))),
            times = 1,
            matches = refreshGrant(client),
        )

        client.refresh()

        val attempts = refreshRequests(client)
        assertEquals(2, attempts.size)
        val gap = attempts[1].at - attempts[0].at
        assertTrue("gap ${gap}ms", gap in 2_000..3_900)
    }

    @Test
    fun `35 a Retry-After past the budget, a day long, stops at once with the value`() = runTest {
        for ((header, expectedMillis) in listOf("30" to 30_000L, "86400" to 86_400_000L, "999999999" to 86_400_000L)) {
            OAuthClient.forgetAll()
            val client = client()
            client.login()
            val before = refreshRequests(client).size
            respondWith(429, headers = mapOf("Retry-After" to header), matches = refreshGrant(client))

            val error = failsWith<VersolaError.Recoverable> { runBlocking { client.refresh() } }

            val cause = serverCause(error)
            assertEquals(429, cause.status)
            assertEquals(header, expectedMillis, cause.retryAfterMillis)
            assertEquals(header, 1, cause.attempts)
            // One request, no sleeping and no shortening of the wait.
            assertEquals(header, 1, refreshRequests(client).size - before)
            proxy.clearRewrites()
        }
    }

    @Test
    fun `35 a malformed Retry-After is ignored with ordinary backoff, three requests and no Configuration`() = runBlocking {
        for (junk in listOf("-1", "1.5", "soon", "")) {
            OAuthClient.forgetAll()
            val client = client()
            client.login()
            val before = refreshRequests(client).size
            respondWith(503, headers = mapOf("Retry-After" to junk), matches = refreshGrant(client))

            val error = failsWith<VersolaError.Recoverable> { runBlocking { client.refresh() } }

            val cause = serverCause(error)
            assertNull("'$junk'", cause.retryAfterMillis)
            assertEquals("'$junk'", 3, refreshRequests(client).size - before)
            proxy.clearRewrites()
        }
    }

    @Test
    fun `35 a Retry-After on a 500 is ignored`() = runBlocking {
        val client = client()
        client.login()
        respondWith(500, headers = mapOf("Retry-After" to "86400"), matches = refreshGrant(client))

        val error = failsWith<VersolaError.Recoverable> { runBlocking { client.refresh() } }

        // A 500 is not repeated by a facade with no Idempotency-Key, and its header is not read.
        val cause = serverCause(error)
        assertNull(cause.retryAfterMillis)
        assertEquals(1, cause.attempts)
    }

    @Test
    fun `35 a Retry-After on a 502 from UserInfo is ignored and the ordinary backoff applies`() = runBlocking {
        val client = client()
        client.login()
        val userinfo = client.metadata().userinfoEndpoint
        assumeTrue("the provider advertises no userinfo_endpoint", userinfo != null)
        respondWith(502, headers = mapOf("Retry-After" to "86400"), matches = path(userinfo!!.substringAfter(proxy.origin)))

        val error = failsWith<VersolaError.Recoverable> { runBlocking { client.userInfo() } }

        val cause = serverCause(error)
        assertNull(cause.retryAfterMillis)
        assertEquals(3, cause.attempts)
    }

    // ---- 36 ---------------------------------------------------------------------------------

    @Test
    fun `36 after a Retry-After nothing is sent to the provider until it passes, and logout still wipes`() = runTest {
        val client = client()
        client.login()
        respondWith(429, headers = mapOf("Retry-After" to "30"), matches = refreshGrant(client))
        val first = failsWith<VersolaError.Recoverable> { runBlocking { client.refresh() } }
        assertEquals(30_000L, serverCause(first).retryAfterMillis)
        val sent = transcript.entries.size

        // Inside the window: every one of these fails at once, and none sends a request.
        for (call in listOf<suspend () -> Unit>({ client.refresh() }, { client.userInfo() })) {
            val error = failsWith<VersolaError.Recoverable> { runBlocking { call() } }
            val cause = serverCause(error)
            assertEquals(429, cause.status)
            assertEquals(0, cause.attempts)
            assertTrue("left ${cause.retryAfterMillis}", cause.retryAfterMillis!! in 1..30_000)
        }
        // accessToken() serves the live token from memory: no request to make, so none refused. The
        // expired-token form, where it fails at once with attempts 0, is SessionCoordinatorTest's.
        client.accessToken()
        assertEquals(sent, transcript.entries.size)
        assertEquals(SessionState.Authenticated, client.state())

        // The revocation is refused by the cooldown (same origin, nothing sent) and the local wipe
        // happens regardless.
        val outcome = client.logout()
        assertEquals(false, outcome.tokenRevoked)
        assertEquals(SessionState.Unauthenticated, client.state())
        assertEquals(1, refreshRequests(client).size)
    }

    @Test
    fun `36 exhausting the budget on 503 without Retry-After starts no cooldown`() = runTest {
        val client = client()
        client.login()
        respondWith(503, matches = refreshGrant(client))
        failsWith<VersolaError.Recoverable> { runBlocking { client.refresh() } }
        val afterFirst = refreshRequests(client).size

        failsWith<VersolaError.Recoverable> { runBlocking { client.refresh() } }

        // A second set of three: the SDK invents no provider policy; the retry loop above it is the app's.
        assertEquals(3, afterFirst)
        assertEquals(6, refreshRequests(client).size)
    }

    @Test
    fun `36 the cooldown ends when the Retry-After has passed, and the next refresh goes out`() = runBlocking {
        // A one-second budget makes a two-second Retry-After one that does not fit, so the SDK stops
        // and holds the origin; waiting it out in real time proves the cooldown's end without
        // touching the SDK's clock.
        val client = client(configuration(retryPolicy = RetryPolicy(totalBudget = kotlin.time.Duration.parse("1s"))))
        client.login()
        respondWith(429, headers = mapOf("Retry-After" to "2"), matches = refreshGrant(client))
        val first = failsWith<VersolaError.Recoverable> { runBlocking { client.refresh() } }
        assertEquals(2_000L, serverCause(first).retryAfterMillis)
        val sent = refreshRequests(client).size

        val refused = failsWith<VersolaError.Recoverable> { runBlocking { client.refresh() } }
        val userinfo = failsWith<VersolaError.Recoverable> { runBlocking { client.userInfo() } }

        for (error in listOf(refused, userinfo)) {
            assertEquals(0, serverCause(error).attempts)
            assertTrue(serverCause(error).retryAfterMillis!! in 1..2_000)
        }
        assertEquals(sent, refreshRequests(client).size)

        proxy.clearRewrites()
        Thread.sleep(2_300)
        client.refresh()

        assertEquals(sent + 1, refreshRequests(client).size)
        assertEquals(SessionState.Authenticated, client.state())
    }
}
