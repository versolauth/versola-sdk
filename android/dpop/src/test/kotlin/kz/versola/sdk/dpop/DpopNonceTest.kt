package kz.versola.sdk.dpop

import kz.versola.sdk.core.VersolaError
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

private const val AUTH = "https://id.versola.kz/token"
private const val EDGE = "https://versola.kz/resources/42"

class DpopNonceCacheTest {

    @Test
    fun `auth and edge hold independent entries`() {
        // Scenario 04. One shared entry sends auth's nonce to edge, edge refuses it and
        // challenges, and the retry carries the same wrong nonce — the loop, reached without
        // any server misbehaving.
        val cache = DpopNonceCache()

        cache.store(AUTH, "auth-nonce")

        assertEquals("auth-nonce", cache.nonceFor(AUTH))
        assertNull(cache.nonceFor(EDGE))
    }

    @Test
    fun `the path and query are not part of the key`() {
        val cache = DpopNonceCache()

        cache.store("https://versola.kz/resources/42?page=2", "edge-nonce")

        assertEquals("edge-nonce", cache.nonceFor("https://versola.kz/permissions/me"))
    }

    @Test
    fun `a port distinguishes two origins on one host`() {
        // The staged stack (#15) runs auth and edge on localhost, separated by port alone —
        // so a key of scheme and host only would merge exactly the two caches scenario 04
        // requires to stay apart.
        val cache = DpopNonceCache()

        cache.store("http://localhost:8080/token", "auth-nonce")

        assertNull(cache.nonceFor("http://localhost:8081/resources/42"))
        assertEquals("auth-nonce", cache.nonceFor("http://localhost:8080/token"))
    }

    @Test
    fun `an explicit default port is the same origin as an implicit one`() {
        val cache = DpopNonceCache()

        cache.store("https://versola.kz:443/resources/42", "edge-nonce")

        assertEquals("edge-nonce", cache.nonceFor(EDGE))
    }

    @Test
    fun `clear wipes every origin`() {
        val cache = DpopNonceCache()
        cache.store(AUTH, "auth-nonce")
        cache.store(EDGE, "edge-nonce")

        cache.clear()

        assertNull(cache.nonceFor(AUTH))
        assertNull(cache.nonceFor(EDGE))
    }
}

class DpopNonceRetryTest {

    @Test
    fun `the first challenge caches the nonce and allows the retry`() {
        val cache = DpopNonceCache()

        DpopNonceRetry(cache).accept(AUTH, "fresh-nonce")

        assertEquals("fresh-nonce", cache.nonceFor(AUTH))
    }

    @Test
    fun `a second challenge from the same origin terminates`() {
        // Scenario 05. The request failing is not the failure that matters here; a shipped
        // app retrying forever is.
        val retry = DpopNonceRetry(DpopNonceCache())
        retry.accept(AUTH, "first")

        val error = assertThrows(VersolaError.Recoverable::class.java) { retry.accept(AUTH, "second") }

        assertEquals(VersolaError.Recoverable.Cause.NonceLoop("https://id.versola.kz"), error.reason)
    }

    @Test
    fun `a challenge carrying no nonce terminates immediately`() {
        // There is nothing to retry with, so a retry would repeat the same nonce-less proof
        // and be challenged again: the same unbounded loop by another route.
        val retry = DpopNonceRetry(DpopNonceCache())

        val error = assertThrows(VersolaError.Recoverable::class.java) { retry.accept(AUTH, null) }

        assertEquals(VersolaError.Recoverable.Cause.NonceLoop("https://id.versola.kz"), error.reason)
    }

    @Test
    fun `the bound is per origin, so one operation may be challenged by each`() {
        // A single call can touch edge and, after a refresh, auth. One challenge from each is
        // within budget; the ceiling is one retry per origin per operation.
        val retry = DpopNonceRetry(DpopNonceCache())

        retry.accept(AUTH, "auth-nonce")
        retry.accept(EDGE, "edge-nonce")

        assertThrows(VersolaError.Recoverable::class.java) { retry.accept(EDGE, "again") }
    }

    @Test
    fun `a fresh operation starts with a fresh budget`() {
        // The counter lives in this short-lived object rather than in the cache, so nothing
        // has to remember to reset it between operations.
        val cache = DpopNonceCache()
        DpopNonceRetry(cache).accept(AUTH, "first")

        DpopNonceRetry(cache).accept(AUTH, "second")

        assertEquals("second", cache.nonceFor(AUTH))
    }

    @Test
    fun `an origin survives a raw query, an IPv6 literal and userinfo`() {
        assertEquals("https://versola.kz", Origin.of("""https://versola.kz/x?filter={"a":1}""").value)
        assertEquals("http://[::1]:9003", Origin.of("http://[::1]:9003/token").value)
        assertEquals("http://[::1]", Origin.of("http://[::1]:80/token").value)
        assertEquals("https://id.versola.kz", Origin.of("https://user:pw@id.versola.kz:443/token").value)
        assertEquals("http://localhost:9005", Origin.of("http://LOCALHOST:9005").value)
    }
}
