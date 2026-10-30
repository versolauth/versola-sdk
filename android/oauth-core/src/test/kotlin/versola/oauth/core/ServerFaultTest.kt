package versola.oauth.core

import okhttp3.Headers
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ServerFaultTest {

    // 2026-10-30 12:00:00 UTC, the device clock in these tests: wrong on purpose where it matters.
    private val deviceNow = 1_793_361_600_000L

    private fun headers(vararg pairs: Pair<String, String>): Headers =
        Headers.Builder().apply { pairs.forEach { (name, value) -> add(name, value) } }.build()

    private fun retryAfter(vararg pairs: Pair<String, String>): Long? =
        ServerFault.retryAfterMillis(headers(*pairs), { deviceNow })

    @Test
    fun `408, 429, 500, 502, 503 and 504 are repeatable, and nothing else is`() {
        for (status in listOf(408, 429, 500, 502, 503, 504)) assertTrue("$status", ServerFault.isRepeatable(status))
        for (status in listOf(200, 301, 400, 401, 403, 404, 410, 501, 505, 506, 511)) {
            assertFalse("$status", ServerFault.isRepeatable(status))
        }
    }

    @Test
    fun `a status that is the provider's fault is told apart from a request it refused`() {
        for (status in listOf(408, 429, 500, 501, 503, 505)) assertTrue("$status", ServerFault.isServerFault(status))
        for (status in listOf(400, 401, 403, 404, 410)) assertFalse("$status", ServerFault.isServerFault(status))
    }

    @Test
    fun `delta-seconds becomes milliseconds`() {
        assertEquals(0L, retryAfter("Retry-After" to "0"))
        assertEquals(2_000L, retryAfter("Retry-After" to "2"))
        assertEquals(120_000L, retryAfter("Retry-After" to " 120 "))
    }

    @Test
    fun `a value past a day saturates instead of overflowing`() {
        assertEquals(86_400_000L, retryAfter("Retry-After" to "86400"))
        assertEquals(86_400_000L, retryAfter("Retry-After" to "86401"))
        assertEquals(86_400_000L, retryAfter("Retry-After" to "999999999"))
        // More digits than a Long holds: the conversion must never run.
        assertEquals(86_400_000L, retryAfter("Retry-After" to "9".repeat(40)))
    }

    @Test
    fun `leading zeros are part of the number, not a reason to saturate`() {
        assertEquals(30_000L, retryAfter("Retry-After" to "0000000030"))
        assertEquals(0L, retryAfter("Retry-After" to "000000000000"))
        assertEquals(86_400_000L, retryAfter("Retry-After" to "0000000000999999999999"))
    }

    @Test
    fun `an HTTP-date is measured against the response's Date, not the device clock`() {
        val wait = retryAfter(
            "Date" to "Fri, 30 Oct 2026 12:00:00 GMT",
            "Retry-After" to "Fri, 30 Oct 2026 12:00:04 GMT",
        )

        assertEquals(4_000L, wait)
    }

    @Test
    fun `a skewed device clock does not stretch or shrink an HTTP-date wait`() {
        // The device is an hour ahead of the server: against its own clock the date would be
        // in the past, against the response's Date it is four seconds away.
        val ahead = ServerFault.retryAfterMillis(
            headers(
                "Date" to "Fri, 30 Oct 2026 12:00:00 GMT",
                "Retry-After" to "Fri, 30 Oct 2026 12:00:04 GMT",
            ),
        ) { deviceNow + 3_600_000L }

        assertEquals(4_000L, ahead)
    }

    @Test
    fun `without a usable Date an HTTP-date falls back to the device clock`() {
        assertEquals(10_000L, retryAfter("Retry-After" to "Fri, 30 Oct 2026 12:00:10 GMT"))
        assertEquals(
            10_000L,
            retryAfter("Date" to "not a date", "Retry-After" to "Fri, 30 Oct 2026 12:00:10 GMT"),
        )
    }

    @Test
    fun `the obsolete HTTP-date formats are read too`() {
        assertEquals(
            30_000L,
            retryAfter("Date" to "Fri, 30 Oct 2026 12:00:00 GMT", "Retry-After" to "Friday, 30-Oct-26 12:00:30 GMT"),
        )
        assertEquals(
            30_000L,
            retryAfter("Date" to "Fri, 30 Oct 2026 12:00:00 GMT", "Retry-After" to "Fri Oct 30 12:00:30 2026"),
        )
    }

    @Test
    fun `an HTTP-date at or before now is no hint`() {
        assertNull(retryAfter("Date" to "Fri, 30 Oct 2026 12:00:00 GMT", "Retry-After" to "Fri, 30 Oct 2026 12:00:00 GMT"))
        assertNull(retryAfter("Date" to "Fri, 30 Oct 2026 12:00:00 GMT", "Retry-After" to "Fri, 30 Oct 2026 11:59:00 GMT"))
    }

    @Test
    fun `a value that is not delta-seconds or a date is no hint and never an error`() {
        for (junk in listOf("", "  ", "-1", "1.5", "1e3", "soon", "+5", "0x10", "5 seconds")) {
            assertNull("'$junk'", retryAfter("Retry-After" to junk))
        }
    }

    @Test
    fun `no header and more than one header are both no hint`() {
        assertNull(retryAfter())
        assertNull(retryAfter("Retry-After" to "2", "Retry-After" to "3"))
    }

    @Test
    fun `Retry-After is read on 429 and 503 and ignored on every other status`() {
        val withHeader = headers("Retry-After" to "5")

        for (status in listOf(429, 503)) {
            val cause = ServerFault.failure(status, withHeader).reason as VersolaError.Recoverable.Cause.Server
            assertEquals(status, cause.status)
            assertEquals(5_000L, cause.retryAfterMillis)
        }
        for (status in listOf(408, 500, 502, 504, 501)) {
            val cause = ServerFault.failure(status, withHeader).reason as VersolaError.Recoverable.Cause.Server
            assertEquals(status, cause.status)
            assertNull("$status", cause.retryAfterMillis)
        }
    }
}
