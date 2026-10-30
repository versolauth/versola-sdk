package versola.sdk.dpop

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** 2023-11-14T22:13:20Z, as both epoch millis and the header form a server sends. */
private const val SERVER_MILLIS = 1_700_000_000_000L
private const val SERVER_DATE = "Tue, 14 Nov 2023 22:13:20 GMT"

class ClockSkewTest {

    @Test
    fun `a device running fast is corrected backwards`() {
        val skew = ClockSkew { SERVER_MILLIS + 300_000 }

        skew.learn(SERVER_DATE)

        assertEquals(-300_000L, skew.learnedOffsetMillis)
        assertEquals(SERVER_MILLIS, skew.now())
    }

    @Test
    fun `a device running slow is corrected forwards`() {
        // Scenario 06 runs both directions, because an implementation that subtracts where it
        // should add passes one of them.
        val skew = ClockSkew { SERVER_MILLIS - 300_000 }

        skew.learn(SERVER_DATE)

        assertEquals(300_000L, skew.learnedOffsetMillis)
        assertEquals(SERVER_MILLIS, skew.now())
    }

    @Test
    fun `nothing is corrected until something has been learned`() {
        val skew = ClockSkew { SERVER_MILLIS + 300_000 }

        assertNull(skew.learnedOffsetMillis)
        assertEquals(SERVER_MILLIS + 300_000, skew.now())
    }

    @Test
    fun `an absent or unreadable Date leaves the learned offset alone`() {
        // It says nothing about the clock either way. Resetting to zero would discard a
        // correction that is keeping every proof inside the server's leeway.
        val skew = ClockSkew { SERVER_MILLIS + 300_000 }
        skew.learn(SERVER_DATE)

        skew.learn(null)
        skew.learn("whenever")

        assertEquals(-300_000L, skew.learnedOffsetMillis)
    }

    @Test
    fun `iat is expressed in whole seconds`() {
        // RFC 7519 §2. Truncated rather than rounded: rounding up puts iat in the future,
        // which is the side of the server's leeway with less room on it.
        val skew = ClockSkew { SERVER_MILLIS + 1_500 }

        assertEquals(SERVER_MILLIS / 1000 + 1, skew.nowSeconds())
    }

    @Test
    fun `a later response re-learns the offset`() {
        // The clock can be corrected under us — by NTP, or by the user. A one-shot offset
        // would then be the only thing making proofs wrong.
        var device = SERVER_MILLIS + 300_000
        val skew = ClockSkew { device }
        skew.learn(SERVER_DATE)

        device = SERVER_MILLIS
        skew.learn(SERVER_DATE)

        assertEquals(0L, skew.learnedOffsetMillis)
    }

    @Test
    fun `a Date more than 30 days from the device clock is ignored`() {
        // A device that far off could not complete a TLS handshake against most certificates, so the
        // value is a stale cache or a broken intermediary, and learning it would stamp every proof
        // with a date nobody accepts.
        val skew = ClockSkew { SERVER_MILLIS + 31L * 24 * 3600 * 1000 }
        skew.learn(SERVER_DATE)
        assertNull(skew.learnedOffsetMillis)

        val behind = ClockSkew { SERVER_MILLIS - 31L * 24 * 3600 * 1000 }
        behind.learn(SERVER_DATE)
        assertNull(behind.learnedOffsetMillis)
    }

    @Test
    fun `a Date just inside 30 days is learned, and one outside does not replace what was learned`() {
        var device = SERVER_MILLIS + 300_000
        val skew = ClockSkew { device }
        skew.learn(SERVER_DATE)
        assertEquals(-300_000L, skew.learnedOffsetMillis)

        device = SERVER_MILLIS + 29L * 24 * 3600 * 1000
        skew.learn(SERVER_DATE)
        assertEquals(-29L * 24 * 3600 * 1000, skew.learnedOffsetMillis)

        device = SERVER_MILLIS + 31L * 24 * 3600 * 1000
        skew.learn(SERVER_DATE)
        assertEquals("unchanged", -29L * 24 * 3600 * 1000, skew.learnedOffsetMillis)
    }
}
