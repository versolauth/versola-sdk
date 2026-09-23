package kz.versola.sdk.dpop

import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException

/**
 * The offset between this device's clock and the server's, learned from the `Date` header.
 *
 * Device clocks are wrong far more often than anyone expects, and `Dpop.verify` enforces a
 * bounded `iat` leeway — so a phone five minutes fast has every proof rejected for a reason
 * that looks nothing like a clock problem from the app's side.
 *
 * In memory only, re-learned after process death (scenario 06). Persisting it would mean
 * correcting today's proofs by an offset measured against a clock the user has since fixed.
 */
public class ClockSkew(private val clock: () -> Long = System::currentTimeMillis) {

    @Volatile
    private var offsetMillis: Long? = null

    /** The learned offset, or null until a response has been seen. Server time minus device time. */
    public val learnedOffsetMillis: Long? get() = offsetMillis

    /**
     * Learns from one response's `Date` header. An absent or unparseable value leaves any
     * previously learned offset in place: it says nothing about the clock either way.
     */
    public fun learn(dateHeader: String?) {
        val serverTime = parse(dateHeader ?: return) ?: return
        offsetMillis = serverTime - clock()
    }

    /** Device time corrected by whatever has been learned. What every `iat` is stamped from. */
    public fun now(): Long = clock() + (offsetMillis ?: 0)

    /** Seconds since the epoch, which is the unit `iat` is expressed in (RFC 7519 §2). */
    public fun nowSeconds(): Long = now() / 1000

    private fun parse(header: String): Long? = try {
        // RFC 9110 §5.6.7 preferred form. The two obsolete formats it also permits are not
        // read: no server this SDK talks to emits them, and guessing wrong about a date is
        // worse than not correcting at all.
        ZonedDateTime.parse(header, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant().toEpochMilli()
    } catch (e: DateTimeParseException) {
        null
    }
}
