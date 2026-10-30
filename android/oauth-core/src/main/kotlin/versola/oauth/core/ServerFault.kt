package versola.oauth.core

import okhttp3.Headers

/**
 * What an HTTP answer that is not a success means to the retry policy (`spec/retry-policy.md`,
 * "Classification"), in one place so that every client the SDK sends a request with reads a status
 * the same way.
 *
 * The statuses a repeat can help are [isRepeatable]. Every other status an operation cannot use
 * still becomes a `Recoverable` [VersolaError.Recoverable.Cause.Server] when its own mapping has
 * nothing more precise, because the alternative — the old `Network` for a 404 — would be repeated
 * as a transport failure.
 */
internal object ServerFault {

    private const val ONE_DAY_MILLIS = 86_400_000L
    private const val MILLIS_PER_SECOND = 1_000L

    /** 408, 429, 500, 502, 503, 504: the provider is busy or briefly broken. */
    fun isRepeatable(status: Int): Boolean =
        status == 408 || status == 429 || status == 500 || status == 502 || status == 503 || status == 504

    /**
     * Whether the request provably was not processed, so that repeating it cannot replay a spent
     * single-use token: a failure in the connect phase (no such host, refused, no route, a TLS
     * handshake or certificate failure: nothing was written), or a status that says the provider
     * did not take the request up (408, 429, 503). A timeout after connecting, a reset, a 500, 502
     * or 504 may each have come after the provider acted, so they are not on this list.
     */
    fun wasNotProcessed(failure: VersolaError.Recoverable): Boolean = when (val reason = failure.reason) {
        is VersolaError.Recoverable.Cause.Server -> reason.status == 408 || reason.status == 429 || reason.status == 503
        is VersolaError.Recoverable.Cause.Network -> when (failure.cause) {
            is java.net.UnknownHostException,
            is java.net.ConnectException,
            is java.net.NoRouteToHostException,
            is javax.net.ssl.SSLHandshakeException,
            is javax.net.ssl.SSLPeerUnverifiedException,
            -> true
            else -> false
        }
        else -> false
    }

    /** A status that is the provider's fault rather than a request it understood and refused. */
    fun isServerFault(status: Int): Boolean = status >= 500 || status == 408 || status == 429

    /**
     * The `Recoverable` for an HTTP [status] this operation cannot use. `Retry-After` is read on
     * 429 and 503 only, whatever the other statuses carry.
     */
    fun failure(
        status: Int,
        headers: Headers,
        wallClockMillis: () -> Long = System::currentTimeMillis,
    ): VersolaError.Recoverable {
        val retryAfter = if (status == 429 || status == 503) retryAfterMillis(headers, wallClockMillis) else null
        return VersolaError.Recoverable(VersolaError.Recoverable.Cause.Server(status, retryAfter))
    }

    /**
     * RFC 9110 section 10.2.3: `delta-seconds`, a non-negative integer, or an HTTP-date.
     *
     * An HTTP-date is measured against the response's own `Date`, because the device clock is the
     * one thing in this exchange that is known to be wrong sometimes; with no usable `Date` it
     * falls back to [wallClockMillis]. Anything else — absent, repeated, empty, negative,
     * fractional, text, a date already in the past — is no hint at all and the policy's own
     * backoff applies: a malformed header never fails the request. The result saturates at one
     * day, so no later arithmetic on it can overflow.
     */
    fun retryAfterMillis(headers: Headers, wallClockMillis: () -> Long): Long? {
        val values = headers.values("Retry-After")
        if (values.size != 1) return null
        val value = values[0].trim()
        if (value.isEmpty()) return null
        if (value.all { it in '0'..'9' }) {
            // More digits than a day has seconds is already past the ceiling; stopping before
            // the conversion is what keeps a 40-digit value from overflowing it.
            if (value.length > 9) return ONE_DAY_MILLIS
            return minOf(value.toLong() * MILLIS_PER_SECOND, ONE_DAY_MILLIS)
        }
        val date = headers.getDate("Retry-After")?.time ?: return null
        val now = headers.getDate("Date")?.time ?: wallClockMillis()
        val wait = date - now
        return if (wait > 0) minOf(wait, ONE_DAY_MILLIS) else null
    }
}
