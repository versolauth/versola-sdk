package versola.oauth.core

import okhttp3.CacheControl
import okhttp3.Headers

/**
 * How long a fetched document may be trusted without asking again: what the provider says in
 * `Cache-Control: max-age` (or `Expires`), held between [MIN_MILLIS] and [MAX_MILLIS], and
 * [MAX_MILLIS] when it says nothing.
 *
 * The ceiling is the point. A key set that never expires keeps a withdrawn signing key trusted for
 * as long as the process lives and, through the disk copy, across restarts; a day bounds that
 * without asking the provider on every launch, and it is the 24 hours `spec/oauth-sdk-api.md`
 * section 4 gives discovery. The floor keeps a provider that sends `max-age=0` or `no-store` from
 * being asked on every ID token, which the retry policy's budget would turn into a request storm.
 * An unknown `kid` still forces one refetch whatever is cached; that is a separate path. A response
 * that carries an `Age` has that much less of its lifetime to live.
 */
internal object CacheLifetime {
    const val MIN_MILLIS: Long = 5 * 60 * 1000
    const val MAX_MILLIS: Long = 24 * 60 * 60 * 1000

    /** The lifetime of the answer [headers] came with, received at [nowEpochMillis]. */
    fun of(headers: Headers, nowEpochMillis: Long): Long {
        val control = CacheControl.parse(headers)
        val requested = when {
            // `no-store` and `no-cache` say the answer is not to be reused without revalidation;
            // this client has no validator to revalidate with, so the shortest lifetime it allows.
            control.noStore || control.noCache -> 0L
            control.maxAgeSeconds >= 0 -> control.maxAgeSeconds.toLong().coerceAtMost(MAX_MILLIS / 1000) * 1000
            headers["Expires"] != null -> {
                // An `Expires` that does not parse is in the past (RFC 9111 section 5.3). Measured
                // from the response's own `Date`, so a skewed device clock does not stretch it.
                val expires = headers.getDate("Expires")?.time
                val base = headers.getDate("Date")?.time ?: nowEpochMillis
                if (expires == null) 0L else expires - base
            }
            else -> MAX_MILLIS
        }
        // A response that sat in a cache or a proxy is already `Age` seconds old (RFC 9111 section
        // 4.2.3): it has that much less of its lifetime left. An `Age` that does not parse is none.
        val age = headers["Age"]?.trim()?.toLongOrNull()?.coerceIn(0, MAX_MILLIS / 1000) ?: 0L
        return (requested - age * 1000).coerceIn(MIN_MILLIS, MAX_MILLIS)
    }

    /**
     * Whether something that expires at [expiresAtEpochMillis] is still good at [nowEpochMillis]. An
     * expiry further away than [MAX_MILLIS] cannot have been set by this class: the clock moved back
     * since, or the record is not ours, and either is an expired record.
     */
    fun isFresh(expiresAtEpochMillis: Long, nowEpochMillis: Long): Boolean =
        nowEpochMillis < expiresAtEpochMillis && expiresAtEpochMillis - nowEpochMillis <= MAX_MILLIS
}
