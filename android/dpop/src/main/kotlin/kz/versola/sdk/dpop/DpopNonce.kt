package kz.versola.sdk.dpop

import java.util.concurrent.ConcurrentHashMap
import kz.versola.sdk.core.VersolaError

/**
 * The key a nonce is cached under: scheme, host and port.
 *
 * Per origin, not per deployment, and this is the part that is easy to get wrong. `auth` and
 * `edge` issue independent nonces from independent caches; one shared entry sends auth's nonce
 * to edge, which answers `use_dpop_nonce` again, which is the loop
 * [DpopNonceRetry] exists to bound (#1 §2.1, scenario 04).
 *
 * The port is part of the key even though `id.versola.kz` and `versola.kz` already differ by
 * host: a staged stack (#15) runs both on one host and separates them by port alone.
 */
internal data class Origin(val value: String) {

    override fun toString(): String = value

    companion object {
        fun of(url: String): Origin {
            val (scheme, authority, _) = split(url)
            // Userinfo is not part of an origin; a bracketed IPv6 literal keeps its brackets
            // and its colons, so the port is whatever follows the closing bracket.
            val hostPort = authority.substringAfterLast('@')
            val (host, port) = if (hostPort.startsWith("[")) {
                val end = hostPort.indexOf(']')
                require(end > 0) { "a DPoP request URL has an unterminated IPv6 literal: $url" }
                hostPort.substring(0, end + 1) to hostPort.substring(end + 1).removePrefix(":")
            } else {
                hostPort.substringBefore(':') to hostPort.substringAfter(':', "")
            }
            require(host.isNotEmpty()) { "a DPoP request URL must have a host: $url" }
            // The default port is normalised away rather than kept, so that a server reached
            // once as `https://host` and once as `https://host:443` does not end up holding
            // two entries and challenging on alternate requests.
            val normalisedPort = port.toIntOrNull()?.takeIf { it != defaultPort(scheme) }?.let { ":$it" } ?: ""
            return Origin("$scheme://${host.lowercase(java.util.Locale.ROOT)}$normalisedPort")
        }

        /**
         * RFC 9449 §4.3 step 9: the request URI with query and fragment removed — scheme,
         * authority and path exactly as they went on the wire, which is what `Dpop.normalizeHtu`
         * on the server rebuilds. Decoding first would collapse `/a%2Fb` and `/a/b` into one
         * string, which is exactly the confusion `htu` exists to rule out.
         *
         * Split by hand rather than through `java.net.URI`, which refuses characters OkHttp
         * legitimately leaves raw in a query (`{`, `}`, `|`, `^`): a JSON filter in a query
         * string is an ordinary REST idiom, and a proof builder must not throw on it.
         */
        fun htuOf(url: String): String {
            val (scheme, authority, path) = split(url)
            return "$scheme://$authority$path"
        }

        private fun split(url: String): Triple<String, String, String> {
            val schemeEnd = url.indexOf("://")
            require(schemeEnd > 0) { "a DPoP request URL must be absolute: $url" }
            val scheme = url.substring(0, schemeEnd).lowercase(java.util.Locale.ROOT)
            val rest = url.substring(schemeEnd + 3).substringBefore('#').substringBefore('?')
            val slash = rest.indexOf('/')
            val authority = if (slash < 0) rest else rest.substring(0, slash)
            val path = if (slash < 0) "" else rest.substring(slash)
            require(authority.isNotEmpty()) { "a DPoP request URL must have a host: $url" }
            return Triple(scheme, authority, path)
        }

        private fun defaultPort(scheme: String): Int = when (scheme) {
            "https" -> 443
            "http" -> 80
            else -> -1
        }
    }
}

/**
 * RFC 9449 §9 nonces, held per origin, in memory only.
 *
 * Memory only is deliberate (`spec/state-machine.md`, persistence summary): a nonce is
 * short-lived server state, and a stale one restored from disk buys a guaranteed extra
 * round trip rather than saving one.
 */
public class DpopNonceCache {

    private val nonces = ConcurrentHashMap<String, String>()

    /** The nonce to sign into a proof for [url], or null when that origin has issued none. */
    public fun nonceFor(url: String): String? = nonces[Origin.of(url).value]

    public fun store(url: String, nonce: String) {
        nonces[Origin.of(url).value] = nonce
    }

    /** Logout wipes both caches along with everything else credential-shaped (#10). */
    public fun clear() {
        nonces.clear()
    }
}

/**
 * The one-shot nonce retry, for one operation.
 *
 * `spec/retry-policy.md` allows exactly one nonce retry per origin per operation. A second
 * challenge means the server will never be satisfied, and the failure that matters is not the
 * request failing — it is a shipped app retrying forever (scenario 05). So the bound lives in
 * a short-lived object the caller creates per operation, rather than in a counter someone can
 * forget to reset.
 *
 * Nothing here performs HTTP: the token endpoint (#8) and the authenticated client (#9) drive
 * it, and both must bound the same way.
 */
public class DpopNonceRetry(private val nonces: DpopNonceCache) {

    private val challenged = mutableSetOf<String>()

    /**
     * Records a `use_dpop_nonce` challenge and caches the nonce it carried, so the caller may
     * retry once.
     *
     * Throws `Recoverable(NonceLoop)` on the second challenge from the same origin within one
     * operation, and on a challenge carrying no `DPoP-Nonce` header at all — a challenge with
     * no nonce cannot be answered, so retrying it is the same unbounded loop by another route.
     */
    public fun accept(url: String, nonce: String?) {
        val origin = Origin.of(url)
        if (!challenged.add(origin.value) || nonce.isNullOrEmpty()) {
            throw VersolaError.Recoverable(VersolaError.Recoverable.Cause.NonceLoop(origin.value))
        }
        nonces.store(url, nonce)
    }
}
