package versola.oauth.core

import okhttp3.Headers

/**
 * How an access token is presented: bound to a key the device holds (RFC 9449), or as a
 * bearer [redacted]
 *
 * Not an algorithm choice and not a DPoP configuration — #1 §4 fixes the behaviour to "on and
 * invisible". The only two things an integrator can say here are "I am willing to run without
 * key binding" and "I refuse to run without hardware-backed key binding".
 */
public sealed class TokenBinding {

    /**
     * The default. DPoP whenever the provider advertises it
     * ([ProviderMetadata.supportsDpop]); bearer [redacted]]]]]]]]]]]] one line, when it does not.
     *
     * @param requireHardware turns both silent fallbacks into hard failures: a device with no
     *   hardware-backed keystore, and a deployment that does not advertise DPoP at all. An
     *   app that asserts on possession cannot be served by either, and finding that out at
     *   the first API call rather than at configuration time is worse.
     */
    public data class Dpop(public val requireHardware: Boolean = false) : TokenBinding()

    /** Bearer [redacted] even where the provider supports DPoP. The integrator's own choice. */
    public data object Bearer : TokenBinding()
}

/**
 * The DPoP key's public half, as far as the protocol core needs it.
 *
 * The key itself lives in `:dpop`, which depends on this module and not the other way round:
 * keystore access, proof signing and nonce handling are platform work, whereas *when* a
 * thumbprint goes on the wire is protocol. This interface is the whole of the seam between
 * the two.
 *
 * Suspending because the real implementation generates the key on first use, off the main
 * thread — a StrongBox keygen is not something to run inside `configure()`.
 */
public interface DpopKeyBinding {

    /**
     * RFC 7638 JWK thumbprint of the public key, base64url, unpadded.
     *
     * Sent as `dpop_jkt` on the authorization request (RFC 9449 §10) and carried by the token
     * the code is redeemed for as `cnf.jkt`.
     */
    public suspend fun jkt(): String
}

/**
 * Proofs, as far as the protocol core needs them: the second half of the seam
 * [DpopKeyBinding] opens.
 *
 * Separate from the key because a proof is not only a signature — it carries the nonce the
 * server last issued for this origin and an `iat` corrected for the server's clock, neither of
 * which belongs to a key. `:dpop` owns both caches; this module owns *when* a proof goes on
 * the wire and what a challenge to one means.
 */
public interface DpopProofSource {

    /**
     * A proof for one request.
     *
     * @param accessToken adds the RFC 9449 §4.2 `ath` binding. Absent at the token endpoint,
     *   which has no token yet to hash.
     */
    public suspend fun proof(method: String, url: String, accessToken: String? = null): String

    /**
     * Hands back what a response says about the server's clock and its nonce. Called for
     * every response, not only for challenges: the `Date` header on a success is the cheapest
     * place to learn the offset.
     */
    public fun observe(url: String, dateHeader: String?, nonceHeader: String?)
}

/**
 * The `Date` of a response, for [DpopProofSource.observe], unless it cannot be the server's clock
 * now: a response with an `Age` other than `0` was generated earlier and handed back by a cache or
 * a proxy (RFC 9111 section 5.1), so its `Date` is when the origin produced it, and learning it
 * would move the offset by the age of the response. Null then, which `observe` reads as "says
 * nothing about the clock either way" and leaves what was learned in place.
 */
@VersolaInternalApi
public fun Headers.dateForClockSkew(): String? {
    val age = this["Age"]?.trim()
    return if (age != null && age != "0") null else this["Date"]
}
