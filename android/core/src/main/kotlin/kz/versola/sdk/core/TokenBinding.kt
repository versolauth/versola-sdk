package kz.versola.sdk.core

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
