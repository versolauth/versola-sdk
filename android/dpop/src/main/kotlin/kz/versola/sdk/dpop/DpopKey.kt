package kz.versola.sdk.dpop

import kz.versola.sdk.core.DpopKeyBinding

/**
 * Where the private key actually lives, discovered at runtime rather than assumed at compile
 * time — which is why the SDK's floor is API 26 and not the API 28 StrongBox needs.
 *
 * Surfaced so an app with a real possession requirement can assert on it, and so
 * `TokenBinding.Dpop(requireHardware = true)` has something to fail against.
 */
public enum class KeyAttestation {

    /** A separate tamper-resistant chip. Strongest, API 28+, and present on a minority of devices. */
    StrongBox,

    /** The processor's trusted execution environment. The common case on modern Android. */
    TrustedEnvironment,

    /**
     * Keystore held the key in software. The key is still not handed out by the Keystore API,
     * but nothing below the OS protects it, so a rooted device can reach it.
     */
    Software,

    ;

    /** What `requireHardware` is asking about. */
    public val isHardwareBacked: Boolean get() = this != Software
}

/**
 * The client half of RFC 9449: one key pair, and the proofs [DpopProofFactory] signs with it.
 *
 * One key for the whole installation, not one per request — that is the mechanism's entire
 * point. The key a token is bound to at the token endpoint is the key that has to prove
 * possession at every resource server afterwards.
 *
 * Suspending throughout because the real implementation reaches the Android Keystore, and a
 * StrongBox keygen on the main thread is a visible stall.
 */
public interface DpopKey : DpopKeyBinding {

    /** The public key in RFC 7638 canonical form, embedded verbatim in every proof header. */
    public suspend fun publicJwk(): String

    /** Which tier the key generation actually achieved. */
    public suspend fun attestation(): KeyAttestation

    /** Signs the JWS signing input, returning the fixed-width `R‖S` form (RFC 7515 §A.3). */
    public suspend fun sign(signingInput: ByteArray): ByteArray
}
