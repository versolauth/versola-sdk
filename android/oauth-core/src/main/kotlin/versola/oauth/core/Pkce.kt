package versola.oauth.core

import java.security.MessageDigest
import java.security.SecureRandom

/**
 * RFC 7636 PKCE. S256 always: the server has no opt-out — `AuthorizeRequestParser` fails a
 * request with `CodeChallengeMissing`, and accepts no `code_challenge_method` but `S256`
 * (#1 §2). There is deliberately no way to express `plain` or "no PKCE" here.
 */
public class CodeVerifier @VersolaInternalApi public constructor(internal val value: String) {

    /**
     * The `code_challenge`: base64url(SHA-256(ASCII(code_verifier))), per RFC 7636 §4.2.
     */
    public fun challengeS256(): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.US_ASCII))
        return Base64Url.encode(digest)
    }

    /** Credential material: never printed, including through an accidental string template. */
    override fun toString(): String = "CodeVerifier(redacted)"

    public companion object {
        /**
         * 32 bytes of CSPRNG output, base64url-encoded to 43 characters — the shortest
         * verifier RFC 7636 §4.1 permits, and 256 bits of entropy.
         */
        internal fun generate(random: SecureRandom = SecureRandom()): CodeVerifier =
            CodeVerifier(SecureTokens.generate(random))
    }
}

/**
 * `state` and `nonce`, and the comparison the redirect is validated with.
 */
internal object SecureTokens {

    /**
     * 32 bytes of CSPRNG output as 43 base64url characters. Well above the 128-bit floor
     * scenario 01 asserts, and well under the server's 128-character `state` limit
     * (`AuthorizeRequestParser.MaxStateLength`, which exists so `state` cannot push the
     * conversation cookie past the browser's 4 KiB limit).
     */
    fun generate(random: SecureRandom = SecureRandom()): String {
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return Base64Url.encode(bytes)
    }

    /**
     * Constant-time comparison. Written out rather than delegated to `MessageDigest.isEqual`
     * so the length difference is folded into the accumulator instead of short-circuiting:
     * a comparison that returns early on the first differing byte leaks the length of the
     * matching prefix to anything that can time it.
     */
    fun constantTimeEquals(expected: String, actual: String): Boolean {
        val a = expected.toByteArray(Charsets.UTF_8)
        val b = actual.toByteArray(Charsets.UTF_8)
        // Index into b modulo its length so the loop runs over all of a whatever the lengths
        // are; the mismatch is already recorded in `difference` and cannot be cancelled out.
        // The substitute keeps an empty b from indexing out of bounds, which would turn a
        // comparison against an absent value into a crash.
        val probe = if (b.isEmpty()) ByteArray(1) else b
        var difference = a.size xor b.size
        for (i in a.indices) {
            difference = difference or (a[i].toInt() xor probe[i % probe.size].toInt())
        }
        return difference == 0
    }
}
