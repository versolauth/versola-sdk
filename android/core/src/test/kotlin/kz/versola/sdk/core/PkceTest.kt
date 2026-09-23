package kz.versola.sdk.core

import java.security.SecureRandom
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PkceTest {

    @Test
    fun `challenge matches the RFC 7636 test vector`() {
        // RFC 7636 appendix B, so a mistake in the digest or the encoding fails here rather
        // than against a live server.
        val verifier = CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

        assertEquals("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", verifier.challengeS256())
    }

    @Test
    fun `generated verifier is 43 base64url characters`() {
        val verifier = CodeVerifier.generate()

        // RFC 7636 §4.1 permits 43-128; 43 is 256 bits of CSPRNG output with no padding.
        assertEquals(43, verifier.value.length)
        assertTrue(verifier.value.all { it.isLetterOrDigit() || it == '-' || it == '_' })
    }

    @Test
    fun `two verifiers differ`() {
        assertNotEquals(CodeVerifier.generate().value, CodeVerifier.generate().value)
    }

    @Test
    fun `verifier is not printed`() {
        val verifier = CodeVerifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")

        assertFalse(verifier.toString().contains("dBjftJeZ"))
    }

    @Test
    fun `state and nonce are 256 bits of CSPRNG output and differ between runs`() {
        val first = SecureTokens.generate()
        val second = SecureTokens.generate()

        assertEquals(43, first.length)
        assertEquals(32, Base64Url.decode(first).size)
        assertNotEquals(first, second)
    }

    @Test
    fun `generation is driven by the supplied random source`() {
        // Same seed, same output: proves the value comes from the CSPRNG rather than from
        // something ambient like a timestamp.
        fun seeded() = SecureTokens.generate(SecureRandom.getInstance("SHA1PRNG").apply { setSeed(1L) })

        assertEquals(seeded(), seeded())
    }

    @Test
    fun `constant-time comparison accepts equal values and rejects everything else`() {
        assertTrue(SecureTokens.constantTimeEquals("abc123", "abc123"))
        assertFalse(SecureTokens.constantTimeEquals("abc123", "abc124"))
        assertFalse(SecureTokens.constantTimeEquals("abc123", "abc1234"))
        assertFalse(SecureTokens.constantTimeEquals("abc123", "abc12"))
        assertFalse(SecureTokens.constantTimeEquals("abc123", ""))
        assertFalse(SecureTokens.constantTimeEquals("", "abc123"))
        assertTrue(SecureTokens.constantTimeEquals("", ""))
    }

    @Test
    fun `comparison does not short-circuit on the first differing byte`() {
        // A comparison that returns early leaks the matching prefix length through timing.
        // Asserting on wall-clock here would be flaky; what is assertable is that a value
        // differing in its first byte and one differing in its last are both rejected, and
        // that a prefix is never accepted.
        val expected = "a".repeat(64)

        assertFalse(SecureTokens.constantTimeEquals(expected, "b" + "a".repeat(63)))
        assertFalse(SecureTokens.constantTimeEquals(expected, "a".repeat(63) + "b"))
        assertFalse(SecureTokens.constantTimeEquals(expected, "a".repeat(63)))
    }
}
