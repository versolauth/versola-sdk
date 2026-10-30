package versola.sdk.dpop

import java.security.InvalidKeyException
import java.security.ProviderException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import versola.oauth.core.VersolaLogger

/**
 * Key generation needs a Keystore, which no JVM has; what can be proved here is the decision
 * about which failures of the StrongBox attempt lead to a TEE attempt. The Keystore itself
 * raises `StrongBoxUnavailableException` (a `ProviderException`) only for the one error code
 * "hardware type unavailable"; every other error of a StrongBox that is present but
 * misbehaving comes out of `generateKeyPair` as a plain `ProviderException`
 * (`AndroidKeyStoreKeyPairGeneratorSpi.generateKeyPair`), and used to break login outright.
 */
class StrongBoxFallbackTest {

    private val logs = mutableListOf<String>()
    private val logger = object : VersolaLogger {
        override fun info(message: String) {
            logs += "info: $message"
        }

        override fun warn(message: String) {
            logs += "warn: $message"
        }
    }

    @Test
    fun `StrongBox that works is used and the TEE is not asked`() {
        val asked = mutableListOf<Boolean>()

        val result = withStrongBoxFallback(logger) { strongBox -> asked += strongBox; "key" }

        assertEquals("key", result)
        assertEquals(listOf(true), asked)
        assertTrue(logs.isEmpty())
    }

    @Test
    fun `a transient provider fault from StrongBox is retried once and StrongBox is kept`() {
        val asked = mutableListOf<Boolean>()

        val result = withStrongBoxFallback(logger) { strongBox ->
            asked += strongBox
            if (asked.size == 1) throw ProviderException("Failed to generate key pair.") else "strongbox key"
        }

        assertEquals("strongbox key", result)
        assertEquals("the key keeps its tier: the TEE is never asked", listOf(true, true), asked)
        assertTrue(logs.single(), logs.single().startsWith("info: StrongBox key generation failed (ProviderException), retrying once"))
    }

    @Test
    fun `a provider fault that persists falls back to the TEE after the retry`() {
        val asked = mutableListOf<Boolean>()

        val result = withStrongBoxFallback(logger) { strongBox ->
            asked += strongBox
            if (strongBox) throw ProviderException("Failed to generate key pair.") else "tee key"
        }

        assertEquals("tee key", result)
        assertEquals(listOf(true, true, false), asked)
        assertTrue(logs.last(), logs.last().startsWith("info: StrongBox unavailable (ProviderException), falling back to the TEE"))
    }

    @Test
    fun `an absent StrongBox falls back at once, with no retry`() {
        // StrongBoxUnavailableException is the absent case and cannot be constructed on a JVM.
        class StrongBoxLike(message: String) : ProviderException(message)
        val asked = mutableListOf<Boolean>()

        val result = withStrongBoxFallback(logger, isAbsent = { it is StrongBoxLike }) { strongBox ->
            asked += strongBox
            if (strongBox) throw StrongBoxLike("No StrongBox available") else "tee key"
        }

        assertEquals("tee key", result)
        assertEquals(listOf(true, false), asked)
        assertTrue(logs.single().contains("StrongBoxLike"))
    }

    @Test
    fun `a failure of the TEE attempt is the caller's, not swallowed`() {
        val failure = ProviderException("the TEE failed too")

        try {
            withStrongBoxFallback(logger) { strongBox ->
                if (strongBox) throw ProviderException("no StrongBox") else throw failure
            }
            fail("the second failure must propagate")
        } catch (e: ProviderException) {
            assertSame(failure, e)
        }
    }

    @Test
    fun `a failure that is not a provider fault is not read as a missing StrongBox`() {
        val asked = mutableListOf<Boolean>()

        try {
            withStrongBoxFallback(logger) { strongBox ->
                asked += strongBox
                throw InvalidKeyException("something else")
            }
            fail("only a provider fault falls back")
        } catch (e: InvalidKeyException) {
            // propagates
        }

        assertEquals(listOf(true), asked)
    }

    @Test
    fun `without a logger the fallback is silent`() {
        val result = withStrongBoxFallback(null) { strongBox ->
            if (strongBox) throw ProviderException("no StrongBox") else "tee key"
        }

        assertEquals("tee key", result)
    }
}
