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
    fun `a provider fault from StrongBox falls back to the TEE`() {
        val asked = mutableListOf<Boolean>()

        val result = withStrongBoxFallback(logger) { strongBox ->
            asked += strongBox
            if (strongBox) throw ProviderException("Failed to generate key pair.") else "tee key"
        }

        assertEquals("tee key", result)
        assertEquals(listOf(true, false), asked)
        assertEquals(1, logs.size)
        assertTrue(logs.single(), logs.single().startsWith("info: StrongBox unavailable (ProviderException), falling back to the TEE"))
    }

    @Test
    fun `a subclass of the provider fault falls back the same way`() {
        // StrongBoxUnavailableException is one, and cannot be constructed on a JVM.
        class StrongBoxLike(message: String) : ProviderException(message)

        val result = withStrongBoxFallback(logger) { strongBox ->
            if (strongBox) throw StrongBoxLike("No StrongBox available") else "tee key"
        }

        assertEquals("tee key", result)
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
