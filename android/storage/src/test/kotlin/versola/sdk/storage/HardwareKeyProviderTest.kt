package versola.sdk.storage

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import java.security.ProviderException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.test.runTest
import versola.oauth.core.UnlockPolicy
import versola.oauth.core.VersolaError
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The key's authentication parameters, which decide how often a user sees a prompt. The
 * Keystore has no JVM implementation, so generation itself is out of reach here; what the key
 * is *asked* for is not, and that is where the policy decision lives.
 */
@RunWith(RobolectricTestRunner::class)
class HardwareKeyProviderTest {

    @Test
    fun `default policy does not gate the key`() {
        val spec = HardwareKeyProvider.keySpec("alias", UnlockPolicy.None)

        assertFalse(spec.isUserAuthenticationRequired)
    }

    @Test
    fun `OnAppUnlock gates the key for a window rather than per operation`() {
        val spec = HardwareKeyProvider.keySpec("alias", UnlockPolicy.OnAppUnlock)

        assertTrue(spec.isUserAuthenticationRequired)
        // Zero would mean auth-per-use: a prompt for every token request.
        assertEquals(300, spec.userAuthenticationValidityDurationSeconds)
        assertEquals(
            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
            spec.userAuthenticationType,
        )
    }

    @Test
    @Config(sdk = [29])
    fun `the same window is expressed below API 30`() {
        val spec = HardwareKeyProvider.keySpec("alias", UnlockPolicy.OnAppUnlock)

        assertTrue(spec.isUserAuthenticationRequired)
        assertEquals(300, spec.userAuthenticationValidityDurationSeconds)
    }

    @Test
    fun `the window matches the cross-platform constant`() {
        // iOS cannot exceed 300s; a divergence here would be two machines, not one.
        assertEquals(
            UnlockPolicy.UNLOCK_WINDOW_SECONDS,
            HardwareKeyProvider.keySpec("alias", UnlockPolicy.OnAppUnlock)
                .userAuthenticationValidityDurationSeconds,
        )
    }

    // What the provider does with the key's life, against a stand-in for the Keystore: a plain
    // JCE AES key that fails the way the Keystore documents once it is marked invalidated.

    @Test
    fun `a wrapped blob round trips`() = runTest {
        val provider = KeyWrapping(FakeStorageKeys())

        val wrapped = provider.wrap("refresh-token".toByteArray())

        assertArrayEquals("refresh-token".toByteArray(), provider.unwrap(wrapped))
    }

    @Test
    fun `wrapping after the key was invalidated replaces it, so a later login can store its grant`() = runTest {
        val keys = FakeStorageKeys()
        val provider = KeyWrapping(keys)
        val old = provider.wrap("old-grant".toByteArray())
        keys.invalidate()

        val fresh = provider.wrap("new-grant".toByteArray())

        assertEquals("the invalidated entry was deleted once", 1, keys.discards)
        assertArrayEquals("new-grant".toByteArray(), provider.unwrap(fresh))
        // What the old key wrapped is gone, and says so as a ciphertext that does not verify.
        try {
            provider.unwrap(old)
            fail("a blob of the invalidated key must not open under its replacement")
        } catch (e: AEADBadTagException) {
            // the store reads this as a sign-out
        }
    }

    @Test
    fun `unwrapping with an invalidated key is a sign-out and deletes the dead entry`() = runTest {
        val keys = FakeStorageKeys()
        val provider = KeyWrapping(keys)
        val wrapped = provider.wrap("grant".toByteArray())
        keys.invalidate()

        try {
            provider.unwrap(wrapped)
            fail("an invalidated key must not unwrap")
        } catch (e: VersolaError.Reauthenticate) {
            assertSame(VersolaError.Reauthenticate.Reason.CredentialsInvalidated, e.reason)
        }

        assertEquals(1, keys.discards)
        // The bricked-login case: the next wrap works without anyone clearing app data.
        assertArrayEquals("again".toByteArray(), provider.unwrap(provider.wrap("again".toByteArray())))
    }

    @Test
    fun `a key whose window elapsed is UnlockRequired and is not deleted`() = runTest {
        val keys = FakeStorageKeys()
        val provider = KeyWrapping(keys)
        val wrapped = provider.wrap("grant".toByteArray())
        keys.lock(UserNotAuthenticatedException("the window elapsed"))

        try {
            provider.unwrap(wrapped)
            fail("a locked key must not unwrap")
        } catch (e: VersolaError.Recoverable) {
            assertSame(VersolaError.Recoverable.Cause.UnlockRequired, e.reason)
        }

        assertEquals("a locked key is intact", 0, keys.discards)
        keys.lock(null)
        assertArrayEquals("grant".toByteArray(), provider.unwrap(wrapped))
    }

    @Test
    fun `a keystore fault is not a verdict and the key is left alone`() = runTest {
        val keys = FakeStorageKeys()
        val provider = KeyWrapping(keys)
        val wrapped = provider.wrap("grant".toByteArray())
        keys.lock(ProviderException("keystore service died"))

        val onUnwrap = runCatching { provider.unwrap(wrapped) }.exceptionOrNull()
        val onWrap = runCatching { provider.wrap("x".toByteArray()) }.exceptionOrNull()

        assertTrue("$onUnwrap", onUnwrap is ProviderException)
        assertTrue("$onWrap", onWrap is ProviderException)
        assertEquals(0, keys.discards)
    }

    @Test
    fun `a blob too short to hold an IV and a tag is a ciphertext that cannot verify`() = runTest {
        val provider = KeyWrapping(FakeStorageKeys())

        for (size in listOf(0, 1, 12, 27)) {
            try {
                provider.unwrap(ByteArray(size))
                fail("$size bytes cannot be a wrapped blob")
            } catch (e: AEADBadTagException) {
                // the store reads this as a sign-out
            }
        }
    }

    /**
     * AES-GCM from the JCE on a key held in memory. [invalidate] and [lock] stand in for what
     * `Cipher.init` throws on a Keystore key; [discard] counts deletions and brings a new key.
     */
    private class FakeStorageKeys : StorageKeys {
        private var key: SecretKey = newKey()
        private var invalidated = false
        private var failure: Exception? = null
        var discards = 0
            private set

        fun invalidate() {
            invalidated = true
        }

        fun lock(failure: Exception?) {
            this.failure = failure
        }

        override fun encryptor(): Cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            check()
            init(Cipher.ENCRYPT_MODE, key)
        }

        override fun decryptor(parameters: GCMParameterSpec): Cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
            check()
            init(Cipher.DECRYPT_MODE, key, parameters)
        }

        override fun discard() {
            discards++
            key = newKey()
            invalidated = false
        }

        private fun check() {
            failure?.let { throw it }
            if (invalidated) throw KeyPermanentlyInvalidatedException("lock screen changed")
        }

        private fun newKey(): SecretKey = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    }
}
