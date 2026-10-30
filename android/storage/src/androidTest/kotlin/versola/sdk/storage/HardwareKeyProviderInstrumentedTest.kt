package versola.sdk.storage

import android.app.KeyguardManager
import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.KeyStore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.test.runTest
import versola.oauth.core.UnlockPolicy
import versola.oauth.core.VersolaError
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assume.assumeFalse
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * #30: `HardwareKeyProvider` against a real Android Keystore rather than a hand-thrown
 * exception. What an emulator can prove: the key is generated and usable under
 * `UnlockPolicy.None`, every wrap gets its own IV, a tampered blob does not unwrap, and the
 * credential store round-trips through the real key. What it cannot: an elapsed window
 * (needs a secure lock screen and a clock the Keystore honours) and an enrolment change, both
 * of which stay physical-device work and are called out rather than faked.
 */
@RunWith(AndroidJUnit4::class)
class HardwareKeyProviderInstrumentedTest {

    private val alias = "versola.test.storage-key"
    private val context: Context = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    @After
    fun clean() {
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)
    }

    @Test
    fun wrapAndUnwrapRoundTripThroughTheKeystoreKey() = runTest {
        val provider = HardwareKeyProvider(alias)
        val plaintext = "8xLOxBtZp8-refresh-token-value".toByteArray()

        val wrapped = provider.wrap(plaintext.copyOf())

        assertFalse(wrapped.contentEquals(plaintext))
        assertArrayEquals(plaintext, provider.unwrap(wrapped))
        // The key the provider generated is in the Keystore, as a secret key, non-exportable.
        val entry = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getEntry(alias, null)
        assertTrue(entry is KeyStore.SecretKeyEntry)
        assertNull((entry as KeyStore.SecretKeyEntry).secretKey.encoded)
    }

    @Test
    fun everyWrapGetsAFreshIvFromTheKeystore() = runTest {
        val provider = HardwareKeyProvider(alias)
        val plaintext = "same".toByteArray()

        val first = provider.wrap(plaintext.copyOf())
        val second = provider.wrap(plaintext.copyOf())

        // setRandomizedEncryptionRequired: the Keystore picks the IV, and never the same one
        // twice under one key — a reused GCM nonce is the one thing that breaks the mode.
        assertFalse(first.copyOfRange(0, 12).contentEquals(second.copyOfRange(0, 12)))
        assertFalse(first.contentEquals(second))
    }

    @Test
    fun aTamperedBlobDoesNotUnwrapAndIsNotDressedUpAsALock() = runTest {
        val provider = HardwareKeyProvider(alias)
        val wrapped = provider.wrap("secret".toByteArray())
        wrapped[wrapped.size - 1] = (wrapped.last().toInt() xor 0x01).toByte()

        try {
            provider.unwrap(wrapped)
            fail("a tampered GCM blob must not unwrap")
        } catch (e: VersolaError) {
            fail("tampering is not UnlockRequired or CredentialsInvalidated at this layer; the store maps it: $e")
        } catch (e: Exception) {
            // AEADBadTagException, left for DataStoreCredentialStore to read as a sign-out.
        }
    }

    @Test
    fun aSecondProviderOverTheSameAliasReadsWhatTheFirstWrote() = runTest {
        val wrapped = HardwareKeyProvider(alias).wrap("across-processes".toByteArray())

        assertArrayEquals("across-processes".toByteArray(), HardwareKeyProvider(alias).unwrap(wrapped))
    }

    @Test
    fun theCredentialStoreRoundTripsThroughTheRealKey() = runTest {
        val file = File(context.noBackupFilesDir, "versola-test-credentials-${System.nanoTime()}")
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        try {
            val store = DataStoreCredentialStore(file, HardwareKeyProvider(alias), scope)
            store.save("the-refresh-token".toByteArray(), "the.id.token")
            store.savePendingRotation("idem-1")

            assertTrue(store.hasGrant())
            assertEquals("the-refresh-token", store.useRefreshToken { String(it) })
            assertEquals("the.id.token", store.rawIdToken())
            assertEquals("idem-1", store.pendingRotation())
            // Nothing on disk is the plaintext.
            assertFalse(String(file.readBytes(), Charsets.ISO_8859_1).contains("the-refresh-token"))

            store.clear()
            assertFalse(store.hasGrant())
        } finally {
            scope.cancel()
            file.delete()
        }
    }

    @Test
    fun aGrantWrittenBeforeRecordBindingStillOpensThroughTheRealKey() = runTest {
        // What 0.1.0 wrote: the provider's blob over the bare secret, no slot name inside.
        val provider = HardwareKeyProvider(alias)
        val file = File(context.noBackupFilesDir, "versola-test-legacy-${System.nanoTime()}")
        val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        try {
            file.writeBytes(
                CredentialBlob(
                    refreshToken = provider.wrap("legacy-refresh-token".toByteArray()),
                    rawIdToken = provider.wrap("legacy.id.token".toByteArray()),
                ).encode(),
            )
            val store = DataStoreCredentialStore(file, HardwareKeyProvider(alias), scope)

            assertEquals("legacy-refresh-token", store.useRefreshToken { String(it) })
            assertEquals("legacy.id.token", store.rawIdToken())

            // The next save writes the bound form, and it reads back through the same key.
            store.save("rotated-refresh-token".toByteArray(), null)
            assertEquals("rotated-refresh-token", store.useRefreshToken { String(it) })
            assertEquals("legacy.id.token", store.rawIdToken())
        } finally {
            scope.cancel()
            file.delete()
        }
    }

    @Test
    fun onAppUnlockNeedsASecureLockScreenToGenerateAtAll() = runTest {
        // Without a lock screen the Keystore refuses a user-authentication-gated key outright,
        // which is the right failure: a policy that cannot be enforced must not degrade to
        // one that is not. With one, generation succeeds and the window starts with the
        // unlock that preceded the test — the elapsed-window case needs a physical device.
        val keyguard = context.getSystemService(KeyguardManager::class.java)
        assumeFalse("a secure lock screen is set; the refusal path is not reachable here", keyguard.isDeviceSecure)

        try {
            HardwareKeyProvider(alias, UnlockPolicy.OnAppUnlock).wrap("x".toByteArray())
            fail("expected the Keystore to refuse an authentication-gated key without a lock screen")
        } catch (e: VersolaError) {
            fail("the refusal is a configuration fact about the device, not a session condition: $e")
        } catch (e: Exception) {
            // InvalidAlgorithmParameterException / IllegalStateException from the Keystore.
        }
    }
}
