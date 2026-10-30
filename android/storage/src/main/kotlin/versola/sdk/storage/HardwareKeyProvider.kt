package versola.sdk.storage

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import versola.oauth.core.CredentialKeyProvider
import versola.oauth.core.UnlockPolicy
import versola.oauth.core.VersolaError

/**
 * AES-256-GCM with the key held in the Android Keystore, non-exportable.
 *
 * Deliberately **not** `EncryptedSharedPreferences`: `androidx.security:security-crypto` was
 * deprecated at 1.1.0 with no further releases, and brought main-thread violations and
 * keyset-corruption crashes on some OEMs. Managing one Keystore key directly means no Tink
 * dependency and no keyset file to corrupt.
 *
 * Gating is [UnlockPolicy]'s decision, and it is time-bound rather than per-operation: under
 * [UnlockPolicy.OnAppUnlock] the key is authorized for
 * [UnlockPolicy.UNLOCK_WINDOW_SECONDS] after any matching OS authentication, so the device
 * unlock that preceded the app opening usually covers the session. Per-operation binding would
 * mean a prompt per token request, which `spec/state-machine.md` rules out. #19 adds the
 * PIN-derived provider behind the same interface.
 *
 * The default is [UnlockPolicy.None]: encryption at rest and user authentication are different
 * mechanisms (#1 §4), and only the latter stops a refresh in the background.
 *
 * A key the Keystore reports permanently invalidated (a biometric or lock-screen change under
 * [UnlockPolicy.OnAppUnlock]) is deleted when it is found, and the next wrap generates a new
 * one. What the old key wrapped is unreadable either way; leaving the dead entry in place
 * would fail every later wrap and lock the app out of `login()` until its data is cleared.
 *
 * Nothing here caches plaintext. Callers unwrap inside the request that consumes the value and
 * zero the buffer afterwards.
 */
public class HardwareKeyProvider(
    alias: String = DEFAULT_ALIAS,
    unlockPolicy: UnlockPolicy = UnlockPolicy.None,
) : CredentialKeyProvider {

    private val wrapping = KeyWrapping(KeystoreStorageKeys(alias, unlockPolicy))

    override suspend fun wrap(plaintext: ByteArray): ByteArray = wrapping.wrap(plaintext)

    override suspend fun unwrap(blob: ByteArray): ByteArray = wrapping.unwrap(blob)

    public companion object {
        /** Distinct from the DPoP key's alias: two keys, two purposes, one knob (#1 §4). */
        public const val DEFAULT_ALIAS: String = "versola.storage-key"

        /**
         * Separated from key generation so the authentication parameters can be asserted
         * without an Android Keystore, which no JVM test has.
         *
         * Under [UnlockPolicy.OnAppUnlock] this is a window, not a per-operation binding:
         * `setUserAuthenticationParameters(0, …)` would demand a fresh prompt for every token
         * request. The deprecated setter is the only way to express the same window below
         * API 30, which the API 26 floor still includes.
         */
        internal fun keySpec(alias: String, unlockPolicy: UnlockPolicy): KeyGenParameterSpec =
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .apply {
                    if (unlockPolicy == UnlockPolicy.OnAppUnlock) {
                        setUserAuthenticationRequired(true)
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                            setUserAuthenticationParameters(
                                UnlockPolicy.UNLOCK_WINDOW_SECONDS,
                                KeyProperties.AUTH_BIOMETRIC_STRONG or
                                    KeyProperties.AUTH_DEVICE_CREDENTIAL,
                            )
                        } else {
                            @Suppress("DEPRECATION")
                            setUserAuthenticationValidityDurationSeconds(
                                UnlockPolicy.UNLOCK_WINDOW_SECONDS,
                            )
                        }
                    }
                }
                .build()

    }
}

/**
 * What [HardwareKeyProvider] does with the key and its failures, over [StorageKeys] so that a
 * JVM test can run it without a Keystore.
 */
internal class KeyWrapping(
    private val keys: StorageKeys,
) : CredentialKeyProvider {

    override suspend fun wrap(plaintext: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        translatingKeyFailures {
            try {
                encrypt(plaintext)
            } catch (e: KeyPermanentlyInvalidatedException) {
                // Everything the old key wrapped is unreadable already, so replacing it costs
                // nothing and is the only way a `login()` after an enrolment change can store
                // its grant at all: left in place, the invalidated entry fails every later
                // wrap and the app is locked out until its data is cleared.
                keys.discard()
                encrypt(plaintext)
            }
        }
    }

    override suspend fun unwrap(blob: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        // Too short to hold an IV and a tag: it can never authenticate, which is what a
        // GCM tag failure says, and the store reads that as a ciphertext that is gone for good.
        if (blob.size < IV_LENGTH + TAG_LENGTH_BITS / 8) {
            throw AEADBadTagException("wrapped blob is too short to carry an IV and a tag")
        }
        translatingKeyFailures {
            val cipher = keys.decryptor(GCMParameterSpec(TAG_LENGTH_BITS, blob, 0, IV_LENGTH))
            cipher.doFinal(blob, IV_LENGTH, blob.size - IV_LENGTH)
        }
    }

    private fun encrypt(plaintext: ByteArray): ByteArray {
        val cipher = keys.encryptor()
        // The IV is generated by the Keystore, never by us — setRandomizedEncryptionRequired
        // refuses a caller-supplied one precisely so a nonce cannot be reused under one key.
        return cipher.iv + cipher.doFinal(plaintext)
    }

    /**
     * The two Keystore failures that are session conditions rather than crypto faults, mapped
     * to the categories `spec/errors.md` assigns them. Anything else propagates for the store
     * to sort ([StorageFailure]): a caller that cannot decrypt for an unmodelled reason
     * should not have it dressed up as a lock.
     *
     * One process-wide lock around the whole operation, discard and regeneration included:
     * two callers that both found the key invalidated must not each delete the key the other
     * just generated, which would strand what the second one wrapped.
     */
    private inline fun <T> translatingKeyFailures(block: () -> T): T = try {
        synchronized(KEY_LOCK) {
            try {
                block()
            } catch (e: KeyPermanentlyInvalidatedException) {
                // The dead entry goes now, under the lock, so that the next wrap generates a
                // usable key instead of failing on this one again.
                keys.discard()
                throw e
            }
        }
    } catch (e: UserNotAuthenticatedException) {
        throw VersolaError.Recoverable(VersolaError.Recoverable.Cause.UnlockRequired, e)
    } catch (e: KeyPermanentlyInvalidatedException) {
        // An enrolment change is indistinguishable from tampering, so this is a sign-out and
        // not a retry. The wrapped blob is gone for good: a new key cannot read the old one.
        throw VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.CredentialsInvalidated)
    }

    private companion object {
        val KEY_LOCK = Any()
        const val IV_LENGTH = 12
        const val TAG_LENGTH_BITS = 128
    }
}


/**
 * The storage key as [HardwareKeyProvider] uses it: ciphers on the current key, and the key's
 * deletion. A seam only because the Android Keystore has no JVM implementation.
 */
internal interface StorageKeys {
    /** A cipher ready to encrypt, on the existing key or a newly generated one. */
    fun encryptor(): Cipher

    /** A cipher ready to decrypt a blob written with [parameters]'s IV. */
    fun decryptor(parameters: GCMParameterSpec): Cipher

    /** Deletes the key; the next [encryptor] generates a new one. */
    fun discard()
}

internal class KeystoreStorageKeys(
    private val alias: String,
    private val unlockPolicy: UnlockPolicy,
) : StorageKeys {

    override fun encryptor(): Cipher =
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key()) }

    override fun decryptor(parameters: GCMParameterSpec): Cipher =
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.DECRYPT_MODE, key(), parameters) }

    override fun discard() {
        KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(alias)
    }

    private fun key(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(HardwareKeyProvider.keySpec(alias, unlockPolicy))
        return generator.generateKey()
    }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
