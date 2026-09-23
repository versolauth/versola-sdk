package kz.versola.sdk.storage

import androidx.datastore.core.DataStore
import androidx.datastore.core.DataStoreFactory
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kz.versola.sdk.core.CredentialKeyProvider
import kz.versola.sdk.core.CredentialStore
import kz.versola.sdk.core.VersolaError

/**
 * The grant on disk, wrapped by a [CredentialKeyProvider] and written through DataStore.
 *
 * DataStore rather than `EncryptedSharedPreferences`: `androidx.security:security-crypto` was
 * deprecated at 1.1.0 with no further releases, and its keyset file is a second thing that can
 * corrupt (#7). The key here is a Keystore key this SDK manages directly, so there is no
 * keyset. DataStore rather than the plain file [FilePendingAuthorizationStore] uses, because
 * this file has several fields written from several places — the token exchange, the rotation
 * slot, logout — and `updateData` serialises them onto one consistent view.
 *
 * **One instance per [file] per process.** That is DataStore's own constraint, not this
 * class's; a second instance over the same file corrupts both. Construct it where the rest of
 * the SDK's singletons are constructed.
 *
 * Callers should place [file] under `Context.noBackupFilesDir`. A refresh token restored onto
 * a different device from a cloud backup cannot be unwrapped there — the Keystore key does not
 * travel — so backing it up trades a silent sign-out for nothing.
 */
public class DataStoreCredentialStore(
    file: File,
    private val keyProvider: CredentialKeyProvider,
    scope: CoroutineScope = CoroutineScope(Dispatchers.IO + SupervisorJob()),
) : CredentialStore {

    private val dataStore: DataStore<CredentialBlob> = DataStoreFactory.create(
        serializer = CredentialBlobSerializer,
        // A file that will not parse is replaced rather than thrown from forever. The app
        // sees no grant and sends the user through login(), which is where an unreadable
        // grant ends regardless.
        corruptionHandler = ReplaceFileCorruptionHandler { CredentialBlob.EMPTY },
        scope = scope,
        produceFile = { file },
    )

    override suspend fun save(refreshToken: ByteArray, rawIdToken: String?) {
        // `keyProvider.wrap` can throw — a locked key above all — and `save`'s contract is
        // that it takes ownership of `refreshToken` regardless of outcome. Zeroing has to run
        // whether or not the wrap succeeded, or a failed save leaves the caller's buffer
        // readable for as long as whatever holds the reference keeps holding it.
        val wrappedToken = try {
            keyProvider.wrap(refreshToken)
        } finally {
            refreshToken.fill(0)
        }
        val wrappedIdToken = rawIdToken?.let { keyProvider.wrap(it.toByteArray(Charsets.UTF_8)) }

        dataStore.updateData { current ->
            CredentialBlob(
                refreshToken = wrappedToken,
                rawIdToken = wrappedIdToken ?: current.rawIdToken,
                pendingRotation = current.pendingRotation,
            )
        }
    }

    override suspend fun <T> useRefreshToken(block: suspend (ByteArray) -> T): T? {
        val wrapped = dataStore.data.first().refreshToken ?: return null
        val plaintext = unwrapping(wrapped)
        return try {
            block(plaintext)
        } finally {
            plaintext.fill(0)
        }
    }

    override suspend fun hasGrant(): Boolean = dataStore.data.first().refreshToken != null

    override suspend fun rawIdToken(): String? {
        val wrapped = dataStore.data.first().rawIdToken ?: return null
        return unwrapping(wrapped).toString(Charsets.UTF_8)
    }

    override suspend fun savePendingRotation(idempotencyKey: String?) {
        val wrapped = idempotencyKey?.let { keyProvider.wrap(it.toByteArray(Charsets.UTF_8)) }
        dataStore.updateData { current ->
            CredentialBlob(
                refreshToken = current.refreshToken,
                rawIdToken = current.rawIdToken,
                pendingRotation = wrapped,
            )
        }
    }

    override suspend fun pendingRotation(): String? {
        val wrapped = dataStore.data.first().pendingRotation ?: return null
        return unwrapping(wrapped).toString(Charsets.UTF_8)
    }

    override suspend fun clear() {
        dataStore.updateData { CredentialBlob.EMPTY }
    }

    /**
     * A [VersolaError] from the provider is already the right answer and passes through —
     * `UnlockRequired` above all, which is a grant out of reach rather than a grant gone.
     * Anything else means these bytes will not open again: an enrolment change invalidated
     * the key, or the ciphertext was altered, and `spec/errors.md` treats both as a sign-out
     * because they cannot be told apart.
     */
    private suspend fun unwrapping(wrapped: ByteArray): ByteArray = try {
        keyProvider.unwrap(wrapped)
    } catch (e: VersolaError) {
        throw e
    } catch (e: Exception) {
        throw VersolaError.Reauthenticate(
            VersolaError.Reauthenticate.Reason.CredentialsInvalidated,
        )
    }
}
