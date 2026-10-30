package versola.sdk.storage

import androidx.datastore.core.DataStore
import androidx.datastore.core.DataStoreFactory
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import java.io.File
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import versola.oauth.core.CredentialKeyProvider
import versola.oauth.core.CredentialStore
import versola.oauth.core.VersolaError

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
 * class's: a second active instance over the same file throws `IllegalStateException` on its
 * first read. [forFile] is the constructor to use — it hands back the instance already open
 * on that path, so a `configure()` repeated on every `Activity.onCreate` keeps working. The
 * public constructor stays for a caller that owns its own file and scope, tests above all.
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
            wrapping(REFRESH_TOKEN, refreshToken)
        } finally {
            refreshToken.fill(0)
        }
        val wrappedIdToken = rawIdToken?.let { wrapping(ID_TOKEN, it.toByteArray(Charsets.UTF_8)) }

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
        val plaintext = unwrapping(REFRESH_TOKEN, wrapped)
        return try {
            block(plaintext)
        } finally {
            plaintext.fill(0)
        }
    }

    override suspend fun hasGrant(): Boolean = dataStore.data.first().refreshToken != null

    override suspend fun rawIdToken(): String? {
        val wrapped = dataStore.data.first().rawIdToken ?: return null
        return unwrapping(ID_TOKEN, wrapped).toUtf8AndZero()
    }

    override suspend fun savePendingRotation(idempotencyKey: String?) {
        val wrapped = idempotencyKey?.let { wrapping(PENDING_ROTATION, it.toByteArray(Charsets.UTF_8)) }
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
        return unwrapping(PENDING_ROTATION, wrapped).toUtf8AndZero()
    }

    override suspend fun clear() {
        dataStore.updateData { CredentialBlob.EMPTY }
    }

    public companion object {
        private val instances = HashMap<String, DataStoreCredentialStore>()

        // The slot each secret is bound to ([RecordBinding]): a blob moved to another field
        // does not open there.
        private const val REFRESH_TOKEN = "credentials/refreshToken"
        private const val ID_TOKEN = "credentials/rawIdToken"
        private const val PENDING_ROTATION = "credentials/pendingRotation"

        /**
         * The store for [file], opened once per process and shared by every caller naming
         * the same path. [keyProvider] is bound at the first call; a later call with another
         * provider gets the store as first opened, because the ciphertext on disk belongs to
         * the key that wrote it.
         */
        public fun forFile(file: File, keyProvider: CredentialKeyProvider): DataStoreCredentialStore =
            synchronized(instances) {
                instances.getOrPut(file.canonicalPath) { DataStoreCredentialStore(file, keyProvider) }
            }
    }

    /**
     * A [VersolaError] from the provider is already the right answer and passes through, as
     * does a cancellation: the caller's scope ending says nothing about the grant, and
     * reporting it as a lost one would have the coordinator wipe a session that is fine.
     * Anything else is sorted by [StorageFailure]: a verdict on the bytes (a tampered
     * ciphertext, an invalidated key) is a sign-out because `spec/errors.md` cannot tell the
     * two apart, and every other failure leaves the grant in place and the caller to retry.
     * A blob that opens but names another slot is read as the tampered one it is.
     */
    private suspend fun unwrapping(record: String, wrapped: ByteArray): ByteArray = try {
        RecordBinding.open(record, keyProvider.unwrap(wrapped))
    } catch (e: CancellationException) {
        throw e
    } catch (e: VersolaError) {
        throw e
    } catch (e: Exception) {
        throw StorageFailure.toError(e)
    }

    /** [secret] bound to [record], wrapped, with the sealed copy zeroed whether or not the wrap held. */
    private suspend fun wrapping(record: String, secret: ByteArray): ByteArray {
        val sealed = RecordBinding.seal(record, secret)
        return try {
            keyProvider.wrap(sealed)
        } finally {
            sealed.fill(0)
        }
    }

    private fun ByteArray.toUtf8AndZero(): String = try {
        toString(Charsets.UTF_8)
    } finally {
        fill(0)
    }
}
