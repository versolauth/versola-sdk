package kz.versola.sdk.storage

import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kz.versola.sdk.core.CredentialKeyProvider
import kz.versola.sdk.core.PendingAuthorizationCodec
import kz.versola.sdk.core.PendingAuthorizationRequest
import kz.versola.sdk.core.PendingAuthorizationStore

/**
 * The pending authorization request, wrapped by a [CredentialKeyProvider] and written to one
 * file.
 *
 * A single small blob written once per `login()` and read once per redirect — a file is the
 * whole requirement. DataStore arrives with #7, which has a reason for it the pending slot
 * does not: several values, written from several places, needing a consistent view.
 *
 * Callers should place the file under `Context.noBackupFilesDir`: a pending request restored
 * onto a different device from a cloud backup is useless at best, and the `code_verifier` is
 * credential material.
 */
public class FilePendingAuthorizationStore(
    private val file: File,
    private val keyProvider: CredentialKeyProvider,
) : PendingAuthorizationStore {

    override suspend fun save(request: PendingAuthorizationRequest) {
        val wrapped = keyProvider.wrap(PendingAuthorizationCodec.encode(request))
        withContext(Dispatchers.IO) {
            file.parentFile?.mkdirs()
            // Written to a sibling and renamed: a process killed mid-write must not leave a
            // half-written slot behind, since the whole point of this file is surviving a kill.
            val temporary = File(file.parentFile, file.name + ".tmp")
            temporary.writeBytes(wrapped)
            if (!temporary.renameTo(file)) {
                temporary.delete()
                error("could not persist the pending authorization request")
            }
        }
    }

    override suspend fun load(): PendingAuthorizationRequest? {
        val wrapped = withContext(Dispatchers.IO) {
            if (file.exists()) file.readBytes() else null
        } ?: return null

        return try {
            PendingAuthorizationCodec.decode(keyProvider.unwrap(wrapped))
        } catch (e: Exception) {
            // A slot that cannot be unwrapped or decoded is a slot that cannot complete a
            // flow. Nothing is recoverable from it, so it is discarded rather than surfaced:
            // the user simply logs in again. Distinct from the key being invalidated with
            // *credentials* behind it, which #7 surfaces as Reauthenticate.
            clear()
            null
        }
    }

    override suspend fun clear() {
        withContext(Dispatchers.IO) {
            file.delete()
            File(file.parentFile, file.name + ".tmp").delete()
        }
    }
}
