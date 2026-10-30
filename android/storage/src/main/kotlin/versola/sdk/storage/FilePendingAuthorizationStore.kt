package versola.sdk.storage

import java.io.File
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.withContext
import versola.oauth.core.CredentialKeyProvider
import versola.oauth.core.PendingAuthorizationCodec
import versola.oauth.core.PendingAuthorizationRequest
import versola.oauth.core.PendingAuthorizationStore
import versola.oauth.core.SdkDispatchers
import versola.oauth.core.VersolaError

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
        val encoded = PendingAuthorizationCodec.encode(request)
        val sealed = RecordBinding.seal(RECORD, encoded)
        val wrapped = try {
            keyProvider.wrap(sealed)
        } finally {
            encoded.fill(0)
            sealed.fill(0)
        }
        withContext(SdkDispatchers.blocking) {
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
        val wrapped = withContext(SdkDispatchers.blocking) {
            if (file.exists()) file.readBytes() else null
        } ?: return null

        // Discarded only when nothing can ever be made of it. The slot is a login the user may
        // be in the middle of, and a failure that says nothing about the bytes (a locked key, a
        // keystore hiccup, a cancelled caller) must not cost them the redirect that is on its
        // way: those surface, with the slot left where it is.
        val plaintext = try {
            RecordBinding.open(RECORD, keyProvider.unwrap(wrapped))
        } catch (e: CancellationException) {
            throw e
        } catch (e: VersolaError.Reauthenticate) {
            // The key that wrote it is gone for good.
            clear()
            return null
        } catch (e: VersolaError) {
            throw e
        } catch (e: Exception) {
            if (StorageFailure.isPermanent(e)) {
                clear()
                return null
            }
            throw StorageFailure.toError(e)
        }

        return try {
            PendingAuthorizationCodec.decode(plaintext)
        } catch (e: Exception) {
            // It opened and is not a pending request: a slot that cannot complete a flow, with
            // nothing recoverable in it. Discarded rather than surfaced: the user logs in
            // again. Distinct from the key being invalidated with *credentials* behind it,
            // which #7 surfaces as Reauthenticate.
            clear()
            null
        } finally {
            plaintext.fill(0)
        }
    }

    override suspend fun clear() {
        withContext(SdkDispatchers.blocking) {
            file.delete()
            File(file.parentFile, file.name + ".tmp").delete()
        }
    }
}

/** The slot the pending request is bound to ([RecordBinding]). */
private const val RECORD = "pending-authorization"
