package versola.sdk.storage

import android.security.keystore.KeyPermanentlyInvalidatedException
import java.security.UnrecoverableKeyException
import javax.crypto.AEADBadTagException
import versola.oauth.core.VersolaError

/**
 * What a failed key operation says about the bytes it was asked to open, shared by the two
 * stores so that they cannot disagree.
 *
 * The question is whether the bytes can ever be read again, because the answer decides
 * between a sign-out and a retry, and the two are not symmetric: wrongly signing out destroys
 * a grant (and the DPoP key bound to it) that was fine, while wrongly retrying costs one more
 * attempt. So only a verdict is treated as a verdict.
 *
 * Permanent, each for a reason of its own:
 * - [AEADBadTagException]: GCM's tag did not verify. The ciphertext was altered, or the key
 *   that wrote it is not the key that answers now (a restore onto another device, a key
 *   regenerated after the entry vanished). Deterministic, so retrying cannot change it.
 * - [KeyPermanentlyInvalidatedException]: the Keystore documents it as final: the key was
 *   invalidated by a biometric or lock-screen change and will never operate again.
 * - [UnrecoverableKeyException]: the entry exists and cannot be read back, which is what
 *   `KeyStore.getEntry` documents it throws for a key that cannot be recovered.
 *
 * Everything else (a `ProviderException` or `KeyStoreException` out of a busy keystore
 * service, a StrongBox fault, an `IOException`, any exception this class has not seen) is no
 * verdict on the key and stays recoverable. A key that is permanently broken in some other
 * way keeps reporting that, which the app sees as a failing retry rather than a lost session.
 */
internal object StorageFailure {

    /** How far down a wrapped cause the verdict is looked for; a provider adds one level or two. */
    private const val MAX_CAUSE_DEPTH = 4

    fun isPermanent(failure: Throwable): Boolean {
        var current: Throwable? = failure
        repeat(MAX_CAUSE_DEPTH) {
            when (current) {
                is AEADBadTagException, is KeyPermanentlyInvalidatedException, is UnrecoverableKeyException -> return true
                is VersolaError.Reauthenticate -> return true
            }
            current = current?.cause ?: return false
        }
        return false
    }

    /**
     * The error an unwrap failure is reported as. The detail carries the class of the
     * failure and not its message, which is the provider's to write.
     *
     * No `Cause` fits a storage fault exactly, and `UnlockRequired` is the wrong one: it
     * moves the session to `Locked` and asks the app for an authentication prompt that will
     * not change the outcome. `Network` is the one that means "grant intact, retry, nothing
     * wiped" (the session reverts to `Authenticated`, and the retry budget may repeat it).
     */
    fun toError(failure: Exception): VersolaError =
        if (isPermanent(failure)) {
            VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.CredentialsInvalidated)
        } else {
            VersolaError.Recoverable(
                VersolaError.Recoverable.Cause.Network("storage key unavailable: ${failure.javaClass.simpleName}"),
                failure,
            )
        }
}
