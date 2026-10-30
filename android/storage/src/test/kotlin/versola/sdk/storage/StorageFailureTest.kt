package versola.sdk.storage

import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import java.io.IOException
import java.security.KeyStoreException
import java.security.ProviderException
import java.security.UnrecoverableKeyException
import javax.crypto.AEADBadTagException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import versola.oauth.core.VersolaError

/**
 * Which Keystore failures are a verdict on the key. `KeyPermanentlyInvalidatedException` and
 * `UserNotAuthenticatedException` are framework classes, so this runs under Robolectric; the
 * store-level behaviour for each branch is in [DataStoreCredentialStoreTest] and
 * [FilePendingAuthorizationStoreTest].
 */
@RunWith(RobolectricTestRunner::class)
class StorageFailureTest {

    @Test
    fun `the three failures the Keystore documents as final are permanent`() {
        assertTrue(StorageFailure.isPermanent(KeyPermanentlyInvalidatedException("lock screen changed")))
        assertTrue(StorageFailure.isPermanent(AEADBadTagException("Tag mismatch")))
        assertTrue(StorageFailure.isPermanent(UnrecoverableKeyException("cannot recover key")))
    }

    @Test
    fun `a verdict is found under a wrapper`() {
        val wrapped = ProviderException("operation failed", KeyPermanentlyInvalidatedException("lock screen changed"))

        assertTrue(StorageFailure.isPermanent(wrapped))
    }

    @Test
    fun `a self-referencing cause chain terminates`() {
        val loop = IOException("a")
        loop.initCause(IOException("b", loop))

        assertFalse(StorageFailure.isPermanent(loop))
    }

    @Test
    fun `failures that say nothing about the key are not permanent`() {
        assertFalse(StorageFailure.isPermanent(ProviderException("keystore service died")))
        assertFalse(StorageFailure.isPermanent(KeyStoreException("Keystore operation failed")))
        assertFalse(StorageFailure.isPermanent(IOException("not ready")))
        assertFalse(StorageFailure.isPermanent(IllegalStateException("unexpected")))
        // A locked key is the provider's UnlockRequired, never this class's business.
        assertFalse(StorageFailure.isPermanent(UserNotAuthenticatedException("window elapsed")))
    }

    @Test
    fun `a permanent failure becomes CredentialsInvalidated and any other a recoverable error`() {
        val permanent = StorageFailure.toError(AEADBadTagException("Tag mismatch"))
        val transient = StorageFailure.toError(KeyStoreException("Keystore operation failed"))

        assertEquals(
            VersolaError.Reauthenticate.Reason.CredentialsInvalidated,
            (permanent as VersolaError.Reauthenticate).reason,
        )
        assertTrue((transient as VersolaError.Recoverable).reason is VersolaError.Recoverable.Cause.Network)
    }
}
