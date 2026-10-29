package versola.sdk.storage

import versola.oauth.core.CredentialKeyProvider

/**
 * Stands in for the Keystore-backed provider, which needs a device. Reversible and obviously
 * not encryption — its only job is to prove a store never touches the plaintext it was given,
 * and that whatever the provider returns is what reaches the disk.
 *
 * [unwrapFailure] stands in for the two conditions a real Keystore raises and a store must
 * tell apart: a key that no longer decrypts, and a key that is merely locked.
 */
internal class ReversingKeyProvider : CredentialKeyProvider {
    var unwrapFailure: Throwable? = null
    var wrapFailure: Throwable? = null

    override suspend fun wrap(plaintext: ByteArray): ByteArray {
        wrapFailure?.let { throw it }
        return plaintext.reversedArray()
    }

    override suspend fun unwrap(blob: ByteArray): ByteArray {
        unwrapFailure?.let { throw it }
        return blob.reversedArray()
    }
}
