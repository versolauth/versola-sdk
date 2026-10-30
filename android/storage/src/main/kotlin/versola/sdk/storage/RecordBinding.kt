package versola.sdk.storage

import javax.crypto.AEADBadTagException

/**
 * Binds a stored secret to the record it belongs to, inside the plaintext the key provider
 * wraps.
 *
 * AES-GCM authenticates the whole plaintext, so a record name in front of the secret is
 * bound to the ciphertext as strongly as additional authenticated data would be, and it works
 * over any [versola.oauth.core.CredentialKeyProvider] without widening that public interface.
 * What it stops is moving a valid blob from one slot to another: the stored ID token read back
 * as the refresh token, or the pending request's blob answering as a credential. It does not
 * stop replaying an older blob of the same slot (that needs a counter nothing here keeps).
 *
 * Format: `00 'V' 'B' 02`, one byte of name length, the name in UTF-8, then the secret. The
 * leading zero byte cannot start anything 0.1.0 stored (opaque tokens, a JWT, a UUID and the
 * pending request's JSON are all printable text), so a plaintext that does not begin with the
 * marker is a 0.1.0 record and is read as it is. It is rewritten in this format the next time
 * the record is saved: the refresh token on every rotation, the pending request at every login.
 * Older SDKs cannot read the new format; see `spec/state-machine.md`, "Persistence".
 */
internal object RecordBinding {

    private val MARKER = byteArrayOf(0x00, 'V'.code.toByte(), 'B'.code.toByte(), 0x02)

    /** `marker | name | secret`; the caller zeroes [secret] and the result. */
    fun seal(record: String, secret: ByteArray): ByteArray {
        val name = record.toByteArray(Charsets.UTF_8)
        require(name.size in 1..255) { "record name must be 1..255 bytes" }
        val out = ByteArray(MARKER.size + 1 + name.size + secret.size)
        MARKER.copyInto(out)
        out[MARKER.size] = name.size.toByte()
        name.copyInto(out, MARKER.size + 1)
        secret.copyInto(out, MARKER.size + 1 + name.size)
        return out
    }

    /**
     * The secret of [record] in [plaintext], zeroing [plaintext]. A 0.1.0 record, which has no
     * marker, is returned as it is (the same array). A sealed one that names another record,
     * or is cut short, is a blob that was moved or altered: [AEADBadTagException], the same
     * failure a ciphertext that does not authenticate is, and read as the same sign-out.
     */
    fun open(record: String, plaintext: ByteArray): ByteArray {
        if (plaintext.size < MARKER.size || !plaintext.copyOfRange(0, MARKER.size).contentEquals(MARKER)) {
            return plaintext
        }
        val expected = record.toByteArray(Charsets.UTF_8)
        try {
            val nameLength = plaintext.getOrNull(MARKER.size)?.toInt()?.and(0xFF)
                ?: throw AEADBadTagException("sealed record is cut short")
            val nameStart = MARKER.size + 1
            val secretStart = nameStart + nameLength
            if (secretStart > plaintext.size) throw AEADBadTagException("sealed record is cut short")
            if (!plaintext.copyOfRange(nameStart, secretStart).contentEquals(expected)) {
                throw AEADBadTagException("sealed record belongs to another slot")
            }
            return plaintext.copyOfRange(secretStart, plaintext.size)
        } finally {
            plaintext.fill(0)
        }
    }
}
