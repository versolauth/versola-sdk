package kz.versola.sdk.storage

import androidx.datastore.core.CorruptionException
import androidx.datastore.core.Serializer
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream

/**
 * What one credential file contains: three independently wrapped fields, each already
 * ciphertext by the time it gets here.
 *
 * Wrapped separately rather than as one record so that reading the ID token or the rotation
 * slot does not unwrap the refresh token, and so `hasGrant()` can answer from the presence of
 * a field without touching the key at all.
 *
 * Not JSON, unlike [kz.versola.sdk.core.PendingAuthorizationCodec]. Two reasons, and the
 * first is the one that decides it: a JSON codec hands back `String`s, and a `String` holding
 * a refresh token cannot be zeroed. The second is that this encoding never crosses a module
 * boundary — one store writes it and the same store reads it — where the pending request's
 * does.
 */
internal class CredentialBlob(
    val refreshToken: ByteArray? = null,
    val rawIdToken: ByteArray? = null,
    val pendingRotation: ByteArray? = null,
) {

    fun encode(): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(MAGIC)
        out.write(VERSION)
        listOf(refreshToken, rawIdToken, pendingRotation).forEach { field ->
            if (field == null) {
                out.writeInt(ABSENT)
            } else {
                out.writeInt(field.size)
                out.write(field)
            }
        }
        return out.toByteArray()
    }

    companion object {
        val EMPTY: CredentialBlob = CredentialBlob()

        private val MAGIC = byteArrayOf('V'.code.toByte(), 'C'.code.toByte())
        private const val VERSION = 1
        private const val ABSENT = -1

        /**
         * A version byte is written from the first release rather than added when it is
         * first needed: a file with no version in it cannot be migrated later without
         * guessing what wrote it.
         */
        fun decode(bytes: ByteArray): CredentialBlob {
            var offset = 0

            fun require(condition: Boolean, detail: String) {
                if (!condition) throw CorruptionException("credential file is not readable: $detail")
            }

            fun take(count: Int): ByteArray {
                // Not `offset + count <= bytes.size`: a forged length near Int.MAX_VALUE
                // overflows that sum to a negative number, which then passes the check
                // vacuously and reaches `copyOfRange` with a corrupt range it throws
                // `IllegalArgumentException` for — not a `CorruptionException`, so DataStore
                // would never invoke the corruption handler and every later read fails
                // instead of resetting to an empty grant. `bytes.size - offset` cannot
                // overflow (both are within array-size bounds), so the comparison is safe
                // for any `count`.
                require(count in 0..(bytes.size - offset), "truncated")
                return bytes.copyOfRange(offset, offset + count).also { offset += count }
            }

            fun takeInt(): Int = take(4).fold(0) { acc, byte -> (acc shl 8) or (byte.toInt() and 0xFF) }

            require(take(MAGIC.size).contentEquals(MAGIC), "not a credential file")
            require(take(1)[0].toInt() == VERSION, "unknown version")

            fun takeField(): ByteArray? {
                val length = takeInt()
                if (length == ABSENT) return null
                require(length >= 0, "negative field length")
                return take(length)
            }

            val blob = CredentialBlob(takeField(), takeField(), takeField())
            require(offset == bytes.size, "trailing bytes")
            return blob
        }
    }
}

private fun ByteArrayOutputStream.writeInt(value: Int) {
    write(value ushr 24)
    write(value ushr 16)
    write(value ushr 8)
    write(value)
}

/**
 * DataStore's contract over [CredentialBlob]. Unreadable bytes surface as
 * [CorruptionException], which the store's corruption handler turns into an empty file — a
 * grant nobody can read is a sign-out, and the alternative is a store that throws on every
 * call for the rest of the install.
 */
internal object CredentialBlobSerializer : Serializer<CredentialBlob> {

    override val defaultValue: CredentialBlob = CredentialBlob.EMPTY

    override suspend fun readFrom(input: InputStream): CredentialBlob =
        try {
            CredentialBlob.decode(input.readBytes())
        } catch (e: CorruptionException) {
            throw e
        } catch (e: Exception) {
            // Belt and braces alongside the overflow fix in `take`: whatever a future bug in
            // `decode` throws, it must still reach the corruption handler rather than
            // wedging this store into throwing on every call for the rest of the install.
            throw CorruptionException("credential file is not readable: ${e.message}", e)
        }

    override suspend fun writeTo(t: CredentialBlob, output: OutputStream) {
        output.write(t.encode())
    }
}
