package versola.sdk.storage

import javax.crypto.AEADBadTagException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.fail
import org.junit.Test

class RecordBindingTest {

    private val secret = "8xLOxBtZp8-refresh-token-value".toByteArray()

    @Test
    fun `a sealed secret opens for its own record`() {
        val sealed = RecordBinding.seal("credentials/refreshToken", secret)

        assertArrayEquals(secret, RecordBinding.open("credentials/refreshToken", sealed))
    }

    @Test
    fun `opening zeroes the sealed buffer`() {
        val sealed = RecordBinding.seal("a", secret)

        RecordBinding.open("a", sealed)

        assertArrayEquals(ByteArray(sealed.size), sealed)
    }

    @Test
    fun `a sealed secret does not open for another record`() {
        val sealed = RecordBinding.seal("credentials/refreshToken", secret)

        try {
            RecordBinding.open("credentials/rawIdToken", sealed)
            fail("a blob moved to another slot must not open")
        } catch (e: AEADBadTagException) {
            // read as tampered
        }
    }

    @Test
    fun `a record name that is a prefix of another is not the same record`() {
        val sealed = RecordBinding.seal("credentials/refreshToken", secret)

        try {
            RecordBinding.open("credentials/refresh", sealed)
            fail("a prefix is not the record")
        } catch (e: AEADBadTagException) {
            // read as tampered
        }
    }

    @Test
    fun `a bare legacy plaintext comes back as it is`() {
        val legacy = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.sig".toByteArray()

        assertSame(legacy, RecordBinding.open("credentials/rawIdToken", legacy))
        assertEquals("{", String(RecordBinding.open("pending-authorization", "{}".toByteArray())).take(1))
    }

    @Test
    fun `empty and tiny plaintexts are legacy, not a crash`() {
        assertArrayEquals(ByteArray(0), RecordBinding.open("a", ByteArray(0)))
        assertArrayEquals(byteArrayOf(0, 'V'.code.toByte()), RecordBinding.open("a", byteArrayOf(0, 'V'.code.toByte())))
    }

    @Test
    fun `a marker with no length or a name that runs past the end is tampering`() {
        val marker = byteArrayOf(0, 'V'.code.toByte(), 'B'.code.toByte(), 2)
        for (cut in listOf(marker, marker + byteArrayOf(5, 'a'.code.toByte()))) {
            try {
                RecordBinding.open("a", cut)
                fail("a cut-short record must not open")
            } catch (e: AEADBadTagException) {
                // read as tampered
            }
        }
    }

    @Test
    fun `an empty secret round trips`() {
        assertArrayEquals(ByteArray(0), RecordBinding.open("a", RecordBinding.seal("a", ByteArray(0))))
    }
}
