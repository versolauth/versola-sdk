package versola.sdk.core

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The bytes and names of the attestation contract, held to values computed outside this code. */
class NativeAttestationTest {

    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it) }

    @Test
    fun `the challenge for a client is the vector the spec and edge both publish`() {
        // `SHA-256("versola-attest-v1\nmobile-app")`, from `spec/server-dependencies.md`, computed with
        // `hashlib` and checked by edge's own spec: neither side's hashing is the other's reading of it.
        assertEquals(
            "da1a942191246aaada23ebad9694ba705d6babcd5bfec362779077b377440e15",
            hex(NativeAttestation.androidChallenge("mobile-app")),
        )
    }

    @Test
    fun `a challenge made for one client is not another's`() {
        assertFalse(NativeAttestation.androidChallenge("a").contentEquals(NativeAttestation.androidChallenge("b")))
        assertArrayEquals(NativeAttestation.androidChallenge("a"), NativeAttestation.androidChallenge("a"))
    }

    @Test
    fun `a chain is the platform and a field per certificate, leaf first`() {
        val fields = NativeAttestation.androidFields(listOf(byteArrayOf(1, 2), byteArrayOf(3)))

        assertEquals(
            listOf("attestation_platform" to "android", "attestation_chain" to "AQI=", "attestation_chain" to "Aw=="),
            fields,
        )
    }

    @Test
    fun `no chain is no field, not a field with nothing in it`() {
        assertTrue(NativeAttestation.androidFields(null).isEmpty())
        assertTrue(NativeAttestation.androidFields(emptyList()).isEmpty())
    }
}
