package kz.versola.sdk.dpop

import com.nimbusds.jose.jwk.ECKey
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class JoseTest {

    private fun der(r: BigInteger, s: BigInteger): ByteArray {
        fun integer(value: BigInteger): ByteArray {
            val bytes = value.toByteArray()
            return byteArrayOf(0x02, bytes.size.toByte()) + bytes
        }
        val body = integer(r) + integer(s)
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    @Test
    fun `a signature component with a high bit set loses its DER sign byte`() {
        // BigInteger.toByteArray prefixes 0x00 when the top bit would otherwise read as
        // negative, making r 33 bytes. Passed through unchanged, the JOSE form is 65 bytes
        // and every proof signed by such a signature is rejected — roughly one in two
        // hundred, which is how this bug reaches production.
        val r = BigInteger(1, ByteArray(32) { 0xFF.toByte() })
        val s = BigInteger.ONE

        val jose = Jose.derToJose(der(r, s))

        assertEquals(64, jose.size)
        assertArrayEquals(ByteArray(32) { 0xFF.toByte() }, jose.copyOfRange(0, 32))
        assertArrayEquals(ByteArray(31) + byteArrayOf(1), jose.copyOfRange(32, 64))
    }

    @Test
    fun `a short signature component is left-padded rather than left short`() {
        // The other direction: a small s encodes in one byte, and a JOSE form that is 33
        // bytes long fails just as hard as one that is 65.
        val jose = Jose.derToJose(der(BigInteger.TEN, BigInteger.TEN))

        assertEquals(64, jose.size)
        assertEquals(10, jose[31].toInt())
        assertEquals(10, jose[63].toInt())
        assertEquals(0, jose[0].toInt())
    }

    @Test
    fun `real signatures convert to sixty-four bytes, whatever the component widths`() {
        // The widths above occur by chance, so one run of this proves little on its own; the
        // point is the loop, which covers both padding directions within a few iterations.
        val pair = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        repeat(200) { attempt ->
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initSign(pair.private)
            signature.update("message $attempt".toByteArray())

            assertEquals(64, Jose.derToJose(signature.sign()).size)
        }
    }

    @Test
    fun `a signature that is not a DER sequence is rejected rather than misread`() {
        assertThrows(IllegalArgumentException::class.java) {
            Jose.derToJose(ByteArray(70) { 0x31 })
        }
    }

    @Test
    fun `the canonical JWK carries only the required members, in lexicographic order`() {
        // RFC 7638 §3.3. Any other spelling hashes to a different thumbprint, so the jkt a
        // token is bound to would not equal the one the authorization request committed to.
        val key = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair().public as ECPublicKey

        val jwk = Jose.canonicalJwk(key)

        assertEquals(listOf("crv", "kty", "x", "y"), Regex("\"(\\w+)\":").findAll(jwk).map { it.groupValues[1] }.toList())
        assertTrue(jwk, jwk.startsWith("""{"crv":"P-256","kty":"EC","x":""""))
        assertTrue(jwk, jwk.endsWith("\"}"))
    }

    @Test
    fun `the thumbprint matches the one the server computes from the same key`() {
        // Nimbus is what auth and edge verify with (`versola.util.Dpop`), so agreeing with it
        // is the same thing as the token's cnf.jkt matching our dpop_jkt.
        val key = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair().public as ECPublicKey

        val ours = Jose.thumbprint(Jose.canonicalJwk(key))
        val theirs = ECKey.Builder(com.nimbusds.jose.jwk.Curve.P_256, key).build().computeThumbprint().toString()

        assertEquals(theirs, ours)
    }

    @Test
    fun `a coordinate with leading zero bytes is still thirty-two bytes wide`() {
        // A P-256 x or y smaller than 2^248 encodes short, and a JWK that drops the leading
        // zeros is a different, non-canonical key representation with a different thumbprint.
        val jwk = Jose.canonicalJwk(SmallCoordinateKey)

        val x = Regex("\"x\":\"([^\"]+)\"").find(jwk)!!.groupValues[1]

        assertEquals(32, java.util.Base64.getUrlDecoder().decode(x).size)
    }

    private object SmallCoordinateKey : ECPublicKey {
        private val real = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair().public as ECPublicKey

        override fun getW(): java.security.spec.ECPoint = java.security.spec.ECPoint(BigInteger.ONE, BigInteger.ONE)
        override fun getParams(): java.security.spec.ECParameterSpec = real.params
        override fun getAlgorithm(): String = real.algorithm
        override fun getFormat(): String = real.format
        override fun getEncoded(): ByteArray = real.encoded
    }
}
