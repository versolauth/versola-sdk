package versola.sdk.dpop

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import versola.oauth.core.JwsSignatures

/**
 * Android names the PSS family `SHA256withRSA/PSS` and does not list the JDK's `RSASSA-PSS`
 * for the supported API range, so the JVM unit tests of the JWS verifier prove nothing about
 * a device. This runs the verifier's own code against signatures made on the device, in the
 * module whose instrumented job already runs on the CI emulator matrix.
 */
@RunWith(AndroidJUnit4::class)
class JwsPssInstrumentedTest {

    private val keys = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private val signingInput = "eyJhbGciOiJQUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9".toByteArray(Charsets.US_ASCII)

    private fun pss(digest: String, bits: Int): Signature =
        Signature.getInstance("SHA${bits}withRSA/PSS").apply {
            setParameter(PSSParameterSpec(digest, "MGF1", MGF1ParameterSpec(digest), bits / 8, 1))
        }

    @Test
    fun ps256_ps384_and_ps512_signatures_made_on_this_device_verify() {
        for ((alg, digest, bits) in listOf(Triple("PS256", "SHA-256", 256), Triple("PS384", "SHA-384", 384), Triple("PS512", "SHA-512", 512))) {
            val signature = pss(digest, bits).apply {
                initSign(keys.private)
                update(signingInput)
            }.sign()

            assertTrue(alg, JwsSignatures.verifies(alg, keys.public, signingInput, signature))
            assertFalse(alg, JwsSignatures.verifies(alg, keys.public, signingInput + 1, signature))
        }
    }

    @Test
    fun rs256_and_es256_verify_on_this_device_too() {
        val rsa = Signature.getInstance("SHA256withRSA").apply {
            initSign(keys.private)
            update(signingInput)
        }.sign()
        assertTrue(JwsSignatures.verifies("RS256", keys.public, signingInput, rsa))

        val ec = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val der = Signature.getInstance("SHA256withECDSA").apply {
            initSign(ec.private)
            update(signingInput)
        }.sign()
        // The verifier takes JOSE `R || S`; convert the DER the JCA produced.
        assertTrue(JwsSignatures.verifies("ES256", ec.public, signingInput, derToJose(der, 32)))
    }

    private fun derToJose(der: ByteArray, width: Int): ByteArray {
        var offset = 2
        if (der[1].toInt() and 0x80 != 0) offset += der[1].toInt() and 0x7f
        fun integer(): ByteArray {
            check(der[offset] == 0x02.toByte())
            val length = der[offset + 1].toInt()
            val bytes = der.copyOfRange(offset + 2, offset + 2 + length)
            offset += 2 + length
            val unsigned = bytes.dropWhile { it == 0.toByte() }.toByteArray()
            return ByteArray(width - unsigned.size) + unsigned
        }
        return integer() + integer()
    }
}
