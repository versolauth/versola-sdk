package versola.sdk.dpop

import android.os.Build
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.math.BigInteger
import java.security.KeyStore
import java.security.Signature
import java.util.Base64
import kotlinx.coroutines.test.runTest
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaLogger
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The half of #6 and #37 that Robolectric cannot reach: the key the Android Keystore actually
 * produces, which tier it lands on, and whether a proof it signs verifies against the public
 * key the Keystore reports for it.
 *
 * Runs on whatever the device is. An emulator has no StrongBox and, on most images, no TEE
 * either, so the tier it reports is `Software` and `requireHardware = true` must fail there —
 * which is the one bullet of #37 an emulator can prove by itself. The StrongBox and TEE rows
 * need a physical device and are read off `keyAttestation()` rather than asserted.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreDpopKeyInstrumentedTest {

    private val alias = "versola.test.dpop-key"
    private val logs = mutableListOf<String>()
    private val logger = object : VersolaLogger {
        override fun info(message: String) {
            logs += "info: $message"
        }

        override fun warn(message: String) {
            logs += "warn: $message"
        }
    }

    @Before
    @After
    fun clean() {
        KeystoreDpopKey.destroy(alias)
    }

    @Test
    fun theKeyIsGeneratedInTheKeystoreNonExportableAndItsTierIsReported() = runTest {
        val key = KeystoreDpopKey(alias, logger = logger)

        val attestation = key.attestation()

        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val entry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
        // Non-exportable: an AndroidKeyStore private key has no encoding to hand out.
        assertNull(entry.privateKey.encoded)
        assertTrue(attestation in KeyAttestation.entries)
        // The log line #1 §4 promises when the key is not in hardware, and silence when it is.
        assertEquals(!attestation.isHardwareBacked, logs.any { it.startsWith("warn: DPoP key is software-backed") })
    }

    @Test
    fun aProofSignedByTheKeyVerifiesAgainstTheKeystoresOwnPublicKey() = runTest {
        val key = KeystoreDpopKey(alias, logger = logger)
        val factory = DpopProofFactory(key)

        val proof = factory.proof("POST", "https://id.versola.kz/token?x=1")

        val (header, payload, signature) = proof.split('.')
        val signingInput = "$header.$payload".toByteArray(Charsets.US_ASCII)
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val publicKey = keyStore.getCertificate(alias).publicKey
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(publicKey)
        verifier.update(signingInput)
        assertTrue(verifier.verify(joseToDer(Base64.getUrlDecoder().decode(signature))))

        val claims = String(Base64.getUrlDecoder().decode(payload), Charsets.UTF_8)
        assertTrue(claims.contains("\"htm\":\"POST\""))
        assertTrue(claims.contains("\"htu\":\"https://id.versola.kz/token\""))
        assertFalse(claims.contains("ath"))
        val headerJson = String(Base64.getUrlDecoder().decode(header), Charsets.UTF_8)
        assertTrue(headerJson.contains("\"alg\":\"ES256\""))
        assertTrue(headerJson.contains("\"typ\":\"dpop+jwt\""))
    }

    @Test
    fun theKeySurvivesANewInstanceAndDestroyProducesADifferentThumbprint() = runTest {
        val first = KeystoreDpopKey(alias).jkt()
        // A second instance over the same alias loads rather than regenerates: the
        // thumbprint a token was bound to must be the one that proves possession later.
        assertEquals(first, KeystoreDpopKey(alias).jkt())

        val key = KeystoreDpopKey(alias)
        assertEquals(first, key.jkt())
        key.destroy()

        // Scenario 18: the next login produces a proof with a different jkt — through the
        // same instance, which must forget what it loaded, and through a fresh one.
        assertNotEquals(first, key.jkt())
        assertEquals(key.jkt(), KeystoreDpopKey(alias).jkt())
    }

    @Test
    fun requireHardwareFailsHardOnASoftwareOnlyDeviceAndIsSilentOnHardware() = runTest {
        val tier = KeystoreDpopKey(alias).attestation()
        KeystoreDpopKey.destroy(alias)

        val strict = KeystoreDpopKey(alias, requireHardware = true, logger = logger)
        if (tier.isHardwareBacked) {
            assertEquals(tier, strict.attestation())
        } else {
            val error = try {
                strict.jkt()
                null
            } catch (e: VersolaError.Configuration) {
                e
            }
            assertTrue(error?.detail is VersolaError.Configuration.Detail.HardwareBindingUnavailable)
        }
    }

    @Test
    fun strongBoxIsNegotiatedAtRuntimeRatherThanAssumed() = runTest {
        // API 28+ asks for StrongBox first and falls through; below that it never asks. On a
        // device without the chip the fall-through is logged, on one with it nothing is.
        assumeTrue(Build.VERSION.SDK_INT >= Build.VERSION_CODES.P)
        val tier = KeystoreDpopKey(alias, logger = logger).attestation()

        val fellThrough = logs.any { it.startsWith("info: StrongBox unavailable") }
        assertEquals(tier != KeyAttestation.StrongBox, fellThrough)
    }

    /** RFC 7515 §A.3.2 in reverse: fixed-width `R‖S` back to the DER sequence JCA verifies. */
    private fun joseToDer(jose: ByteArray): ByteArray {
        val half = jose.size / 2
        val r = BigInteger(1, jose.copyOfRange(0, half)).toByteArray()
        val s = BigInteger(1, jose.copyOfRange(half, jose.size)).toByteArray()
        val body = byteArrayOf(0x02, r.size.toByte()) + r + byteArrayOf(0x02, s.size.toByte()) + s
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}
