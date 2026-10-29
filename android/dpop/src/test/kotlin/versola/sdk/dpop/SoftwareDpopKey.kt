package versola.sdk.dpop

import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * A [DpopKey] backed by an ordinary JCA key pair, for the tests that are about proofs rather
 * than about where the key lives.
 *
 * Not shipped, and deliberately not a "software tier" fallback in the SDK: the Keystore's own
 * software tier already is that, and it at least keeps the key out of the app's heap.
 * [KeystoreDpopKey]'s tiering has no JVM equivalent to test against and is covered by the
 * device test #6 lists separately.
 */
internal class SoftwareDpopKey : DpopKey {

    private val pair = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    private val jwk = Jose.canonicalJwk(pair.public as ECPublicKey)

    override suspend fun jkt(): String = Jose.thumbprint(jwk)

    override suspend fun publicJwk(): String = jwk

    override suspend fun attestation(): KeyAttestation = KeyAttestation.Software

    override suspend fun sign(signingInput: ByteArray): ByteArray {
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(pair.private)
        signature.update(signingInput)
        return Jose.derToJose(signature.sign())
    }
}
