package versola.oauth.conformance

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.StrongBoxUnavailableException
import java.security.Key
import java.security.KeyPair
import java.security.KeyPairGeneratorSpi
import java.security.KeyStore
import java.security.KeyStoreSpi
import java.security.Provider
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.spec.AlgorithmParameterSpec
import java.util.Collections
import java.util.Date
import java.util.Enumeration
import java.util.concurrent.ConcurrentHashMap

/**
 * What a JVM has in place of the Android Keystore: a JCA provider registered as
 * `AndroidKeyStore` that hands `KeystoreDpopKey` an ordinary P-256 key pair, so the SDK's own
 * key class runs unmodified and the scenarios can prove DPoP on the wire without a device.
 *
 * It models what a machine without a secure element does and nothing more:
 * - a key request with `setIsStrongBoxBacked(true)` fails with `StrongBoxUnavailableException`,
 *   which `KeystoreDpopKey` answers by asking again without StrongBox, as it does on a phone
 *   with no StrongBox chip;
 * - `KeyFactory.getKeySpec(.., KeyInfo)` is not offered, so the key's security level cannot be
 *   read back and `KeystoreDpopKey` reports `KeyAttestation.Software` (and `requireHardware`
 *   refuses it), the path it takes when the Keystore does not say.
 *
 * The tier this proves is therefore Software, by construction. The Keystore's StrongBox and
 * TEE tiers are the device tier's (`android/dpop`'s instrumented tests); nothing in a run with
 * this provider supports a claim about them.
 *
 * [generated] keeps each generated pair by alias so the harness can sign what the SDK's key would
 * sign, with claims it chooses: a resource server's refusal of a forged proof is only a proof
 * of the check it names when the key, `htm`, `htu`, `iat`, `jti` and `ath` are otherwise the
 * SDK's own. A real Keystore never hands its private key out; this one is a test fixture.
 */
class SoftwareAndroidKeyStore : Provider("AndroidKeyStore", 1.0, "JVM stand-in for the Android Keystore (conformance harness)") {

    val generated = ConcurrentHashMap<String, KeyPair>()

    init {
        putService(object : Service(this, "KeyStore", "AndroidKeyStore", Store::class.java.name, null, null) {
            override fun newInstance(constructorParameter: Any?): Any = Store(generated)
        })
        putService(object : Service(this, "KeyPairGenerator", "EC", Generator::class.java.name, null, null) {
            override fun newInstance(constructorParameter: Any?): Any = Generator(generated)
        })
    }

    /** The one key the client under test generated, or fails: a test with two clients names its alias. */
    fun soleKey(): KeyPair = checkNotNull(generated.values.singleOrNull()) { "expected exactly one generated DPoP key, found ${generated.size}" }

    /** Entries are never persisted: a key lives as long as the `KeystoreDpopKey` that generated it. */
    class Store(private val keys: ConcurrentHashMap<String, KeyPair>) : KeyStoreSpi() {
        override fun engineGetKey(alias: String?, password: CharArray?): Key? = null
        override fun engineGetCertificateChain(alias: String?): Array<Certificate>? = null
        override fun engineGetCertificate(alias: String?): Certificate? = null
        override fun engineGetCreationDate(alias: String?): Date? = null
        override fun engineSetKeyEntry(alias: String?, key: Key?, password: CharArray?, chain: Array<out Certificate>?) = throw UnsupportedOperationException()
        override fun engineSetKeyEntry(alias: String?, key: ByteArray?, chain: Array<out Certificate>?) = throw UnsupportedOperationException()
        override fun engineSetCertificateEntry(alias: String?, cert: Certificate?) = throw UnsupportedOperationException()
        override fun engineDeleteEntry(alias: String?) {
            keys.remove(alias)
        }
        override fun engineAliases(): Enumeration<String> = Collections.enumeration(keys.keys)
        override fun engineContainsAlias(alias: String?): Boolean = false
        override fun engineSize(): Int = 0
        override fun engineIsKeyEntry(alias: String?): Boolean = false
        override fun engineIsCertificateEntry(alias: String?): Boolean = false
        override fun engineGetCertificateAlias(cert: Certificate?): String? = null
        override fun engineStore(stream: java.io.OutputStream?, password: CharArray?) = Unit
        override fun engineLoad(stream: java.io.InputStream?, password: CharArray?) = Unit
        override fun engineEntryInstanceOf(alias: String?, entryClass: Class<out KeyStore.Entry>?): Boolean = false
    }

    class Generator(private val keys: ConcurrentHashMap<String, KeyPair>) : KeyPairGeneratorSpi() {
        private var alias: String? = null

        override fun initialize(keysize: Int, random: SecureRandom?) = throw UnsupportedOperationException("a KeyGenParameterSpec is required")

        override fun initialize(params: AlgorithmParameterSpec?, random: SecureRandom?) {
            val spec = params as? KeyGenParameterSpec ?: throw java.security.InvalidAlgorithmParameterException("a KeyGenParameterSpec is required")
            // `isStrongBoxBacked` exists from API 28, and the SDK asks for StrongBox only from there too.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && spec.isStrongBoxBacked) throw StrongBoxUnavailableException("this JVM has no StrongBox")
            alias = spec.keystoreAlias
        }

        override fun generateKeyPair(): KeyPair {
            val pair = DpopResourceServer.newKeyPair()
            keys[checkNotNull(alias) { "initialize first" }] = pair
            return pair
        }
    }
}
