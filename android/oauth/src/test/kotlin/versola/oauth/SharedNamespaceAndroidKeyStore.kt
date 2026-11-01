package versola.oauth

import android.security.keystore.KeyGenParameterSpec
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidAlgorithmParameterException
import java.security.Key
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyPairGeneratorSpi
import java.security.KeyStore
import java.security.KeyStoreSpi
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.Certificate
import java.security.spec.AlgorithmParameterSpec
import java.security.spec.ECGenParameterSpec
import java.util.Collections
import java.util.Date
import java.util.Enumeration
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.KeyGenerator
import javax.crypto.KeyGeneratorSpi
import javax.crypto.SecretKey

/**
 * A JVM stand-in for the Android Keystore that models the one property the SDK's two keys must
 * not forget: the alias namespace is per app and shared by every key type, and generating under
 * an alias that exists REPLACES whatever entry is there, an AES secret key and an EC private key
 * alike. [generated] holds the entry per alias; [overwrites] records each replacement
 * as "alias: old -> new", which is the audit's Z1 symptom, observable without any Cipher.
 *
 * Entries persist for the life of the provider instance, so a test that rebuilds its clients
 * over the same instance is a process restart over the same Keystore. `getEntry` returns the
 * entry class matching what is stored (SecretKeyEntry or PrivateKeyEntry), as the real one does,
 * and the SDK's `as?` casts decide what that means for it.
 */
internal class SharedNamespaceAndroidKeyStore : Provider("AndroidKeyStore", 1.0, "JVM stand-in with one alias namespace for every key type") {

    val generated = ConcurrentHashMap<String, Any>()
    val overwrites = Collections.synchronizedList(mutableListOf<String>())
    val specs = ConcurrentHashMap<String, KeyGenParameterSpec>()

    init {
        putService(object : Service(this, "KeyStore", "AndroidKeyStore", Store::class.java.name, null, null) {
            override fun newInstance(constructorParameter: Any?): Any = Store()
        })
        putService(object : Service(this, "KeyPairGenerator", "EC", PairGenerator::class.java.name, null, null) {
            override fun newInstance(constructorParameter: Any?): Any = PairGenerator()
        })
        putService(object : Service(this, "KeyGenerator", "AES", AesGenerator::class.java.name, null, null) {
            override fun newInstance(constructorParameter: Any?): Any = AesGenerator()
        })
    }

    private fun put(alias: String, entry: Any, spec: KeyGenParameterSpec) {
        val old = generated.put(alias, entry)
        specs[alias] = spec
        if (old != null) overwrites += "$alias: ${typeOf(old)} -> ${typeOf(entry)}"
    }

    /** The JVM's own implementation of [type]/[algorithm], whichever provider Robolectric left in front. */
    private fun other(type: String, algorithm: String): Provider =
        java.security.Security.getProviders().first { it !== this && it.getService(type, algorithm) != null }

    private fun typeOf(entry: Any) = if (entry is KeyPair) "EC" else "AES"

    private class FakeCertificate(private val key: PublicKey) : Certificate("X.509") {
        override fun getEncoded(): ByteArray = key.encoded
        override fun verify(key: PublicKey?) = Unit
        override fun verify(key: PublicKey?, sigProvider: String?) = Unit
        override fun toString(): String = "stand-in certificate"
        override fun getPublicKey(): PublicKey = key
    }

    private inner class Store : KeyStoreSpi() {
        override fun engineGetKey(alias: String?, password: CharArray?): Key? = when (val e = generated[alias]) {
            is KeyPair -> e.private
            is SecretKey -> e
            else -> null
        }
        override fun engineGetCertificateChain(alias: String?): Array<Certificate>? =
            (generated[alias] as? KeyPair)?.let { arrayOf(FakeCertificate(it.public)) }
        override fun engineGetCertificate(alias: String?): Certificate? = engineGetCertificateChain(alias)?.first()
        override fun engineGetEntry(alias: String?, protParam: KeyStore.ProtectionParameter?): KeyStore.Entry? = when (val e = generated[alias]) {
            is KeyPair -> KeyStore.PrivateKeyEntry(e.private as PrivateKey, arrayOf(FakeCertificate(e.public)))
            is SecretKey -> KeyStore.SecretKeyEntry(e)
            else -> null
        }
        override fun engineGetCreationDate(alias: String?): Date? = Date(0)
        override fun engineSetKeyEntry(alias: String?, key: Key?, password: CharArray?, chain: Array<out Certificate>?) = throw UnsupportedOperationException()
        override fun engineSetKeyEntry(alias: String?, key: ByteArray?, chain: Array<out Certificate>?) = throw UnsupportedOperationException()
        override fun engineSetCertificateEntry(alias: String?, cert: Certificate?) = throw UnsupportedOperationException()
        override fun engineDeleteEntry(alias: String?) {
            generated.remove(alias)
            specs.remove(alias)
        }
        override fun engineAliases(): Enumeration<String> = Collections.enumeration(generated.keys.toList())
        override fun engineContainsAlias(alias: String?): Boolean = generated.containsKey(alias)
        override fun engineSize(): Int = generated.size
        override fun engineIsKeyEntry(alias: String?): Boolean = generated.containsKey(alias)
        override fun engineIsCertificateEntry(alias: String?): Boolean = false
        override fun engineGetCertificateAlias(cert: Certificate?): String? = null
        override fun engineStore(stream: OutputStream?, password: CharArray?) = Unit
        override fun engineLoad(stream: InputStream?, password: CharArray?) = Unit
        override fun engineEntryInstanceOf(alias: String?, entryClass: Class<out KeyStore.Entry>?): Boolean = when (generated[alias]) {
            is KeyPair -> entryClass == KeyStore.PrivateKeyEntry::class.java
            is SecretKey -> entryClass == KeyStore.SecretKeyEntry::class.java
            else -> false
        }
    }

    inner class PairGenerator : KeyPairGeneratorSpi() {
        private var spec: KeyGenParameterSpec? = null
        override fun initialize(keysize: Int, random: SecureRandom?) = throw UnsupportedOperationException("a KeyGenParameterSpec is required")
        override fun initialize(params: AlgorithmParameterSpec?, random: SecureRandom?) {
            spec = params as? KeyGenParameterSpec ?: throw InvalidAlgorithmParameterException("a KeyGenParameterSpec is required")
        }
        override fun generateKeyPair(): KeyPair {
            val spec = checkNotNull(spec) { "initialize first" }
            // No StrongBox on a JVM: the SDK's fall-through to the TEE request is what runs.
            if (spec.isStrongBoxBacked) throw android.security.keystore.StrongBoxUnavailableException("this JVM has no StrongBox")
            val pair = KeyPairGenerator.getInstance("EC", other("KeyPairGenerator", "EC")).apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
            put(spec.keystoreAlias, pair, spec)
            return pair
        }
    }

    inner class AesGenerator : KeyGeneratorSpi() {
        private var spec: KeyGenParameterSpec? = null
        override fun engineInit(random: SecureRandom?) = throw UnsupportedOperationException("a KeyGenParameterSpec is required")
        override fun engineInit(params: AlgorithmParameterSpec?, random: SecureRandom?) {
            spec = params as? KeyGenParameterSpec ?: throw InvalidAlgorithmParameterException("a KeyGenParameterSpec is required")
        }
        override fun engineInit(keysize: Int, random: SecureRandom?) = throw UnsupportedOperationException("a KeyGenParameterSpec is required")
        override fun engineGenerateKey(): SecretKey {
            val spec = checkNotNull(spec) { "initialize first" }
            val key = KeyGenerator.getInstance("AES", other("KeyGenerator", "AES")).apply { init(256) }.generateKey()
            put(spec.keystoreAlias, key, spec)
            return key
        }
    }
}
