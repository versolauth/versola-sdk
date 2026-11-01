package versola.sdk.storage

import android.security.keystore.KeyGenParameterSpec
import java.io.InputStream
import java.io.OutputStream
import java.security.InvalidAlgorithmParameterException
import java.security.Key
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
import javax.crypto.KeyGenerator
import javax.crypto.KeyGeneratorSpi
import javax.crypto.SecretKey

/**
 * A JVM stand-in for the Android Keystore's AES half, enough for `KeystoreStorageKeys`: a
 * `KeyStore` and a `KeyGenerator` registered as `AndroidKeyStore`. [specs] keeps, per alias, the
 * `KeyGenParameterSpec` the key behind the entry was generated with, so a test can ask what the
 * key *requires* (user authentication) without a device; that is the property the real Keystore
 * reports through `KeyInfo`. Entries live as long as the instance, so a second provider over the
 * same alias finds what the first one generated, as a second process would.
 */
internal class AesAndroidKeyStore : Provider("AndroidKeyStore", 1.0, "JVM stand-in for the Keystore's AES keys") {

    val aesKeys = ConcurrentHashMap<String, SecretKey>()
    val specs = ConcurrentHashMap<String, KeyGenParameterSpec>()
    var generations = 0
        private set

    init {
        putService(object : Service(this, "KeyStore", "AndroidKeyStore", Store::class.java.name, null, null) {
            override fun newInstance(constructorParameter: Any?): Any = Store()
        })
        putService(object : Service(this, "KeyGenerator", "AES", Generator::class.java.name, null, null) {
            override fun newInstance(constructorParameter: Any?): Any = Generator()
        })
    }

    private inner class Store : KeyStoreSpi() {
        override fun engineGetKey(alias: String?, password: CharArray?): Key? = aesKeys[alias]
        override fun engineGetEntry(alias: String?, protParam: KeyStore.ProtectionParameter?): KeyStore.Entry? =
            aesKeys[alias]?.let { KeyStore.SecretKeyEntry(it) }
        override fun engineGetCertificateChain(alias: String?): Array<Certificate>? = null
        override fun engineGetCertificate(alias: String?): Certificate? = null
        override fun engineGetCreationDate(alias: String?): Date? = Date(0)
        override fun engineSetKeyEntry(alias: String?, key: Key?, password: CharArray?, chain: Array<out Certificate>?) = throw UnsupportedOperationException()
        override fun engineSetKeyEntry(alias: String?, key: ByteArray?, chain: Array<out Certificate>?) = throw UnsupportedOperationException()
        override fun engineSetCertificateEntry(alias: String?, cert: Certificate?) = throw UnsupportedOperationException()
        override fun engineDeleteEntry(alias: String?) {
            aesKeys.remove(alias)
            specs.remove(alias)
        }
        override fun engineAliases(): Enumeration<String> = Collections.enumeration(aesKeys.keys.toList())
        override fun engineContainsAlias(alias: String?): Boolean = aesKeys.containsKey(alias)
        override fun engineSize(): Int = aesKeys.size
        override fun engineIsKeyEntry(alias: String?): Boolean = aesKeys.containsKey(alias)
        override fun engineIsCertificateEntry(alias: String?): Boolean = false
        override fun engineGetCertificateAlias(cert: Certificate?): String? = null
        override fun engineStore(stream: OutputStream?, password: CharArray?) = Unit
        override fun engineLoad(stream: InputStream?, password: CharArray?) = Unit
        override fun engineEntryInstanceOf(alias: String?, entryClass: Class<out KeyStore.Entry>?): Boolean =
            aesKeys.containsKey(alias) && entryClass == KeyStore.SecretKeyEntry::class.java
    }

    private inner class Generator : KeyGeneratorSpi() {
        private var spec: KeyGenParameterSpec? = null
        override fun engineInit(random: SecureRandom?) = throw UnsupportedOperationException("a KeyGenParameterSpec is required")
        override fun engineInit(keysize: Int, random: SecureRandom?) = throw UnsupportedOperationException("a KeyGenParameterSpec is required")
        override fun engineInit(params: AlgorithmParameterSpec?, random: SecureRandom?) {
            spec = params as? KeyGenParameterSpec ?: throw InvalidAlgorithmParameterException("a KeyGenParameterSpec is required")
        }
        override fun engineGenerateKey(): SecretKey {
            val spec = checkNotNull(spec) { "initialize first" }
            val other = java.security.Security.getProviders().first { it !== this@AesAndroidKeyStore && it.getService("KeyGenerator", "AES") != null }
            val key = KeyGenerator.getInstance("AES", other).apply { init(256) }.generateKey()
            aesKeys[spec.keystoreAlias] = key
            specs[spec.keystoreAlias] = spec
            generations++
            return key
        }
    }
}
