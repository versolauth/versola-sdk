package versola.sdk.dpop

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaLogger

/**
 * EC P-256 in the Android Keystore, non-exportable, generated on first use.
 *
 * ES256 is not a choice: RFC 9449 §5 mandates it, `Dpop.Algorithm.Default` accepts it, and it
 * is exactly what P-256 hardware produces. There is no algorithm parameter anywhere in this
 * module.
 *
 * **Not user-authentication-gated under any `UnlockPolicy`**, and that is platform-enforced
 * rather than a preference: Android fails biometric authentication while the app is not in the
 * foreground, so a gated key would break background refresh outright (#1 §4). A policy moves
 * the storage key alone — gating a key that signs a proof on every request is a prompt per
 * request under another name, which `spec/state-machine.md` rules out.
 *
 * Distinct from `HardwareKeyProvider`'s storage key: two keys, two purposes, one knob.
 * Encrypting a refresh token at rest and proving possession of a device are different
 * mechanisms and must not share a lifetime — this one is destroyed on logout (#10).
 */
public class KeystoreDpopKey(
    private val alias: String = DEFAULT_ALIAS,
    private val requireHardware: Boolean = false,
    private val logger: VersolaLogger? = null,
) : DpopKey {

    private class Material(
        val privateKey: PrivateKey,
        val jwk: String,
        val jkt: String,
        val attestation: KeyAttestation,
    )

    private val mutex = Mutex()
    private var material: Material? = null

    override suspend fun jkt(): String = material().jkt

    override suspend fun publicJwk(): String = material().jwk

    override suspend fun attestation(): KeyAttestation = material().attestation

    /**
     * Destroys the key and forgets it, so the next proof is signed by a freshly generated one
     * with a different `jkt` — scenario 18's assertion. Logout does this (#10): the key is
     * cheap to regenerate and its whole purpose is binding one grant to one
     * device-installation, so carrying it into the next user's session on a shared device
     * would defeat it.
     *
     * Under the same lock as [material], so a proof being minted concurrently signs with the
     * key it loaded and the next one starts over, rather than either seeing a half-deleted
     * entry.
     */
    public suspend fun destroy() {
        mutex.withLock {
            withContext(Dispatchers.IO) { destroy(alias) }
            material = null
        }
    }

    override suspend fun sign(signingInput: ByteArray): ByteArray {
        val key = material().privateKey
        return withContext(Dispatchers.IO) {
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initSign(key)
            signature.update(signingInput)
            Jose.derToJose(signature.sign())
        }
    }

    private suspend fun material(): Material = mutex.withLock {
        material?.let { return@withLock it }
        withContext(Dispatchers.IO) { load() ?: generate() }
            .also {
                if (requireHardware && !it.attestation.isHardwareBacked) {
                    throw VersolaError.Configuration(
                        VersolaError.Configuration.Detail.HardwareBindingUnavailable(
                            "this device produced a software-backed DPoP key",
                        ),
                    )
                }
                if (!it.attestation.isHardwareBacked) {
                    logger?.warn(
                        "DPoP key is software-backed: this device has no hardware keystore. " +
                            "Set TokenBinding.Dpop(requireHardware = true) to refuse this.",
                    )
                }
                material = it
            }
    }

    private fun load(): Material? {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry ?: return null
        return material(entry.privateKey, entry.certificate.publicKey as ECPublicKey)
    }

    private fun generate(): Material {
        // StrongBox first, and the fall-through is the whole reason this is runtime work:
        // asking for it on a device without the chip throws rather than degrading, and a
        // compile-time decision would either exclude API 26–27 or never use StrongBox at all.
        val pair = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            withStrongBoxFallback(logger) { strongBox -> generate(strongBox) }
        } else {
            generate(strongBox = false)
        }
        return material(pair.private, pair.public as ECPublicKey)
    }

    private fun generate(strongBox: Boolean): java.security.KeyPair {
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec(CURVE))
            .setDigests(KeyProperties.DIGEST_SHA256)
            // Explicit rather than defaulted: the default is already false, and this is the
            // line a future reader will look for when asking why refresh works in the
            // background. See the class comment and #1 §4.
            .setUserAuthenticationRequired(false)
            .apply {
                if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setIsStrongBoxBacked(true)
                }
            }
            .build()
        generator.initialize(spec)
        return generator.generateKeyPair()
    }

    private fun material(privateKey: PrivateKey, publicKey: ECPublicKey): Material {
        val jwk = Jose.canonicalJwk(publicKey)
        return Material(
            privateKey = privateKey,
            jwk = jwk,
            jkt = Jose.thumbprint(jwk),
            attestation = attestationOf(privateKey),
        )
    }

    /**
     * Read back from the key the Keystore actually produced, never from what was requested:
     * `setIsStrongBoxBacked(true)` succeeding is not by itself proof of where the key landed.
     */
    private fun attestationOf(privateKey: PrivateKey): KeyAttestation {
        val info = try {
            KeyFactory.getInstance(privateKey.algorithm, KEYSTORE)
                .getKeySpec(privateKey, KeyInfo::class.java)
        } catch (e: Exception) {
            logger?.warn("Keystore did not report a security level, assuming software: ${e.message}")
            return KeyAttestation.Software
        }
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeyAttestation.StrongBox
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeyAttestation.TrustedEnvironment
                // SECURITY_LEVEL_UNKNOWN_SECURE is hardware of an unnamed kind; it satisfies
                // requireHardware, and claiming StrongBox for it would not.
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> KeyAttestation.TrustedEnvironment
                else -> KeyAttestation.Software
            }
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) KeyAttestation.TrustedEnvironment else KeyAttestation.Software
        }
    }

    public companion object {
        /** Distinct from `HardwareKeyProvider.DEFAULT_ALIAS`: two keys, two purposes (#1 §4). */
        public const val DEFAULT_ALIAS: String = "versola.dpop-key"

        private const val KEYSTORE = "AndroidKeyStore"
        private const val CURVE = "secp256r1"

        /**
         * Deletes the Keystore entry under [alias]. The instance method [KeystoreDpopKey.destroy]
         * is the one logout calls — it also drops the loaded material, which this cannot — and
         * this remains for a caller cleaning up an alias no instance holds.
         */
        public fun destroy(alias: String = DEFAULT_ALIAS) {
            KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(alias)
        }
    }
}

/**
 * Runs [generate] with StrongBox, and with the TEE when that attempt fails with a
 * `ProviderException`.
 *
 * Not only `StrongBoxUnavailableException`, which is a `ProviderException` and which the
 * Keystore raises for the one error code "hardware type unavailable": every other error of a
 * StrongBox that is present and misbehaving (a communication failure, an operation it does
 * not implement) is thrown by `generateKeyPair` as a plain `ProviderException`, and caught
 * only by the narrower type it used to break `login()` on those devices for good. A failed
 * generation deletes the entry it started, so the TEE attempt under the same alias is clean.
 *
 * A fault that is not [isAbsent] may be transient (a busy secure element), and the key is
 * generated once and kept, so falling through on it would pin the TEE tier for the key's whole
 * life: StrongBox is tried a second time first. Absence is final and falls through at once.
 * Anything that is not a `ProviderException` is not read as "no StrongBox" and propagates, as
 * does a failure of the TEE attempt itself.
 */
internal fun <T> withStrongBoxFallback(
    logger: VersolaLogger?,
    isAbsent: (ProviderException) -> Boolean = { it is StrongBoxUnavailableException },
    generate: (strongBox: Boolean) -> T,
): T =
    try {
        try {
            generate(true)
        } catch (e: ProviderException) {
            if (isAbsent(e)) throw e
            logger?.info("StrongBox key generation failed (${e.javaClass.simpleName}), retrying once: ${e.message}")
            generate(true)
        }
    } catch (e: ProviderException) {
        logger?.info("StrongBox unavailable (${e.javaClass.simpleName}), falling back to the TEE: ${e.message}")
        generate(false)
    }
