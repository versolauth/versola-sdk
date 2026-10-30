package versola.oauth.core

import kotlinx.coroutines.currentCoroutineContext

import java.security.InvalidKeyException
import java.security.PublicKey
import java.security.Signature
import java.security.SignatureException
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.security.GeneralSecurityException
import java.security.NoSuchAlgorithmException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Why a JWS was refused, before the caller decides what that means for it. An ID token maps it
 * to `IdTokenRejected(reason)` and a signed UserInfo response to `UserInfoRejected`; the check
 * itself is the same, so it is written once and the reason is the closed enum the ID-token
 * error already has.
 *
 * Not a [VersolaError]: it never leaves this module's validation code. A network failure or a
 * missing capability while verifying is a [VersolaError] and passes through untouched.
 */
internal class JwsRejection(val reason: IdTokenRejection, detail: String? = null) :
    Exception(detail ?: reason.name)

/**
 * The asymmetric JWS algorithms an ID token may use, and nothing else (`spec/oauth-sdk-api.md`
 * section 11). `none` and the HMAC family are not members and cannot become one by
 * configuration: a public client holds no secret to verify an HMAC with, so a token claiming
 * `HS256` is either an attack (the key-confusion downgrade, where the provider's public key is
 * used as the HMAC secret) or a provider this SDK cannot talk to.
 */
internal enum class JwsAlgorithm(
    val jose: String,
    val keyType: String,
    /** JCA name for RSA PKCS#1 v1.5 and ECDSA; for PSS the digest name in [digest]. */
    val jcaName: String,
    val digest: String,
    /** Width in bytes of each of R and S for ECDSA; 0 for RSA. */
    val ecComponentBytes: Int = 0,
    val pss: Boolean = false,
) {
    RS256("RS256", "RSA", "SHA256withRSA", "SHA-256"),
    RS384("RS384", "RSA", "SHA384withRSA", "SHA-384"),
    RS512("RS512", "RSA", "SHA512withRSA", "SHA-512"),
    PS256("PS256", "RSA", "RSASSA-PSS", "SHA-256", pss = true),
    PS384("PS384", "RSA", "RSASSA-PSS", "SHA-384", pss = true),
    PS512("PS512", "RSA", "RSASSA-PSS", "SHA-512", pss = true),
    ES256("ES256", "EC", "SHA256withECDSA", "SHA-256", ecComponentBytes = 32),
    ES384("ES384", "EC", "SHA384withECDSA", "SHA-384", ecComponentBytes = 48),

    // P-521, not 512: the curve's order is 521 bits, which is 66 bytes (RFC 7518 3.4).
    ES512("ES512", "EC", "SHA512withECDSA", "SHA-512", ecComponentBytes = 66);

    /** Bytes of the digest; `at_hash` takes the left half of it (Core 3.1.3.6). */
    val digestBytes: Int get() = when (digest) {
        "SHA-256" -> 32
        "SHA-384" -> 48
        else -> 64
    }

    companion object {
        fun forName(name: String): JwsAlgorithm? = entries.firstOrNull { it.jose == name }
    }
}

/**
 * A compact JWS taken apart but not yet trusted: nothing in [header] or [payload] means
 * anything until [Jws.verify] has said the signature holds.
 */
internal class ParsedJws(
    val header: JsonObject,
    val payload: JsonObject,
    /** `BASE64URL(header) "." BASE64URL(payload)` as it came, the exact bytes that were signed (RFC 7515 5.2). */
    val signingInput: ByteArray,
    val signature: ByteArray,
) {
    val alg: String? get() = (header["alg"] as? JsonPrimitive)?.takeIf { it.isString }?.content
    val kid: String? get() = (header["kid"] as? JsonPrimitive)?.takeIf { it.isString }?.content
    val typ: String? get() = (header["typ"] as? JsonPrimitive)?.takeIf { it.isString }?.content

    /** Claim values and the token itself are secrets-adjacent; print nothing of them. */
    override fun toString(): String = "ParsedJws(redacted)"
}

internal object Jws {

    private val json = Json

    /**
     * RFC 7515 7.2 for the compact form: exactly three dot-separated base64url parts, a header
     * that is a JSON object with a string `alg`, a payload that is a JSON object (the only
     * payload an ID token or a UserInfo JWT has).
     *
     * A header carrying `crit` is refused: it lists extensions the recipient MUST understand
     * and this verifier understands none, so accepting it would be ignoring a MUST.
     *
     * @throws JwsRejection with [IdTokenRejection.Malformed].
     */
    fun parse(compact: String): ParsedJws {
        val parts = compact.split('.')
        if (parts.size != 3) throw JwsRejection(IdTokenRejection.Malformed, "not three JWS segments")
        val header = parseObject(parts[0], "header")
        val payload = parseObject(parts[1], "payload")
        val signature = try {
            Base64Url.decode(parts[2])
        } catch (e: IllegalArgumentException) {
            throw JwsRejection(IdTokenRejection.Malformed, "signature is not base64url")
        }
        if (header["alg"].let { it !is JsonPrimitive || !it.isString }) {
            throw JwsRejection(IdTokenRejection.Malformed, "header has no string alg")
        }
        if ("crit" in header) throw JwsRejection(IdTokenRejection.Malformed, "unsupported crit header")
        return ParsedJws(
            header = header,
            payload = payload,
            signingInput = (parts[0] + "." + parts[1]).toByteArray(Charsets.US_ASCII),
            signature = signature,
        )
    }

    private fun parseObject(segment: String, what: String): JsonObject {
        val bytes = try {
            Base64Url.decode(segment)
        } catch (e: IllegalArgumentException) {
            throw JwsRejection(IdTokenRejection.Malformed, "$what is not base64url")
        }
        return try {
            json.parseToJsonElement(bytes.toString(Charsets.UTF_8)) as? JsonObject
                ?: throw JwsRejection(IdTokenRejection.Malformed, "$what is not a JSON object")
        } catch (e: JwsRejection) {
            throw e
        } catch (e: Exception) {
            throw JwsRejection(IdTokenRejection.Malformed, "$what is not JSON")
        }
    }

    /**
     * Whether [key] is one this [algorithm] may be verified with. A key of the wrong type is
     * refused rather than handed to the JCA to fail (or, worse, not fail): ES256 with a P-384
     * key is not ES256, and an RSA key under 2048 bits is not one this SDK trusts a provider
     * to have published on purpose.
     */
    fun suits(key: PublicKey, algorithm: JwsAlgorithm): Boolean = when {
        algorithm.keyType == "RSA" -> key is RSAPublicKey && key.modulus.bitLength() >= MIN_RSA_BITS
        else -> key is ECPublicKey &&
            (key.params.order.bitLength() + 7) / 8 == algorithm.ecComponentBytes
    }

    /** Whether the signature over [ParsedJws.signingInput] verifies under [key]. Never throws for a bad signature. */
    fun verify(token: ParsedJws, key: PublicKey, algorithm: JwsAlgorithm): Boolean {
        if (!suits(key, algorithm)) return false
        return try {
            val signature = if (algorithm.pss) pssSignature(algorithm) else Signature.getInstance(algorithm.jcaName)
            signature.initVerify(key)
            signature.update(token.signingInput)
            if (algorithm.ecComponentBytes > 0) {
                val der = joseToDer(token.signature, algorithm.ecComponentBytes) ?: return false
                signature.verify(der)
            } else {
                signature.verify(token.signature)
            }
        } catch (e: GeneralSecurityException) {
            // SignatureException and InvalidKeyException are a bad signature or key; a
            // NoSuchAlgorithmException or InvalidAlgorithmParameterException is a platform
            // without the algorithm. None of them may leave as a raw exception: the token is
            // simply not verified, and the caller reports it as such.
            false
        }
    }

    /**
     * Android names the PSS family `SHA256withRSA/PSS` (API 23+) and does not list the JDK's
     * `RSASSA-PSS` with explicit parameters for the supported range; the JDK (11+) has the
     * latter and not the former. Try Android's name first, so a device never reaches the
     * fallback, and fall back for the unit tests on a JDK.
     */
    private fun pssSignature(algorithm: JwsAlgorithm): Signature = try {
        Signature.getInstance(algorithm.digest.replace("-", "") + "withRSA/PSS")
    } catch (e: NoSuchAlgorithmException) {
        Signature.getInstance("RSASSA-PSS").apply {
            // RFC 7518 3.5: MGF1 with the same digest, and a salt as long as the digest.
            setParameter(
                PSSParameterSpec(algorithm.digest, "MGF1", MGF1ParameterSpec(algorithm.digest), algorithm.digestBytes, 1),
            )
        }
    }

    /**
     * RFC 7515 A.3.1: a JOSE ECDSA signature is `R || S`, each a big-endian integer padded to
     * the curve's fixed width. The JCA wants ASN.1 DER, `SEQUENCE { INTEGER r, INTEGER s }`.
     * Wrong total length is not a signature, so null.
     *
     * Each INTEGER is minimal and non-negative: leading zero bytes dropped, one `0x00` put
     * back when the top bit is set (otherwise DER reads it as negative), and a zero value
     * stays the single byte `00`. The sequence length needs the long form when it exceeds 127,
     * which P-521 always does (two 66-byte integers).
     */
    fun joseToDer(signature: ByteArray, componentBytes: Int): ByteArray? {
        if (signature.size != 2 * componentBytes) return null
        val r = derInteger(signature.copyOfRange(0, componentBytes))
        val s = derInteger(signature.copyOfRange(componentBytes, signature.size))
        val body = r + s
        return byteArrayOf(0x30) + derLength(body.size) + body
    }

    private fun derInteger(unsigned: ByteArray): ByteArray {
        var start = 0
        while (start < unsigned.size - 1 && unsigned[start] == 0.toByte()) start++
        var value = unsigned.copyOfRange(start, unsigned.size)
        if (value[0].toInt() and 0x80 != 0) value = byteArrayOf(0) + value
        return byteArrayOf(0x02) + derLength(value.size) + value
    }

    private fun derLength(length: Int): ByteArray = when {
        length < 0x80 -> byteArrayOf(length.toByte())
        length < 0x100 -> byteArrayOf(0x81.toByte(), length.toByte())
        else -> byteArrayOf(0x82.toByte(), (length shr 8).toByte(), length.toByte())
    }

    private const val MIN_RSA_BITS = 2048
}

/**
 * Parses a compact JWS and proves it was signed by a key the provider publishes, which is the
 * part ID-token validation and signed-UserInfo verification share. Everything after the
 * signature (`iss`, `aud`, times) is the caller's, because it differs.
 *
 * Order is part of the contract, and cheap checks come first so that a refused token costs
 * nothing: structure, then the algorithm (closed set, then the provider's advertised list),
 * and only then `jwks_uri` and the network. In particular `none` and `HS256` are refused
 * before anything is fetched, so a forged token cannot be used to make the SDK send requests.
 *
 * A key is chosen by `kid`; a token without one is checked against the only suitable key, and
 * refused when several are (guessing which to try is how a verifier ends up accepting a
 * signature from a key the provider retired). A `kid` the set does not hold earns exactly one
 * refetch of the set, because that is what a rotation looks like, and then a refusal.
 *
 * Suppliers are suspending because discovery is lazy and owned by another component.
 */
@VersolaInternalApi
public class JwsVerifier(
    private val jwksUri: suspend () -> String?,
    private val allowedAlgorithms: suspend () -> List<String>,
    private val jwks: JwksClient,
) {

    /**
     * @return the parsed token, whose [ParsedJws.payload] is now trustworthy.
     * @throws JwsRejection [IdTokenRejection.Malformed], [IdTokenRejection.Algorithm] or
     *   [IdTokenRejection.Signature].
     * @throws VersolaError.Configuration(ProviderUnsupported("jwks_uri")) when discovery has
     *   no `jwks_uri`, [VersolaError.Recoverable] when the key set cannot be fetched.
     */
    internal suspend fun verify(compact: String): ParsedJws {
        val token = Jws.parse(compact)
        val algorithm = token.alg?.let(JwsAlgorithm::forName)
            ?: throw JwsRejection(IdTokenRejection.Algorithm, "alg is not in the closed asymmetric set")
        val advertised = allowedAlgorithms()
        if (advertised.isNotEmpty() && algorithm.jose !in advertised) {
            throw JwsRejection(IdTokenRejection.Algorithm, "alg is not advertised by the provider")
        }
        val uri = jwksUri() ?: throw VersolaError.Configuration(
            VersolaError.Configuration.Detail.ProviderUnsupported("jwks_uri"),
        )

        val allowStale = currentCoroutineContext()[StaleKeysAllowed] != null
        var loaded = jwks.keys(uri, forceRefresh = false, allowStale = allowStale)
        var candidates = select(loaded.keys, token, algorithm)
        if (candidates.isEmpty() && !loaded.fetched && !loaded.stale) {
            // One refetch, and only when the set in hand was not itself just fetched: a cold
            // start that found no such key has already asked the provider.
            loaded = jwks.keys(uri, forceRefresh = true, allowStale = allowStale)
            candidates = select(loaded.keys, token, algorithm)
        }
        // A stale set that lacks the token's `kid` proves an outage and nothing else: the key may be
        // exactly the one the provider has published since. Recoverable, never a rejection.
        if (candidates.isEmpty() && loaded.stale) {
            throw loaded.cause ?: VersolaError.Recoverable(VersolaError.Recoverable.Cause.Network("the key set is unreachable"))
        }
        if (candidates.none { Jws.verify(token, it.publicKey, algorithm) }) {
            throw JwsRejection(IdTokenRejection.Signature, "no key at jwks_uri verifies the signature")
        }
        return token
    }

    /**
     * The keys that could have signed [token]: right type, usable for signing, not pinned to
     * another `alg`, suited to the algorithm's curve or size, and matching `kid` when the
     * token names one. Without a `kid` more than one candidate is ambiguous and is refused
     * outright (a refetch would not make it less so).
     */
    private fun select(set: JsonWebKeySet, token: ParsedJws, algorithm: JwsAlgorithm): List<JsonWebKey> {
        val suitable = set.keys.filter { key ->
            key.keyType == algorithm.keyType &&
                (key.use == null || key.use == "sig") &&
                (key.algorithm == null || key.algorithm == algorithm.jose) &&
                Jws.suits(key.publicKey, algorithm)
        }
        val kid = token.kid
        if (kid != null) return suitable.filter { it.keyId == kid }
        if (suitable.size > 1) {
            throw JwsRejection(IdTokenRejection.Signature, "token has no kid and several keys could have signed it")
        }
        return suitable
    }
}

/**
 * The signature check alone, for a test that must prove an algorithm on a real platform (the
 * PSS family on an Android emulator, where the JCA names differ from a JDK's). Not for apps.
 */
@VersolaInternalApi
public object JwsSignatures {
    /** Whether [signature] over [signingInput] verifies under [key] for the JOSE algorithm [algorithm]. */
    public fun verifies(algorithm: String, key: java.security.PublicKey, signingInput: ByteArray, signature: ByteArray): Boolean {
        val parsed = JwsAlgorithm.forName(algorithm) ?: return false
        val empty = kotlinx.serialization.json.JsonObject(emptyMap())
        return Jws.verify(ParsedJws(empty, empty, signingInput, signature), key, parsed)
    }
}

/**
 * Marks the coroutines that may be given a key set past its lifetime when the fetch fails as a
 * `Recoverable`, up to a week past expiry (`spec/retry-policy.md`, "A stale key set for a refresh"):
 * the check of a refresh's ID token and nothing else. A context element rather than a parameter
 * because [IdTokenValidator] is public API and the rule is the coordinator's.
 */
internal class StaleKeysAllowed : kotlin.coroutines.AbstractCoroutineContextElement(Key) {
    companion object Key : kotlin.coroutines.CoroutineContext.Key<StaleKeysAllowed>
}
