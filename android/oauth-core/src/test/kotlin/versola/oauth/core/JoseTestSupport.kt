package versola.oauth.core

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.MGF1ParameterSpec
import java.security.spec.PSSParameterSpec
import java.util.Base64
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Keys, JWKS documents and signed tokens for the JOSE tests. Written against `java.security`
 * directly and not against the code under test, so a bug in the verifier's DER conversion or
 * PSS parameters cannot be mirrored here and cancel out: this file is the second opinion.
 *
 * Key generation is the slow part (RSA 2048), so each key is generated once per test run.
 */
internal object Jose {

    val rsa: KeyPair by lazy { generate("RSA") { initialize(2048) } }
    val rsaOther: KeyPair by lazy { generate("RSA") { initialize(2048) } }
    val p256: KeyPair by lazy { ec("secp256r1") }
    val p256Other: KeyPair by lazy { ec("secp256r1") }
    val p384: KeyPair by lazy { ec("secp384r1") }
    val p521: KeyPair by lazy { ec("secp521r1") }

    private fun ec(curve: String) = generate("EC") { initialize(ECGenParameterSpec(curve)) }

    private fun generate(algorithm: String, init: KeyPairGenerator.() -> Unit): KeyPair =
        KeyPairGenerator.getInstance(algorithm).apply(init).generateKeyPair()

    private val encoder = Base64.getUrlEncoder().withoutPadding()

    fun b64(bytes: ByteArray): String = encoder.encodeToString(bytes)

    fun b64(text: String): String = b64(text.toByteArray(Charsets.UTF_8))

    private fun unsigned(value: BigInteger, width: Int = 0): ByteArray {
        val raw = value.toByteArray().let { if (it.size > 1 && it[0] == 0.toByte()) it.copyOfRange(1, it.size) else it }
        return if (width == 0) raw else ByteArray(width - raw.size) + raw
    }

    /** One JWK as JSON text. [extra] is spliced in, for `"use":"enc"` and the like. */
    fun jwk(key: KeyPair, kid: String?, alg: String? = null, extra: String = ""): String {
        val body = when (val pub = key.public) {
            is RSAPublicKey ->
                """"kty":"RSA","n":"${b64(unsigned(pub.modulus))}","e":"${b64(unsigned(pub.publicExponent))}""""
            is ECPublicKey -> {
                val width = (pub.params.order.bitLength() + 7) / 8
                val crv = when (width) { 32 -> "P-256"; 48 -> "P-384"; else -> "P-521" }
                """"kty":"EC","crv":"$crv","x":"${b64(unsigned(pub.w.affineX, width))}","y":"${b64(unsigned(pub.w.affineY, width))}""""
            }
            else -> error("unsupported key")
        }
        val parts = listOfNotNull(body, kid?.let { """"kid":"$it"""" }, alg?.let { """"alg":"$it"""" }, extra.ifEmpty { null })
        return "{" + parts.joinToString(",") + "}"
    }

    fun jwks(vararg jwks: String): String = """{"keys":[${jwks.joinToString(",")}]}"""

    /** The JCA's DER ECDSA signature to the JOSE `R || S` form, written independently of the SDK. */
    fun derToJose(der: ByteArray, width: Int): ByteArray {
        var i = 2
        if (der[1].toInt() and 0x80 != 0) i += der[1].toInt() and 0x7F
        val out = ByteArray(2 * width)
        for (part in 0..1) {
            check(der[i] == 0x02.toByte())
            val length = der[i + 1].toInt() and 0xFF
            val value = BigInteger(1, der.copyOfRange(i + 2, i + 2 + length))
            unsigned(value, width).copyInto(out, part * width)
            i += 2 + length
        }
        return out
    }

    private fun jcaSignature(alg: String): Signature = when (alg) {
        "RS256" -> Signature.getInstance("SHA256withRSA")
        "RS384" -> Signature.getInstance("SHA384withRSA")
        "RS512" -> Signature.getInstance("SHA512withRSA")
        "PS256", "PS384", "PS512" -> {
            val digest = "SHA-" + alg.substring(2)
            Signature.getInstance("RSASSA-PSS").apply {
                setParameter(PSSParameterSpec(digest, "MGF1", MGF1ParameterSpec(digest), alg.substring(2).toInt() / 8, 1))
            }
        }
        "ES256" -> Signature.getInstance("SHA256withECDSA")
        "ES384" -> Signature.getInstance("SHA384withECDSA")
        "ES512" -> Signature.getInstance("SHA512withECDSA")
        else -> error(alg)
    }

    private fun width(alg: String) = when (alg) { "ES256" -> 32; "ES384" -> 48; else -> 66 }

    /** The signature of [signingInput] under [alg], in the JOSE encoding of that algorithm. */
    fun sign(alg: String, key: PrivateKey, signingInput: String): ByteArray {
        val signature = jcaSignature(alg)
        signature.initSign(key)
        signature.update(signingInput.toByteArray(Charsets.US_ASCII))
        val raw = signature.sign()
        return if (alg.startsWith("ES")) derToJose(raw, width(alg)) else raw
    }

    /** `header.payload.signature` with the header `alg` and `kid` given. */
    fun jws(
        alg: String,
        key: PrivateKey?,
        payload: String,
        kid: String? = null,
        header: String? = null,
    ): String {
        val head = header ?: ("{" + listOfNotNull("\"alg\":\"$alg\"", "\"typ\":\"JWT\"", kid?.let { "\"kid\":\"$it\"" }).joinToString(",") + "}")
        val input = b64(head) + "." + b64(payload)
        val signature = if (key == null) ByteArray(0) else sign(alg, key, input)
        return input + "." + b64(signature)
    }

    fun json(map: Map<String, JsonElement>): String = JsonObject(map).toString()

    fun str(value: String): JsonElement = JsonPrimitive(value)

    fun num(value: Long): JsonElement = JsonPrimitive(value)

    val absent: JsonElement = JsonNull
}
