package versola.oauth.conformance

import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/**
 * The key the ID-token scenarios (25 to 27) re-sign with: the proxy serves its JWKS in place of
 * the provider's and rewrites the token response's `id_token` so that exactly the claim under
 * test differs from what the provider issued. Generated per test; nothing here is a real key.
 */
class HarnessSigner(val kid: String = "harness") {
    val keys: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    fun jwks(): String {
        val public = keys.public as RSAPublicKey
        return """{"keys":[{"kty":"RSA","kid":"$kid","alg":"RS256","use":"sig","n":"${unsigned(public.modulus)}","e":"${unsigned(public.publicExponent)}"}]}"""
    }

    /** [idToken]'s payload with [mutate] applied, signed by this key under [alg] and [kid]. */
    fun resign(idToken: String, alg: String = "RS256", kid: String? = this.kid, mutate: (JsonObject) -> JsonObject): String {
        val payload = mutate(Transcript.decodeJwtPart(idToken, 1) ?: error("not a JWT"))
        val header = buildString {
            append("""{"alg":"$alg","typ":"JWT"""")
            if (kid != null) append(""","kid":"$kid"""")
            append("}")
        }
        val signingInput = "${b64(header.toByteArray())}.${b64(payload.toString().toByteArray())}"
        val signature = when (alg) {
            "RS256" -> Signature.getInstance("SHA256withRSA").apply {
                initSign(keys.private)
                update(signingInput.toByteArray())
            }.sign()
            "none" -> ByteArray(0)
            // HS256 with the client id as the key: the classic algorithm-confusion attempt.
            "HS256" -> javax.crypto.Mac.getInstance("HmacSHA256").apply {
                init(javax.crypto.spec.SecretKeySpec(Provider.CLIENT_ID.toByteArray(), "HmacSHA256"))
            }.doFinal(signingInput.toByteArray())
            else -> error("no signer for $alg")
        }
        return "$signingInput.${b64(signature)}"
    }

    companion object {
        fun b64(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        private fun unsigned(value: BigInteger): String {
            val bytes = value.toByteArray()
            return b64(if (bytes[0] == 0.toByte()) bytes.copyOfRange(1, bytes.size) else bytes)
        }

        /** [response] with its `id_token` replaced. */
        fun withIdToken(response: JsonObject, idToken: String): JsonObject =
            JsonObject(response + ("id_token" to JsonPrimitive(idToken)))

        fun JsonObject.with(vararg entries: Pair<String, kotlinx.serialization.json.JsonElement>): JsonObject =
            JsonObject(this + entries)

        fun JsonObject.without(vararg names: String): JsonObject = JsonObject(filterKeys { it !in names })

        fun parse(json: String): JsonObject = Json.parseToJsonElement(json).jsonObject
    }
}
