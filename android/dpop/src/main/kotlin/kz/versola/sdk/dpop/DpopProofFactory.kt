package kz.versola.sdk.dpop

import java.net.URI
import java.util.UUID
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Mints RFC 9449 proofs: one per request, signed by the one [DpopKey] this installation holds.
 *
 * Holds the nonce cache and the learned clock offset because a proof needs both and neither
 * belongs to a single request. Performs no HTTP itself — the token endpoint (#8) and the
 * authenticated client (#9) call [proof] on the way out and [observe] on the way back.
 */
public class DpopProofFactory(
    private val key: DpopKey,
    public val nonces: DpopNonceCache = DpopNonceCache(),
    public val clockSkew: ClockSkew = ClockSkew(),
    private val jti: () -> String = { UUID.randomUUID().toString() },
) {

    /**
     * A proof for one request.
     *
     * @param accessToken adds the §4.2 `ath` binding. Required by a resource server and
     *   impossible at the token endpoint, which has no token yet to hash — so its presence is
     *   decided by the caller having one, not by configuration.
     */
    public suspend fun proof(
        method: String,
        url: String,
        accessToken: String? = null,
    ): String {
        val header = """{"typ":"dpop+jwt","alg":"ES256","jwk":${key.publicJwk()}}"""
        val claims = buildJsonObject {
            put("htm", method.uppercase())
            put("htu", htu(url))
            put("iat", clockSkew.nowSeconds())
            put("jti", jti())
            nonces.nonceFor(url)?.let { put("nonce", it) }
            accessToken?.let { put("ath", ath(it)) }
        }
        val signingInput =
            "${Jose.base64Url(header.toByteArray(Charsets.UTF_8))}.${Jose.base64Url(encode(claims))}"
        val signature = key.sign(signingInput.toByteArray(Charsets.US_ASCII))
        return "$signingInput.${Jose.base64Url(signature)}"
    }

    /**
     * Takes from a response the two things that change how the next proof is minted: the
     * server's clock, and a nonce it issued.
     *
     * Called for every response, not only for challenges — the `Date` header on a *successful*
     * response is the cheapest place to learn the offset, and waiting for a rejection to learn
     * it means paying for one rejection per process.
     */
    public fun observe(url: String, dateHeader: String?, nonceHeader: String?) {
        clockSkew.learn(dateHeader)
        if (!nonceHeader.isNullOrEmpty()) nonces.store(url, nonceHeader)
    }

    /**
     * RFC 9449 §4.3 step 9 compares `htu` against the request URI "ignoring any query and
     * fragment parts". Stripping them here rather than sending the full URL keeps the claim
     * equal to what the server reconstructs, and keeps query parameters — which on an
     * authorization-adjacent request can carry identifiers — out of a token the server logs.
     *
     * Built from the raw authority and path, matching `Dpop.normalizeHtu` on the server side:
     * decoding first would collapse `/a%2Fb` and `/a/b` into one string, which is exactly the
     * confusion `htu` exists to rule out.
     */
    private fun htu(url: String): String {
        val uri = URI(url)
        val authority = uri.rawAuthority ?: ""
        val path = uri.rawPath ?: ""
        return "${uri.scheme}://$authority$path"
    }

    /** §4.2: `base64url(SHA-256(ASCII(access token)))`. */
    private fun ath(accessToken: String): String =
        Jose.base64Url(Jose.sha256(accessToken.toByteArray(Charsets.US_ASCII)))

    private fun encode(claims: JsonObject): ByteArray =
        Json.encodeToString(JsonObject.serializer(), claims).toByteArray(Charsets.UTF_8)
}
