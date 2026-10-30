package versola.oauth.conformance

import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPair
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.RSAPublicKeySpec
import java.util.Base64
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import mockwebserver3.Dispatcher
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import okhttp3.OkHttpClient
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import okhttp3.Request

/**
 * Why a DPoP-verifying resource server refused a request. One value per check of RFC 9449
 * section 7.1 / 4.3, so a negative test names the check it is about and a verdict for another
 * reason is a failure rather than a pass: a request that is refused for the wrong reason has
 * not shown that the right check exists.
 */
enum class DpopRefusal {
    NoAuthorization,

    /** The token was presented under a scheme other than `DPoP` (RFC 9449 section 7.1). */
    WrongScheme,
    NoProof,
    MultipleProofs,
    TokenMalformed,
    TokenSignature,
    TokenIssuer,
    TokenExpired,

    /** The access token carries no `cnf.jkt`: it is not sender-constrained, so DPoP proves nothing about it. */
    TokenNotBound,
    ProofMalformed,
    ProofType,
    ProofAlgorithm,
    ProofKey,
    ProofSignature,
    Method,
    Url,
    IssuedAt,
    ReplayedJti,
    AccessTokenHash,

    /** The proof is valid but its key is not the one the token is bound to (`cnf.jkt`). */
    KeyMismatch,
    NonceRequired,
}

/** What the resource server did with one request. */
sealed class DpopVerdict {
    /** [jkt] is the thumbprint of the proof's key, equal to the token's `cnf.jkt` by the time it is accepted. */
    data class Accepted(val jkt: String, val subject: String) : DpopVerdict()

    data class Refused(val reason: DpopRefusal) : DpopVerdict()
}

/**
 * A protected resource that verifies DPoP the way RFC 9449 section 7 asks of one, so that what
 * the SDK sends is judged by a party that holds nothing but the provider's public keys:
 *
 * - the access token: an RS256 JWT signed by a key of the provider's JWKS, issued by the
 *   issuer the SDK was configured with (the proxy's), not expired, and carrying `cnf.jkt`;
 * - the scheme is `DPoP`, never `Bearer` (a bound token under `Bearer` is refused), with exactly
 *   one `DPoP` header;
 * - the proof: `typ` `dpop+jwt`, `alg` `ES256`, a public EC P-256 `jwk` (no private member), a
 *   signature that verifies under that `jwk`, `htm` the request method, `htu` the request URL
 *   without query and fragment, `iat` within [window] seconds of now, a `jti` never seen
 *   before, `ath` the base64url SHA-256 of the access token, and the thumbprint of the `jwk`
 *   equal to the token's `cnf.jkt`;
 * - with [nonce] set, a proof that does not carry it is answered `401 use_dpop_nonce` with a
 *   `DPoP-Nonce` header (section 8), the `force-dpop-nonce` capability for a resource.
 *
 * Every request is recorded with its verdict ([attempts]); the test reads those, not the
 * response code alone. Independent of the SDK's own proof code on purpose: it shares no class
 * with `DpopProofFactory`, so a mistake there cannot be mirrored here.
 */
class DpopResourceServer(
    private val provider: Provider,
    private val proxy: ProviderProxy,
    /** Demands this nonce in every proof (RFC 9449 section 8); null demands none. */
    private val nonce: String? = null,
    /**
     * The nonce the 401 offers, [nonce] unless a test wants a server that offers one it will not
     * accept: the client that retries on every challenge would loop on it, and the test proves it
     * stops after one retry.
     */
    private val offered: String? = nonce,
    private val clock: () -> Long = System::currentTimeMillis,
    private val window: Long = 60,
) : Dispatcher() {

    class Attempt(val request: RecordedRequest, val verdict: DpopVerdict)

    private val server = MockWebServer()
    private val http = OkHttpClient()
    private val seenJti = ConcurrentHashMap.newKeySet<String>()
    val attempts = CopyOnWriteArrayList<Attempt>()

    val origin: String get() = server.url("/").toString().trimEnd('/')

    fun start() {
        server.dispatcher = this
        server.start()
    }

    fun stop() = server.close()

    fun url(path: String): String = origin + path

    /** The verdicts for [path], in the order the requests arrived. */
    fun verdicts(path: String): List<DpopVerdict> = attempts.filter { it.request.url.encodedPath == path }.map { it.verdict }

    override fun dispatch(request: RecordedRequest): MockResponse {
        val verdict = verify(request)
        attempts += Attempt(request, verdict)
        return when (verdict) {
            is DpopVerdict.Accepted -> MockResponse.Builder().code(200).setHeader("Content-Type", "application/json")
                .body("""{"sub":"${verdict.subject}","jkt":"${verdict.jkt}"}""").build()
            is DpopVerdict.Refused -> when (verdict.reason) {
                DpopRefusal.NonceRequired -> MockResponse.Builder().code(401)
                    .setHeader("WWW-Authenticate", "DPoP error=\"use_dpop_nonce\", algs=\"ES256\"")
                    .setHeader("DPoP-Nonce", checkNotNull(offered)).build()
                DpopRefusal.NoAuthorization, DpopRefusal.WrongScheme, DpopRefusal.NoProof, DpopRefusal.MultipleProofs ->
                    MockResponse.Builder().code(401).setHeader("WWW-Authenticate", "DPoP algs=\"ES256\"").build()
                DpopRefusal.TokenMalformed, DpopRefusal.TokenSignature, DpopRefusal.TokenIssuer, DpopRefusal.TokenExpired, DpopRefusal.TokenNotBound ->
                    MockResponse.Builder().code(401).setHeader("WWW-Authenticate", "DPoP error=\"invalid_token\", algs=\"ES256\"").build()
                else -> MockResponse.Builder().code(401).setHeader("WWW-Authenticate", "DPoP error=\"invalid_dpop_proof\", algs=\"ES256\"").build()
            }
        }
    }

    private fun refuse(reason: DpopRefusal) = DpopVerdict.Refused(reason)

    private fun verify(request: RecordedRequest): DpopVerdict {
        val authorization = request.headers["Authorization"] ?: return refuse(DpopRefusal.NoAuthorization)
        val scheme = authorization.substringBefore(' ')
        val tokenValue = authorization.substringAfter(' ', "")

        // The token first, whatever the scheme: a refusal for the scheme is only a statement about
        // binding when the token really is a bound one.
        val token = parts(tokenValue) ?: return refuse(DpopRefusal.TokenMalformed)
        val tokenHeader = decode(token[0]) ?: return refuse(DpopRefusal.TokenMalformed)
        val claims = decode(token[1]) ?: return refuse(DpopRefusal.TokenMalformed)
        if (tokenHeader["alg"]?.jsonPrimitive?.content != "RS256") return refuse(DpopRefusal.TokenSignature)
        val key = jwks[tokenHeader["kid"]?.jsonPrimitive?.content] ?: return refuse(DpopRefusal.TokenSignature)
        val signed = Signature.getInstance("SHA256withRSA").run {
            initVerify(key)
            update("${token[0]}.${token[1]}".toByteArray(Charsets.US_ASCII))
            runCatching { verify(Base64.getUrlDecoder().decode(token[2])) }.getOrDefault(false)
        }
        if (!signed) return refuse(DpopRefusal.TokenSignature)
        if (claims["iss"]?.jsonPrimitive?.content != proxy.issuer) return refuse(DpopRefusal.TokenIssuer)
        if ((claims["exp"]?.jsonPrimitive?.content?.toLongOrNull() ?: 0) * 1000 <= clock()) return refuse(DpopRefusal.TokenExpired)
        val boundTo = claims["cnf"]?.jsonObject?.get("jkt")?.jsonPrimitive?.content ?: return refuse(DpopRefusal.TokenNotBound)

        if (scheme != "DPoP") return refuse(DpopRefusal.WrongScheme)
        val proofs = request.headers.values("DPoP")
        if (proofs.isEmpty()) return refuse(DpopRefusal.NoProof)
        if (proofs.size > 1) return refuse(DpopRefusal.MultipleProofs)

        val proof = parts(proofs.single()) ?: return refuse(DpopRefusal.ProofMalformed)
        val header = decode(proof[0]) ?: return refuse(DpopRefusal.ProofMalformed)
        val body = decode(proof[1]) ?: return refuse(DpopRefusal.ProofMalformed)
        if (header["typ"]?.jsonPrimitive?.content != "dpop+jwt") return refuse(DpopRefusal.ProofType)
        if (header["alg"]?.jsonPrimitive?.content != "ES256") return refuse(DpopRefusal.ProofAlgorithm)
        val jwk = header["jwk"]?.jsonObject ?: return refuse(DpopRefusal.ProofKey)
        // A private member in a proof's jwk is a key leak, and a proof that carries one is refused.
        if (jwk["kty"]?.jsonPrimitive?.content != "EC" || jwk["crv"]?.jsonPrimitive?.content != "P-256" || jwk.containsKey("d")) {
            return refuse(DpopRefusal.ProofKey)
        }
        val publicKey = ecPublicKey(jwk) ?: return refuse(DpopRefusal.ProofKey)
        val signatureValid = Signature.getInstance("SHA256withECDSA").run {
            initVerify(publicKey)
            update("${proof[0]}.${proof[1]}".toByteArray(Charsets.US_ASCII))
            runCatching { verify(joseToDer(Base64.getUrlDecoder().decode(proof[2]))) }.getOrDefault(false)
        }
        if (!signatureValid) return refuse(DpopRefusal.ProofSignature)

        if (body["htm"]?.jsonPrimitive?.content != request.method) return refuse(DpopRefusal.Method)
        // The target URI as this server saw it, minus query and fragment (RFC 9449 section 4.2).
        val target = request.url.newBuilder().query(null).fragment(null).build().toString()
        if (body["htu"]?.jsonPrimitive?.content != target) return refuse(DpopRefusal.Url)
        val issuedAt = body["iat"]?.jsonPrimitive?.content?.toLongOrNull() ?: return refuse(DpopRefusal.IssuedAt)
        if (kotlin.math.abs(clock() / 1000 - issuedAt) > window) return refuse(DpopRefusal.IssuedAt)
        if (body["ath"]?.jsonPrimitive?.content != sha256Url(tokenValue)) return refuse(DpopRefusal.AccessTokenHash)
        if (thumbprint(jwk) != boundTo) return refuse(DpopRefusal.KeyMismatch)
        val jti = body["jti"]?.jsonPrimitive?.content?.takeIf { it.isNotEmpty() } ?: return refuse(DpopRefusal.ProofMalformed)
        if (!seenJti.add(jti)) return refuse(DpopRefusal.ReplayedJti)
        if (nonce != null && body["nonce"]?.jsonPrimitive?.content != nonce) return refuse(DpopRefusal.NonceRequired)

        return DpopVerdict.Accepted(boundTo, claims["sub"]?.jsonPrimitive?.content.orEmpty())
    }

    /** The provider's signing keys by `kid`, read once from its advertised `jwks_uri`. */
    private val jwks: Map<String?, java.security.PublicKey> by lazy {
        val discovery = http.newCall(Request.Builder().url(provider.issuer + "/.well-known/openid-configuration").build()).execute().text()
        val uri = Json.parseToJsonElement(discovery).jsonObject["jwks_uri"]!!.jsonPrimitive.content
        val keys = Json.parseToJsonElement(http.newCall(Request.Builder().url(uri).build()).execute().text()).jsonObject["keys"]!!.jsonArray
        keys.map { it.jsonObject }.filter { it["kty"]?.jsonPrimitive?.content == "RSA" && it["use"]?.jsonPrimitive?.content != "enc" }.associate {
            fun int(name: String) = BigInteger(1, Base64.getUrlDecoder().decode(it[name]!!.jsonPrimitive.content))
            it["kid"]?.jsonPrimitive?.content to KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(int("n"), int("e")))
        }
    }


    /**
     * What the binding is for: the access token [token], once stolen, is useless without the key.
     * Each case changes exactly one thing from a request this server accepts (the control), so the
     * refusal is that check's and nothing else's; the verdict's reason, not only the 401, is
     * asserted. [sdkKey] is the SDK's own key as the harness reached it, so a case that changes one
     * claim of the SDK's proof is that claim's check and not a forger's mistake. Shared by the native
     * driver and the Flutter bridge's: both hold a token and the key, and neither needs the SDK to
     * make the request.
     */
    fun assertStolenTokenIsRefused(token: String, sdkKey: KeyPair) {
        val attacker = DpopResourceServer.newKeyPair()
        val http = OkHttpClient()
        val url = url("/api")

        fun send(path: String = "/api", method: String = "GET", authorization: String? = "DPoP $token", vararg proofs: String): DpopVerdict {
            val request = Request.Builder().url(url(path)).method(method, if (method == "GET") null else ByteArray(0).toRequestBody()).apply {
                authorization?.let { header("Authorization", it) }
                proofs.forEach { addHeader("DPoP", it) }
            }.build()
            val before = attempts.size
            http.newCall(request).execute().use { response ->
                assertEquals(1, attempts.size - before)
                val verdict = attempts.last().verdict
                assertEquals(verdict.toString(), verdict is DpopVerdict.Accepted, response.code == 200)
                if (verdict is DpopVerdict.Refused) assertEquals(401, response.code)
                return verdict
            }
        }

        fun assertRefused(label: String, reason: DpopRefusal, verdict: DpopVerdict) = assertEquals(label, DpopVerdict.Refused(reason), verdict)

        // The control: the SDK's own key, every claim right. Accepted, so what follows is not the forger's fault.
        assertTrue("control", send(proofs = arrayOf(DpopResourceServer.forgeProof(sdkKey, "GET", url, token))) is DpopVerdict.Accepted)

        assertRefused(
            "the SDK's jwk in the header, a signature by another key", DpopRefusal.ProofSignature,
            send(proofs = arrayOf(DpopResourceServer.forgeProof(sdkKey, "GET", url, token, signer = attacker))),
        )
        assertRefused("the token alone, no proof", DpopRefusal.NoProof, send())
        assertRefused("the token as a Bearer, no proof", DpopRefusal.WrongScheme, send(authorization = "Bearer $token"))
        assertRefused(
            "the token as a Bearer, with a valid proof", DpopRefusal.WrongScheme,
            send(authorization = "Bearer $token", proofs = arrayOf(DpopResourceServer.forgeProof(sdkKey, "GET", url, token))),
        )
        assertRefused(
            "a proof from another key (every claim right, ath included)", DpopRefusal.KeyMismatch,
            send(proofs = arrayOf(DpopResourceServer.forgeProof(attacker, "GET", url, token))),
        )
        assertRefused(
            "the SDK's key, but ath of another token", DpopRefusal.AccessTokenHash,
            send(proofs = arrayOf(DpopResourceServer.forgeProof(sdkKey, "GET", url, token, ath = DpopResourceServer.sha256Url("another-token")))),
        )
        assertRefused(
            "the SDK's key, but no ath", DpopRefusal.AccessTokenHash,
            send(proofs = arrayOf(DpopResourceServer.forgeProof(sdkKey, "GET", url, token, ath = null))),
        )
        assertRefused(
            "the SDK's key, but a proof for another URL", DpopRefusal.Url,
            send(proofs = arrayOf(DpopResourceServer.forgeProof(sdkKey, "GET", url("/api/other"), token))),
        )
        assertRefused(
            "the SDK's key, but a proof for another method", DpopRefusal.Method,
            send(proofs = arrayOf(DpopResourceServer.forgeProof(sdkKey, "POST", url, token))),
        )
        assertRefused(
            "the SDK's key, but a proof ten minutes old", DpopRefusal.IssuedAt,
            send(proofs = arrayOf(DpopResourceServer.forgeProof(sdkKey, "GET", url, token, issuedAt = System.currentTimeMillis() / 1000 - 600))),
        )
        assertRefused(
            "two proofs", DpopRefusal.MultipleProofs,
            send(proofs = arrayOf(DpopResourceServer.forgeProof(sdkKey, "GET", url, token), DpopResourceServer.forgeProof(sdkKey, "GET", url, token))),
        )

        // Re-binding the stolen token to the thief's key: change cnf.jkt, keep the provider's signature.
        val parts = token.split('.')
        val payload = Transcript.decodeJwtPart(token, 1)!!
        val rebound = payload.toString().replace(
            payload["cnf"]!!.jsonObject["jkt"]!!.jsonPrimitive.content,
            DpopResourceServer.thumbprint(attacker.public as ECPublicKey),
        )
        val tampered = "${parts[0]}.${java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(rebound.toByteArray())}.${parts[2]}"
        assertRefused(
            "the token re-bound to the thief's key", DpopRefusal.TokenSignature,
            send(authorization = "DPoP $tampered", proofs = arrayOf(DpopResourceServer.forgeProof(attacker, "GET", url, tampered))),
        )
    }

    companion object {
        private val b64 = Base64.getUrlEncoder().withoutPadding()

        private fun parts(jwt: String): List<String>? = jwt.split('.').takeIf { it.size == 3 }

        private fun decode(segment: String): JsonObject? =
            runCatching { Json.parseToJsonElement(String(Base64.getUrlDecoder().decode(segment), Charsets.UTF_8)).jsonObject }.getOrNull()

        /** A fresh P-256 pair from a provider other than the Keystore stand-in, which is first in line for "EC". */
        fun newKeyPair(): KeyPair {
            val other = java.security.Security.getProviders().first { it !is SoftwareAndroidKeyStore && it.getService("KeyPairGenerator", "EC") != null }
            return java.security.KeyPairGenerator.getInstance("EC", other).apply { initialize(java.security.spec.ECGenParameterSpec("secp256r1")) }.generateKeyPair()
        }

        fun sha256Url(value: String): String = b64.encodeToString(MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.US_ASCII)))

        /** RFC 7638: SHA-256 over the required members in lexicographic order, no whitespace. */
        fun thumbprint(jwk: JsonObject): String {
            val canonical = """{"crv":"${jwk["crv"]!!.jsonPrimitive.content}","kty":"${jwk["kty"]!!.jsonPrimitive.content}","x":"${jwk["x"]!!.jsonPrimitive.content}","y":"${jwk["y"]!!.jsonPrimitive.content}"}"""
            return b64.encodeToString(MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(Charsets.UTF_8)))
        }

        fun thumbprint(key: ECPublicKey): String = thumbprint(jwk(key))

        fun jwk(key: ECPublicKey): JsonObject = buildJsonObject {
            put("kty", "EC")
            put("crv", "P-256")
            put("x", b64.encodeToString(unsigned(key.w.affineX)))
            put("y", b64.encodeToString(unsigned(key.w.affineY)))
        }

        private fun unsigned(value: BigInteger): ByteArray {
            val bytes = value.toByteArray().dropWhile { it == 0.toByte() }.toByteArray()
            return ByteArray(32 - bytes.size) + bytes
        }

        private val curve: ECParameterSpec by lazy { (newKeyPair().public as ECPublicKey).params }

        private fun ecPublicKey(jwk: JsonObject): ECPublicKey? = runCatching {
            val x = BigInteger(1, Base64.getUrlDecoder().decode(jwk["x"]!!.jsonPrimitive.content))
            val y = BigInteger(1, Base64.getUrlDecoder().decode(jwk["y"]!!.jsonPrimitive.content))
            KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), curve)) as ECPublicKey
        }.getOrNull()

        /** JWS `R || S` back to the DER the JCA verifies. */
        private fun joseToDer(raw: ByteArray): ByteArray {
            require(raw.size == 64)
            fun integer(bytes: ByteArray): ByteArray {
                val trimmed = bytes.dropWhile { it == 0.toByte() }.toByteArray().let { if (it.isEmpty()) byteArrayOf(0) else it }
                val body = if (trimmed[0] < 0) byteArrayOf(0) + trimmed else trimmed
                return byteArrayOf(0x02, body.size.toByte()) + body
            }
            val r = integer(raw.copyOfRange(0, 32))
            val s = integer(raw.copyOfRange(32, 64))
            val length = r.size + s.size
            return (if (length < 0x80) byteArrayOf(0x30, length.toByte()) else byteArrayOf(0x30, 0x81.toByte(), length.toByte())) + r + s
        }

        private fun derToJose(der: ByteArray): ByteArray {
            var index = 2 + if (der[1] < 0) 1 else 0
            fun integer(): ByteArray {
                check(der[index] == 0x02.toByte())
                val length = der[index + 1].toInt()
                val value = der.copyOfRange(index + 2, index + 2 + length).dropWhile { it == 0.toByte() }.toByteArray()
                index += 2 + length
                return ByteArray(32 - value.size) + value
            }
            return integer() + integer()
        }

        /**
         * A proof signed with [key], the way the SDK's own would be, with the claims the caller
         * chooses. This is the attacker's tool and the control group in one: a proof built here
         * with every claim right is accepted by [DpopResourceServer], so a refusal of one with a
         * single claim wrong is that claim's check and not the forger's.
         */
        fun forgeProof(
            key: KeyPair,
            method: String,
            url: String,
            accessToken: String?,
            issuedAt: Long = System.currentTimeMillis() / 1000,
            jti: String = java.util.UUID.randomUUID().toString(),
            nonce: String? = null,
            ath: String? = accessToken?.let(::sha256Url),
            /** Signs with this key instead of [key]'s while the header still carries [key]'s `jwk`: a proof whose signature is not its sender's. */
            signer: KeyPair = key,
        ): String {
            val header = buildJsonObject {
                put("typ", "dpop+jwt")
                put("alg", "ES256")
                put("jwk", jwk(key.public as ECPublicKey))
            }
            val claims = buildJsonObject {
                put("htm", method)
                put("htu", url.substringBefore('?').substringBefore('#'))
                put("iat", issuedAt)
                put("jti", jti)
                nonce?.let { put("nonce", it) }
                ath?.let { put("ath", it) }
            }
            val input = "${b64.encodeToString(header.toString().toByteArray())}.${b64.encodeToString(claims.toString().toByteArray())}"
            val signature = Signature.getInstance("SHA256withECDSA").run {
                initSign(signer.private as ECPrivateKey)
                update(input.toByteArray(Charsets.US_ASCII))
                sign()
            }
            return "$input.${b64.encodeToString(derToJose(signature))}"
        }
    }
}
