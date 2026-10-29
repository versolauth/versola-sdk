package versola.oauth.core

import java.io.File
import java.io.IOException
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.RSAPublicKeySpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * One key of a JWK Set (RFC 7517), already turned into the JCA's [PublicKey]. Only what
 * selecting a verification key needs is kept: the type, the `kid`, the pinned `alg` and the
 * intended `use`.
 */
@VersolaInternalApi
public class JsonWebKey internal constructor(
    public val keyType: String,
    public val keyId: String?,
    public val algorithm: String?,
    public val use: String?,
    internal val publicKey: PublicKey,
) {
    override fun toString(): String = "JsonWebKey(kty=$keyType, kid=$keyId)"
}

/**
 * A parsed JWK Set. Parsing is strict about the document and forgiving about its members:
 * RFC 7517 5 says a key the application cannot use (an unknown `kty`, a curve it does not
 * support, a key that does not decode) is ignored rather than failing the set, because a
 * provider rotating in an algorithm this SDK lacks must not break verification with the keys
 * it does have. A document that is not JSON or has no `keys` array is not a JWK Set at all.
 */
@VersolaInternalApi
public class JsonWebKeySet internal constructor(public val keys: List<JsonWebKey>) {

    internal companion object {
        private val json = Json

        /** @throws IllegalArgumentException when [document] is not a JWK Set. */
        fun parse(document: String): JsonWebKeySet {
            val root = try {
                json.parseToJsonElement(document)
            } catch (e: Exception) {
                throw IllegalArgumentException("not JSON", e)
            }
            val array = (root as? JsonObject)?.get("keys") as? JsonArray
                ?: throw IllegalArgumentException("no keys array")
            return JsonWebKeySet(array.mapNotNull { (it as? JsonObject)?.let(::parseKey) })
        }

        private fun parseKey(jwk: JsonObject): JsonWebKey? {
            val kty = jwk.string("kty") ?: return null
            val publicKey = try {
                when (kty) {
                    "RSA" -> rsa(jwk)
                    "EC" -> ec(jwk)
                    else -> null
                }
            } catch (e: Exception) {
                // Bad base64url, a point not on the curve, an unusable exponent: unusable key.
                null
            } ?: return null
            return JsonWebKey(kty, jwk.string("kid"), jwk.string("alg"), jwk.string("use"), publicKey)
        }

        private fun rsa(jwk: JsonObject): PublicKey? {
            val n = jwk.integer("n") ?: return null
            val e = jwk.integer("e") ?: return null
            return KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(n, e))
        }

        private fun ec(jwk: JsonObject): PublicKey? {
            val (curveName, width) = when (jwk.string("crv")) {
                "P-256" -> "secp256r1" to 32
                "P-384" -> "secp384r1" to 48
                "P-521" -> "secp521r1" to 66
                else -> return null
            }
            // RFC 7518 6.2.1.2: x and y are the full coordinate size, leading zeros included.
            val x = jwk.fixedWidth("x", width) ?: return null
            val y = jwk.fixedWidth("y", width) ?: return null
            val parameters = AlgorithmParameters.getInstance("EC").run {
                init(ECGenParameterSpec(curveName))
                getParameterSpec(ECParameterSpec::class.java)
            }
            // The JCA does not always check the point against the curve when building a key
            // from a spec, and a coordinate pair that is not on it is not a public key.
            val field = (parameters.curve.field as? ECFieldFp)?.p ?: return null
            val onCurve = y.pow(2).mod(field) ==
                (x.pow(3) + parameters.curve.a * x + parameters.curve.b).mod(field)
            if (!onCurve) return null
            return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), parameters))
        }

        private fun JsonObject.string(name: String): String? =
            (this[name] as? JsonPrimitive)?.takeIf { it.isString }?.content

        private fun JsonObject.integer(name: String): BigInteger? =
            string(name)?.let { BigInteger(1, Base64Url.decode(it)) }

        private fun JsonObject.fixedWidth(name: String, width: Int): BigInteger? =
            string(name)?.let(Base64Url::decode)?.takeIf { it.size == width }?.let { BigInteger(1, it) }
    }
}

/**
 * Where the JWK Set document is kept between runs. Unencrypted and kept across logout, by the
 * same reasoning as [ProviderMetadataCache]: public keys are not credential material, and a
 * cold start should verify its first ID token without a round trip.
 *
 * The raw document is stored rather than parsed keys so a cache written by one SDK version is
 * still readable by the next, and so a document that no longer parses is dropped like any
 * corrupt cache.
 */
public interface JwksCache {
    public suspend fun load(): String?
    public suspend fun save(json: String)
    public suspend fun clear()
}

/** A plain file, written through a temporary so a crash never leaves half a document. */
public class FileJwksCache(
    private val file: File,
) : JwksCache {

    override suspend fun load(): String? = withContext(Dispatchers.IO) {
        try {
            if (file.exists()) file.readText() else null
        } catch (e: IOException) {
            // Unreadable is a miss, never a failure: the document is one request away.
            null
        }
    }

    override suspend fun save(json: String) {
        withContext(Dispatchers.IO) {
            file.parentFile?.mkdirs()
            val temporary = File(file.parentFile, file.name + ".tmp")
            temporary.writeText(json)
            if (!temporary.renameTo(file)) temporary.delete()
        }
    }

    override suspend fun clear() {
        withContext(Dispatchers.IO) { file.delete() }
    }
}

/** Process-local, for tests and for an integrator who wants nothing on disk. */
public class MemoryJwksCache : JwksCache {
    private var document: String? = null

    override suspend fun load(): String? = document
    override suspend fun save(json: String) {
        document = json
    }

    override suspend fun clear() {
        document = null
    }
}

/**
 * Fetches and caches the provider's JWK Set (`jwks_uri`).
 *
 * The injected client is used as given for timeouts and TLS, with redirects switched off for
 * the reason [TokenRequestExecutor] and `HttpTokenClient` give: the URL came from discovery
 * and is the only place keys may be read from. A key set fetched from wherever a `Location`
 * header pointed would let anything able to answer there choose which keys verify.
 *
 * What it does not do is decide when a refetch is warranted. That is the verifier's call, one
 * per validation, so that a flood of tokens naming unknown `kid`s costs the provider at most
 * one request each and never a loop.
 */
@VersolaInternalApi
public class JwksClient(
    httpClient: OkHttpClient,
    private val cache: JwksCache = MemoryJwksCache(),
) {
    private val httpClient: OkHttpClient = httpClient.newBuilder()
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    private val mutex = Mutex()
    private var inMemory: JsonWebKeySet? = null

    /** A key set and whether this very call fetched it, which tells the caller a refetch would be a repeat. */
    internal class Loaded(val keys: JsonWebKeySet, val fetched: Boolean)

    /**
     * @param forceRefresh skip memory and the cache and fetch. Without it, the key set is
     *   memory, then cache, then the network.
     * @throws VersolaError.Recoverable(Network) when the provider cannot be reached.
     * @throws VersolaError.Configuration(DiscoveryMalformed) when the answer is not a JWK Set.
     */
    internal suspend fun keys(uri: String, forceRefresh: Boolean): Loaded = mutex.withLock {
        if (!forceRefresh) {
            inMemory?.let { return@withLock Loaded(it, fetched = false) }
            cache.load()?.let { stored ->
                val parsed = try {
                    JsonWebKeySet.parse(stored)
                } catch (e: IllegalArgumentException) {
                    // A cache that does not parse is a miss, and is dropped so it is not read again.
                    cache.clear()
                    null
                }
                if (parsed != null) {
                    inMemory = parsed
                    return@withLock Loaded(parsed, fetched = false)
                }
            }
        }
        val body = fetch(uri)
        val parsed = try {
            JsonWebKeySet.parse(body)
        } catch (e: IllegalArgumentException) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.DiscoveryMalformed("jwks_uri did not serve a JWK Set: ${e.message}"),
                e,
            )
        }
        // Saved only once it parsed: a bad answer must not replace keys that worked.
        cache.save(body)
        inMemory = parsed
        Loaded(parsed, fetched = true)
    }

    private suspend fun fetch(uri: String): String = withContext(Dispatchers.IO) {
        val request = Request.Builder().url(uri).header("Accept", "application/json").build()
        try {
            httpClient.newCall(request).execute().use { response ->
                val payload = response.body.string()
                when {
                    response.isSuccessful -> payload
                    // A redirect that was not followed is a deployment fault no retry fixes.
                    response.code in 300..399 -> throw VersolaError.Configuration(
                        VersolaError.Configuration.Detail.DiscoveryMalformed(
                            "jwks_uri answered HTTP ${response.code}; redirects are not followed",
                        ),
                    )
                    else -> throw VersolaError.Recoverable(
                        VersolaError.Recoverable.Cause.Network("jwks_uri returned HTTP ${response.code}"),
                    )
                }
            }
        } catch (e: IOException) {
            throw VersolaError.Recoverable(
                VersolaError.Recoverable.Cause.Network("jwks request failed: ${e.message}"),
                e,
            )
        }
    }
}
