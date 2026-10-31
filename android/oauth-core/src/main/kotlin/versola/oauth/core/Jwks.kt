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
 *
 * What is kept expires ([CacheLifetime]): a provider withdraws a signing key by dropping it from
 * the set, and a copy that outlived that would keep verifying tokens signed with it.
 */
@VersolaInternalApi
public interface JwksCache {
    /**
     * The document, or null when none is kept or the one kept has expired by more than
     * [staleForMillis] (zero: not at all).
     */
    public suspend fun load(staleForMillis: Long = 0): String?

    /** Keeps [json] for [lifetimeMillis]. */
    public suspend fun save(json: String, lifetimeMillis: Long)
    public suspend fun clear()
}

/** What [FileJwksCache] writes: the document and the instant it stops being good, in one file. */
@kotlinx.serialization.Serializable
internal class ExpiringDocument(val expiresAt: Long, val document: String)

/**
 * A plain file, written through a temporary so a crash never leaves half a document.
 *
 * The expiry travels inside the file, beside the document, so one atomic write sets both and
 * nothing that merely touches the file (a backup tool, a `touch`, a restore) can move it. A file
 * written before expiry existed holds the bare document, which does not decode as this envelope and
 * so reads as a miss once and is replaced: the safe way to migrate it.
 */
@VersolaInternalApi
public class FileJwksCache(
    private val file: File,
    private val clock: () -> Long = System::currentTimeMillis,
) : JwksCache {

    override suspend fun load(staleForMillis: Long): String? = withContext(SdkDispatchers.blocking) {
        try {
            if (!file.exists()) return@withContext null
            val stored = discoveryJson.decodeFromString(ExpiringDocument.serializer(), file.readText())
            stored.document.takeIf { CacheLifetime.isUsable(stored.expiresAt, clock(), staleForMillis) }
        } catch (e: IOException) {
            // Unreadable is a miss, never a failure: the document is one request away.
            null
        } catch (e: kotlinx.serialization.SerializationException) {
            // Not this envelope: a bare document from before expiry existed, or damage. A miss.
            null
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    override suspend fun save(json: String, lifetimeMillis: Long) {
        withContext(SdkDispatchers.blocking) {
            file.parentFile?.mkdirs()
            val temporary = File(file.parentFile, file.name + ".tmp")
            temporary.writeText(
                discoveryJson.encodeToString(ExpiringDocument.serializer(), ExpiringDocument(clock() + lifetimeMillis, json)),
            )
            if (!temporary.renameTo(file)) temporary.delete()
        }
    }

    override suspend fun clear() {
        withContext(SdkDispatchers.blocking) { file.delete() }
    }
}

/** Process-local, for tests and for an integrator who wants nothing on disk. */
@VersolaInternalApi
public class MemoryJwksCache(
    private val clock: () -> Long = System::currentTimeMillis,
) : JwksCache {
    private var document: String? = null
    private var expiresAt = 0L

    override suspend fun load(staleForMillis: Long): String? =
        document?.takeIf { CacheLifetime.isUsable(expiresAt, clock(), staleForMillis) }

    override suspend fun save(json: String, lifetimeMillis: Long) {
        document = json
        expiresAt = clock() + lifetimeMillis
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
    /** Wall clock, because the disk copy's expiry has to mean the same thing in the next process. */
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private val httpClient: OkHttpClient = httpClient.newBuilder()
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    private val mutex = Mutex()
    private var inMemory: JsonWebKeySet? = null
    private var inMemoryExpiresAt = 0L

    /** After a failed fetch a reader that may use a stale set is not sent to the provider again before this. */
    private var retryNotBefore = 0L
    private var lastFailure: VersolaError.Recoverable? = null

    /**
     * A key set and whether this very call fetched it, which tells the caller a refetch would be a
     * repeat. [stale] marks a set past its lifetime served because the fetch failed, with that
     * failure as [cause]: it proves an outage and nothing else.
     */
    internal class Loaded(
        val keys: JsonWebKeySet,
        val fetched: Boolean,
        val stale: Boolean = false,
        val cause: VersolaError.Recoverable? = null,
    )

    /**
     * @param forceRefresh skip memory and the cache and fetch. Without it, the key set is
     *   memory, then cache, then the network, and memory and cache are skipped once what they
     *   hold has outlived its lifetime ([CacheLifetime]): an expired set is not served when the
     *   refetch fails, because a key the provider withdrew is exactly what it would still vouch for.
     * @param allowStale the one reader that may be served a set past its lifetime, up to a week, when
     *   the fetch fails as a [VersolaError.Recoverable]: the ID token of a refresh ([StaleKeysAllowed]).
     * @throws VersolaError.Recoverable(Network) when the provider cannot be reached.
     * @throws VersolaError.Configuration(DiscoveryMalformed) when the answer is not a JWK Set.
     */
    internal suspend fun keys(uri: String, forceRefresh: Boolean, allowStale: Boolean = false): Loaded = mutex.withLock {
        if (!forceRefresh) {
            inMemory?.takeIf { CacheLifetime.isFresh(inMemoryExpiresAt, clock()) }
                ?.let { return@withLock Loaded(it, fetched = false) }
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
                    // The disk copy's own remaining lifetime is not visible here, so memory trusts
                    // it for the shortest a copy can be good for; the cache decides at the next load.
                    inMemoryExpiresAt = clock() + CacheLifetime.MIN_MILLIS
                    return@withLock Loaded(parsed, fetched = false)
                }
            }
        }
        // A reader that may use a stale set is not made to wait out a fetch that failed a moment ago.
        if (allowStale && clock() < retryNotBefore) {
            staleSet()?.let { return@withLock Loaded(it, fetched = false, stale = true, cause = lastFailure) }
        }
        val fetched = try {
            fetch(uri)
        } catch (e: VersolaError.Recoverable) {
            // Only an outage is forgiven, and only to the reader that said it can be: anything that
            // is served but wrong (below, or a redirect) is a `Configuration` and never masked.
            retryNotBefore = clock() + STALE_RETRY_MILLIS
            lastFailure = e
            if (!allowStale) throw e
            val stale = staleSet() ?: throw e
            return@withLock Loaded(stale, fetched = false, stale = true, cause = e)
        }
        val parsed = try {
            JsonWebKeySet.parse(fetched.body)
        } catch (e: IllegalArgumentException) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.DiscoveryMalformed("jwks_uri did not serve a JWK Set: ${e.message}"),
                e,
            )
        }
        // Saved only once it parsed: a bad answer must not replace keys that worked.
        cache.save(fetched.body, fetched.lifetimeMillis)
        inMemory = parsed
        inMemoryExpiresAt = clock() + fetched.lifetimeMillis
        retryNotBefore = 0
        Loaded(parsed, fetched = true)
    }

    /** The key set held past its lifetime, by memory or disk, if it expired no more than a week ago. */
    private suspend fun staleSet(): JsonWebKeySet? {
        val now = clock()
        inMemory?.takeIf { CacheLifetime.isUsable(inMemoryExpiresAt, now, CacheLifetime.STALE_KEYS_MILLIS) }?.let { return it }
        val stored = cache.load(CacheLifetime.STALE_KEYS_MILLIS) ?: return null
        return try {
            JsonWebKeySet.parse(stored)
        } catch (e: IllegalArgumentException) {
            null
        }
    }

    private class Fetched(val body: String, val lifetimeMillis: Long)

    private suspend fun fetch(uri: String): Fetched = retrying(originOf(uri)) { withContext(SdkDispatchers.blocking) {
        val request = Request.Builder().url(uri).header("Accept", "application/json").build()
        try {
            httpClient.newCall(request).execute().use { response ->
                val payload = response.body.string()
                when {
                    response.isSuccessful -> Fetched(payload, CacheLifetime.of(response.headers, clock()))
                    // A redirect that was not followed is a deployment fault no retry fixes.
                    response.code in 300..399 -> throw VersolaError.Configuration(
                        VersolaError.Configuration.Detail.DiscoveryMalformed(
                            "jwks_uri answered HTTP ${response.code}; redirects are not followed",
                        ),
                    )
                    else -> throw ServerFault.failure(response.code, response.headers)
                }
            }
        } catch (e: IOException) {
            throw VersolaError.Recoverable(
                VersolaError.Recoverable.Cause.Network("jwks request failed: ${e.message}"),
                e,
            )
        }
    } }
}

/** A reader that may use a stale key set is not sent to the provider again for this long after a failed fetch. */
private const val STALE_RETRY_MILLIS = 60_000L
