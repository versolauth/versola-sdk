package versola.oauth.core

import java.io.File
import java.io.IOException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient
import okhttp3.Request

/** Fetches the provider's metadata document. */
public interface DiscoveryClient {
    public suspend fun fetch(issuer: String): ProviderMetadata
}

/**
 * A [DiscoveryClient] that also says how long the answer it fetched may be trusted
 * ([CacheLifetime]: the provider's `Cache-Control` or `Expires`, bounded). The wiring seam of
 * [DiscoveryService]; a client that is not one is cached for the longest lifetime there is.
 */
@VersolaInternalApi
public interface LifetimeAwareDiscoveryClient : DiscoveryClient {
    /** The document and its lifetime in milliseconds. */
    public suspend fun fetchWithLifetime(issuer: String): Pair<ProviderMetadata, Long>
}

/** [LifetimeAwareDiscoveryClient.fetchWithLifetime] where the client is one, the longest lifetime otherwise. */
@VersolaInternalApi
public suspend fun DiscoveryClient.fetchWithLifetime(issuer: String): Pair<ProviderMetadata, Long> =
    (this as? LifetimeAwareDiscoveryClient)?.fetchWithLifetime(issuer)
        ?: (fetch(issuer) to CacheLifetime.MAX_MILLIS)

/**
 * Where a fetched document is kept between runs. Unencrypted and kept across logout, both
 * deliberately: metadata is not credential material, and a re-login should not need a round
 * trip to `/.well-known/openid-configuration` (`spec/state-machine.md`, persistence summary).
 */
public interface ProviderMetadataCache {
    public suspend fun load(): ProviderMetadata?
    public suspend fun save(metadata: ProviderMetadata)
    public suspend fun clear()

    /**
     * [save], remembering that the document is good for [lifetimeMillis] and no longer
     * ([expiresAtEpochMillis]). The default forgets it, for a cache that cannot keep one.
     */
    public suspend fun save(metadata: ProviderMetadata, lifetimeMillis: Long) {
        save(metadata)
    }

    /**
     * When the document [load] returns stops being good, in epoch milliseconds, or null when the
     * cache does not know (a document saved without a lifetime, or by a cache that keeps none).
     * [DiscoveryService] then reads it as good for the longest lifetime from now, so such a cache
     * is bounded by that many hours from each load rather than never.
     */
    public suspend fun expiresAtEpochMillis(): Long? = null
}

@VersolaInternalApi
public val discoveryJson: Json = Json {
    ignoreUnknownKeys = true
    encodeDefaults = true
}

/**
 * OpenID Connect Discovery §4.1: the well-known path is appended to the issuer, retaining any
 * path component the issuer already has.
 */
internal fun wellKnownUrl(issuer: String): String =
    issuer.trimEnd('/') + "/.well-known/openid-configuration"

public class HttpDiscoveryClient(
    private val httpClient: OkHttpClient,
) : LifetimeAwareDiscoveryClient {

    override suspend fun fetch(issuer: String): ProviderMetadata = fetchWithLifetime(issuer).first

    override suspend fun fetchWithLifetime(issuer: String): Pair<ProviderMetadata, Long> {
        val url = wellKnownUrl(issuer)
        val fetched = retrying(originOf(url)) { withContext(Dispatchers.IO) {
            val request = Request.Builder().url(url).header("Accept", "application/json").build()
            try {
                httpClient.newCall(request).execute().use { response ->
                    val payload = response.body.string()
                    when {
                        response.isSuccessful -> payload to CacheLifetime.of(response.headers, System.currentTimeMillis())
                        // 408, 429 and 5xx are the provider having a bad moment: transport-shaped,
                        // repeated under the operation's budget (`spec/retry-policy.md`).
                        ServerFault.isServerFault(response.code) -> throw ServerFault.failure(response.code, response.headers)
                        // A 4xx means this issuer does not serve a discovery document at all,
                        // which no retry fixes — an integrator typo or the wrong environment.
                        response.code in 400..499 -> throw VersolaError.Configuration(
                            VersolaError.Configuration.Detail.InvalidConfiguration(
                                "no discovery document at $url (HTTP ${response.code})",
                            ),
                        )
                        // A redirect that was not followed is a deployment fault no retry fixes
                        // (`spec/errors.md`), as it is at the key set and the token endpoint.
                        response.code in 300..399 -> throw VersolaError.Configuration(
                            VersolaError.Configuration.Detail.InvalidConfiguration(
                                "discovery answered HTTP ${response.code} at $url; redirects are not followed",
                            ),
                        )
                        // Anything else (a 1xx) is an answer this client cannot use and a repeat
                        // cannot change.
                        else -> throw ServerFault.failure(response.code, response.headers)
                    }
                }
            } catch (e: IOException) {
                throw VersolaError.Recoverable(
                    VersolaError.Recoverable.Cause.Network("discovery request failed: ${e.message}"),
                    e,
                )
            }
        } }

        val (body, lifetime) = fetched
        val metadata = try {
            discoveryJson.decodeFromString(ProviderMetadata.serializer(), body)
        } catch (e: Exception) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.DiscoveryMalformed(e.message ?: e::class.java.simpleName),
                e,
            )
        }
        metadata.validate(issuer)
        return metadata to lifetime
    }
}

/**
 * A plain JSON file. Not encrypted, by the same reasoning as [ProviderMetadataCache].
 *
 * Its expiry is the file's modification time, set at save to the instant the document stops being
 * good (the same device as [FileJwksCache], for the same reasons): nothing second to keep in step,
 * and a copy written before expiry existed has a modification time in the past and so reads as
 * expired once, which is the safe way to migrate it.
 */
public class FileProviderMetadataCache(
    private val file: File,
    private val clock: () -> Long = System::currentTimeMillis,
) : ProviderMetadataCache {

    override suspend fun expiresAtEpochMillis(): Long? = withContext(Dispatchers.IO) {
        file.lastModified().takeIf { it > 0 }
    }

    override suspend fun load(): ProviderMetadata? = withContext(Dispatchers.IO) {
        if (!file.exists()) return@withContext null
        try {
            discoveryJson.decodeFromString(ProviderMetadata.serializer(), file.readText())
        } catch (e: Exception) {
            // A cache that cannot be read is a cache miss, never a failure: the document is
            // one round trip away and the alternative is bricking login on a corrupt file.
            file.delete()
            null
        }
    }

    override suspend fun save(metadata: ProviderMetadata) {
        save(metadata, CacheLifetime.MAX_MILLIS)
    }

    override suspend fun save(metadata: ProviderMetadata, lifetimeMillis: Long) {
        withContext(Dispatchers.IO) {
            file.parentFile?.mkdirs()
            val temporary = File(file.parentFile, file.name + ".tmp")
            temporary.writeText(discoveryJson.encodeToString(ProviderMetadata.serializer(), metadata))
            // A failure to stamp leaves the write time, already in the past: the copy then reads
            // as expired and the next call fetches. Safe, and not worth failing for.
            temporary.setLastModified(clock() + lifetimeMillis)
            if (!temporary.renameTo(file)) temporary.delete()
        }
    }

    override suspend fun clear() {
        withContext(Dispatchers.IO) { file.delete() }
    }
}

/**
 * Discovery with its cache in front. One fetch per process at most, unless the caller forces a
 * refresh or what is held has outlived its lifetime ([CacheLifetime]: the provider's
 * `Cache-Control` or `Expires`, held between five minutes and 24 hours, 24 hours when it says
 * nothing; `spec/oauth-sdk-api.md` section 4): a provider that moved its token endpoint, or
 * withdrew a field, is picked up within a day without the integrator shipping anything, and
 * neither memory nor the disk copy outlives that.
 *
 * Past its lifetime the document is fetched again; if that fetch cannot reach the provider the old
 * document is served once more, and the next attempt waits a minute, rather than the failure.
 * Unlike the key set (see [JwksClient]), this document is not what anything is verified against:
 * every endpoint in it is held to the same checks again, and what it can do a stale copy of itself
 * has already been trusted to do. Refusing instead would make a phone that was offline for a day
 * unable even to finish a `logout()`, whose browser leg needs the document. Only an outage is
 * forgiven: a document that is served but wrong is still a `Configuration` failure.
 */
public class DiscoveryService internal constructor(
    private val issuer: String,
    private val client: DiscoveryClient,
    private val cache: ProviderMetadataCache,
    private val clock: () -> Long,
) {
    public constructor(
        issuer: String,
        client: DiscoveryClient,
        cache: ProviderMetadataCache,
    ) : this(issuer, client, cache, System::currentTimeMillis)

    private val mutex = Mutex()
    private var inMemory: ProviderMetadata? = null
    private var inMemoryExpiresAt = 0L

    public suspend fun metadata(forceRefresh: Boolean = false): ProviderMetadata = mutex.withLock {
        // What was held but has aged out: the fallback if the provider cannot be asked.
        var stale: ProviderMetadata? = null
        if (!forceRefresh) {
            inMemory?.let {
                if (CacheLifetime.isFresh(inMemoryExpiresAt, clock())) return@withLock it
                stale = it
            }
            cache.load()?.let { cached ->
                // A cached document from a different issuer belongs to a previous
                // configuration of this app, and one that no longer passes the checks a fetched
                // one must (an endpoint that is not https) was written by an earlier SDK or by
                // something else: either is treated as absent rather than trusted. The same
                // `validate` as on fetch, so the issuer comparison stays trailing-slash-
                // insensitive — otherwise metadata saved as "<issuer>/" would pass validation on
                // first fetch but never be recognised as a cache hit again, silently defeating
                // the disk cache.
                val usable = try {
                    cached.validate(issuer)
                    true
                } catch (e: VersolaError.Configuration) {
                    false
                }
                if (usable) {
                    val expiresAt = cache.expiresAtEpochMillis() ?: (clock() + CacheLifetime.MAX_MILLIS)
                    if (CacheLifetime.isFresh(expiresAt, clock())) {
                        inMemory = cached
                        inMemoryExpiresAt = expiresAt
                        return@withLock cached
                    }
                    stale = stale ?: cached
                }
            }
        }
        val (fetched, lifetime) = try {
            client.fetchWithLifetime(issuer)
        } catch (e: VersolaError.Recoverable) {
            val fallback = stale ?: throw e
            inMemory = fallback
            inMemoryExpiresAt = clock() + RETRY_AFTER_OUTAGE_MILLIS
            return@withLock fallback
        }
        cache.save(fetched, lifetime)
        inMemory = fetched
        inMemoryExpiresAt = clock() + lifetime
        fetched
    }
}

/** How long a document served stale because the provider was unreachable is trusted before the next try. */
private const val RETRY_AFTER_OUTAGE_MILLIS = 60_000L
