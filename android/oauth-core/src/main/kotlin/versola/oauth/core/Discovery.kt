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
 * Where a fetched document is kept between runs. Unencrypted and kept across logout, both
 * deliberately: metadata is not credential material, and a re-login should not need a round
 * trip to `/.well-known/openid-configuration` (`spec/state-machine.md`, persistence summary).
 */
public interface ProviderMetadataCache {
    public suspend fun load(): ProviderMetadata?
    public suspend fun save(metadata: ProviderMetadata)
    public suspend fun clear()

    /**
     * When the document [load] returns was fetched, in epoch milliseconds, or null when the cache
     * does not know. [DiscoveryService] expires a document 24 hours after it was fetched
     * (`spec/oauth-sdk-api.md` section 4); a cache that cannot say is read as fetched just now, so
     * it is bounded by that many hours from each load rather than never.
     */
    public suspend fun savedAtEpochMillis(): Long? = null
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
) : DiscoveryClient {

    override suspend fun fetch(issuer: String): ProviderMetadata {
        val url = wellKnownUrl(issuer)
        val body = retrying(originOf(url)) { withContext(Dispatchers.IO) {
            val request = Request.Builder().url(url).header("Accept", "application/json").build()
            try {
                httpClient.newCall(request).execute().use { response ->
                    val payload = response.body.string()
                    when {
                        response.isSuccessful -> payload
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

        val metadata = try {
            discoveryJson.decodeFromString(ProviderMetadata.serializer(), body)
        } catch (e: Exception) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.DiscoveryMalformed(e.message ?: e::class.java.simpleName),
                e,
            )
        }
        metadata.validate(issuer)
        return metadata
    }
}

/**
 * A plain JSON file. Not encrypted, by the same reasoning as [ProviderMetadataCache]. The time it
 * was fetched is the file's modification time, which the atomic write below sets to the moment of
 * the save.
 */
public class FileProviderMetadataCache(
    private val file: File,
) : ProviderMetadataCache {

    override suspend fun savedAtEpochMillis(): Long? = withContext(Dispatchers.IO) {
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
        withContext(Dispatchers.IO) {
            file.parentFile?.mkdirs()
            val temporary = File(file.parentFile, file.name + ".tmp")
            temporary.writeText(discoveryJson.encodeToString(ProviderMetadata.serializer(), metadata))
            if (!temporary.renameTo(file)) temporary.delete()
        }
    }

    override suspend fun clear() {
        withContext(Dispatchers.IO) { file.delete() }
    }
}

/**
 * Discovery with its cache in front. One fetch per process at most, unless the caller forces
 * a refresh or what is held is older than 24 hours (`spec/oauth-sdk-api.md` section 4): a
 * provider that moved its token endpoint, or withdrew a field, is picked up within a day without
 * the integrator shipping anything, and neither memory nor the disk copy outlives that.
 *
 * Past that age the document is fetched again; if that fetch cannot reach the provider the old
 * document is served once more rather than the failure. Unlike the key set (see [JwksClient]),
 * this document is not what anything is verified against: every endpoint in it is held to the
 * same checks again, and what it can do a stale copy of itself has already been trusted to do.
 * Refusing instead would make a phone that was offline for a day unable even to finish a
 * `logout()`, whose browser leg needs the document. Only an outage is forgiven: a document that
 * is served but wrong is still a `Configuration` failure.
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
    private var inMemoryFetchedAt = 0L

    public suspend fun metadata(forceRefresh: Boolean = false): ProviderMetadata = mutex.withLock {
        // What was held but has aged out: the fallback if the provider cannot be asked.
        var stale: ProviderMetadata? = null
        if (!forceRefresh) {
            inMemory?.let {
                if (isFresh(inMemoryFetchedAt)) return@withLock it
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
                    val fetchedAt = cache.savedAtEpochMillis() ?: clock()
                    if (isFresh(fetchedAt)) {
                        inMemory = cached
                        inMemoryFetchedAt = fetchedAt
                        return@withLock cached
                    }
                    stale = stale ?: cached
                }
            }
        }
        val fetched = try {
            client.fetch(issuer)
        } catch (e: VersolaError.Recoverable) {
            return@withLock stale ?: throw e
        }
        cache.save(fetched)
        inMemory = fetched
        inMemoryFetchedAt = clock()
        fetched
    }

    /** Within 24 hours, and not in the future: a device clock moved back is not a document from tomorrow. */
    private fun isFresh(fetchedAtEpochMillis: Long): Boolean {
        val age = clock() - fetchedAtEpochMillis
        return age in 0 until CacheLifetime.MAX_MILLIS
    }
}
