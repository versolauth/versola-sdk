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

/** A plain JSON file. Not encrypted, by the same reasoning as [ProviderMetadataCache]. */
public class FileProviderMetadataCache(
    private val file: File,
) : ProviderMetadataCache {

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
 * a refresh.
 */
public class DiscoveryService(
    private val issuer: String,
    private val client: DiscoveryClient,
    private val cache: ProviderMetadataCache,
) {
    private val mutex = Mutex()
    private var inMemory: ProviderMetadata? = null

    public suspend fun metadata(forceRefresh: Boolean = false): ProviderMetadata = mutex.withLock {
        if (!forceRefresh) {
            inMemory?.let { return@withLock it }
            cache.load()?.let { cached ->
                // A cached document from a different issuer belongs to a previous
                // configuration of this app; treat it as absent rather than trusting it.
                // Trailing-slash-insensitive, matching `ProviderMetadata.validate` — otherwise
                // metadata saved as "<issuer>/" would pass validation on first fetch but never
                // be recognised as a cache hit again, silently defeating the disk cache.
                if (cached.issuer.trimEnd('/') == issuer.trimEnd('/')) {
                    inMemory = cached
                    return@withLock cached
                }
            }
        }
        val fetched = client.fetch(issuer)
        cache.save(fetched)
        inMemory = fetched
        fetched
    }
}
