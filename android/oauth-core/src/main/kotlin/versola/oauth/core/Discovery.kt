package versola.oauth.core

import java.io.File
import java.io.IOException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
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

/**
 * RFC 8414 section 3.1 for an issuer that has a path: the suffix goes between the host and the path
 * (`https://host/tenant` is served at `https://host/.well-known/oauth-authorization-server/tenant`),
 * where OpenID Connect Discovery appends it. Null for an issuer without a path, where the two forms
 * are the same place.
 */
internal fun rfc8414WellKnownUrl(issuer: String): String? {
    val parsed = issuer.toHttpUrlOrNull() ?: return null
    val path = parsed.encodedPath.trimEnd('/')
    if (path.isEmpty()) return null
    return parsed.newBuilder().encodedPath("/.well-known/oauth-authorization-server$path").build().toString()
}

public class HttpDiscoveryClient(
    httpClient: OkHttpClient,
) : LifetimeAwareDiscoveryClient {

    /**
     * Redirects are never followed, whatever the injected client's policy: a `Location` would
     * otherwise choose where the issuer's metadata is read from, and the 300..399 branch below,
     * as at the key set and the token endpoint, would be dead code (`AUDIT B3`).
     */
    private val httpClient: OkHttpClient = httpClient.newBuilder()
        .followRedirects(false)
        .followSslRedirects(false)
        .build()

    override suspend fun fetch(issuer: String): ProviderMetadata = fetchWithLifetime(issuer).first

    override suspend fun fetchWithLifetime(issuer: String): Pair<ProviderMetadata, Long> {
        val primary = wellKnownUrl(issuer)
        val alternative = rfc8414WellKnownUrl(issuer)
        // An issuer with a path may publish its document at either well-known form; the OpenID one
        // is asked first and a 404 there, and only a 404, falls through to RFC 8414's.
        val fetched = fetchDocument(primary, absentIsNull = alternative != null)
            ?: fetchDocument(checkNotNull(alternative), absentIsNull = false)
            ?: throw IllegalStateException("unreachable")

        val (body, lifetime) = fetched
        // Checked after the fetch, outside the retry budget: the same page would be met again, and
        // iOS surfaces it once (`spec/errors.md`, "A body that is not JSON").
        if (!isJson(body)) throw notJsonFailure(200, null, "discovery")
        val metadata = try {
            discoveryJson.decodeFromString(ProviderMetadata.serializer(), body)
        } catch (e: Exception) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.DiscoveryMalformed(describeParseFailure(e)),
            )
        }
        metadata.validate(issuer)
        return metadata to lifetime
    }

    private suspend fun fetchDocument(url: String, absentIsNull: Boolean): Pair<String, Long>? {
        return retrying(originOf(url)) { withContext(SdkDispatchers.blocking) {
            val request = Request.Builder().url(url).header("Accept", "application/json").build()
            try {
                httpClient.newCall(request).execute().use { response ->
                    val payload = response.body.string()
                    when {
                        // A 2xx that is not JSON at all is a proxy's or a captive portal's page, not the
                        // provider's: the user's network, which a later attempt may not meet (`AUDIT D1`).
                        response.isSuccessful -> payload to CacheLifetime.of(response.headers, System.currentTimeMillis())
                        // 408, 429 and 5xx are the provider having a bad moment: transport-shaped,
                        // repeated under the operation's budget (`spec/retry-policy.md`).
                        ServerFault.isServerFault(response.code) -> throw ServerFault.failure(response.code, response.headers)
                        // A 4xx means this issuer does not serve a discovery document at all,
                        // which no retry fixes — an integrator typo or the wrong environment.
                        response.code == 404 && absentIsNull -> null
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
    }
}

/** What [FileProviderMetadataCache] writes: the document and the instant it stops being good, in one file. */
@kotlinx.serialization.Serializable
internal class ExpiringMetadata(val expiresAt: Long, val metadata: ProviderMetadata)

/**
 * A plain JSON file. Not encrypted, by the same reasoning as [ProviderMetadataCache].
 *
 * The expiry travels inside the file, beside the document ([ExpiringMetadata]), so one atomic write
 * sets both and nothing that merely touches the file can move it. A file written before expiry
 * existed holds the bare document: it still loads, with an expiry of zero, so it is used as the
 * fallback if the provider is unreachable and is otherwise fetched again, once.
 */
public class FileProviderMetadataCache(
    private val file: File,
    private val clock: () -> Long = System::currentTimeMillis,
) : ProviderMetadataCache {

    private fun read(): ExpiringMetadata? {
        if (!file.exists()) return null
        val text = file.readText()
        return try {
            discoveryJson.decodeFromString(ExpiringMetadata.serializer(), text)
        } catch (e: Exception) {
            // The envelope failed: a bare document from before expiry existed, or damage; the
            // second parse tells them apart.
            ExpiringMetadata(0, discoveryJson.decodeFromString(ProviderMetadata.serializer(), text))
        }
    }

    override suspend fun expiresAtEpochMillis(): Long? = withContext(SdkDispatchers.blocking) {
        try {
            read()?.expiresAt
        } catch (e: Exception) {
            null
        }
    }

    override suspend fun load(): ProviderMetadata? = withContext(SdkDispatchers.blocking) {
        try {
            read()?.metadata
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
        withContext(SdkDispatchers.blocking) {
            file.parentFile?.mkdirs()
            val temporary = File(file.parentFile, file.name + ".tmp")
            temporary.writeText(
                discoveryJson.encodeToString(ExpiringMetadata.serializer(), ExpiringMetadata(clock() + lifetimeMillis, metadata)),
            )
            if (!temporary.renameTo(file)) temporary.delete()
        }
    }

    override suspend fun clear() {
        withContext(SdkDispatchers.blocking) { file.delete() }
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

    /** Counts fetches that failed, so a caller that queued behind one can tell it was its answer too. */
    private var failures = 0L
    private var lastFailure: VersolaError? = null

    /**
     * Callers that arrive while a fetch is running queue on the lock, and a cold cache against an
     * unreachable provider would cost each of them a whole fetch of its own, retry budget included
     * (`AUDIT C10`). One that queued behind a fetch that then failed takes that failure as its own
     * answer instead; the next caller after it starts a fetch of its own, so nothing is remembered.
     */
    public suspend fun metadata(forceRefresh: Boolean = false): ProviderMetadata {
        val seen = failures
        return mutex.withLock {
            val shared = lastFailure
            if (failures != seen && shared != null) throw shared
            try {
                metadataUnderLock(forceRefresh)
            } catch (e: VersolaError) {
                failures++
                lastFailure = e
                throw e
            }
        }
    }

    private suspend fun metadataUnderLock(forceRefresh: Boolean): ProviderMetadata {
        // What was held but has aged out: the fallback if the provider cannot be asked.
        var stale: ProviderMetadata? = null
        if (!forceRefresh) {
            inMemory?.let {
                if (CacheLifetime.isFresh(inMemoryExpiresAt, clock())) return it
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
                        return cached
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
            return fallback
        }
        cache.save(fetched, lifetime)
        inMemory = fetched
        inMemoryExpiresAt = clock() + lifetime
        return fetched
    }
}

/** How long a document served stale because the provider was unreachable is trusted before the next try. */
private const val RETRY_AFTER_OUTAGE_MILLIS = 60_000L

/**
 * Whether [body] is a JSON object or array. A document of the wrong shape is the provider's mistake,
 * not a proxy's, so it is not rejected here; but a bare word is no document either, and the parser
 * would take `<html>` or `OK` for a lenient primitive.
 */
internal fun isJson(body: String): Boolean {
    val first = body.firstOrNull { !it.isWhitespace() }
    if (first != '{' && first != '[') return false
    return try {
        discoveryJson.parseToJsonElement(body)
        true
    } catch (e: kotlinx.serialization.SerializationException) {
        false
    }
}

/**
 * The `Recoverable(Network)` for a success status whose body is not JSON, with the status and the
 * content type and none of the body: it is a page that travels into logs, and a token endpoint's
 * answer is credential material. `Network`, because it is what a transport that went wrong in the
 * middle looks like, and so it is repeated as one under the operation's budget where repeating is
 * safe (`spec/errors.md`, "Not JSON").
 */
internal fun notJsonFailure(status: Int, contentType: String?, what: String): VersolaError.Recoverable =
    VersolaError.Recoverable(
        VersolaError.Recoverable.Cause.Network(
            "$what answered HTTP $status with a body that is not JSON" +
                (contentType?.let { " (Content-Type ${it.substringBefore(';').trim().take(64)})" } ?: ""),
        ),
    )

/**
 * What a parse failure may say about itself: the exception's class and, for a kotlinx.serialization
 * failure, the JSON path it stopped at. Never its message, which quotes a snippet of the input: a
 * token response is credential material and an error travels into logs and crash reports, and a
 * captive portal's page is not the app's to be handed back either (`AUDIT B13`, `D1`).
 */
internal fun describeParseFailure(e: Exception): String {
    val path = Regex("""at path: (\$[\w.\[\]]*)""").find(e.message.orEmpty())?.groupValues?.get(1)
    return "the response is not the expected JSON (${e::class.java.simpleName}${path?.let { " at $it" }.orEmpty()})"
}
