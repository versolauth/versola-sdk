package versola.oauth.conformance

import java.util.Base64
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import okhttp3.Interceptor
import okhttp3.Response
import okio.Buffer

/**
 * Every request the SDK emitted, as it went on the wire. Installed as a **network**
 * interceptor on the client `OAuthConfiguration.httpClient` is given, so it sees the headers
 * the SDK's own application interceptor added (`Authorization`, `DPoP`) rather than the request
 * as the app made it. A copy of the Versola driver's `Transcript` (`android/conformance-android`,
 * instrumented sources, which a unit test cannot depend on); keep the two the same.
 *
 * This is what the scenarios' assertions read.
 */
class Transcript : Interceptor {

    class Entry(
        val method: String,
        val url: String,
        val headers: Map<String, List<String>>,
        val body: String?,
        val status: Int,
        val responseHeaders: Map<String, List<String>>,
        val responseBody: String?,
    ) {
        val path: String get() = url.substringAfter("://").substringAfter('/').substringBefore('?').let { "/$it" }
        fun header(name: String): String? = headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value?.firstOrNull()
        fun headerCount(name: String): Int = headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value?.size ?: 0
        fun responseHeader(name: String): String? =
            responseHeaders.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value?.firstOrNull()

        /** `application/x-www-form-urlencoded` fields, decoded. */
        val form: Map<String, String>
            get() = body.orEmpty().split('&').filter { it.contains('=') }.associate {
                java.net.URLDecoder.decode(it.substringBefore('='), "UTF-8") to
                    java.net.URLDecoder.decode(it.substringAfter('='), "UTF-8")
            }

        /** The DPoP proof's claims, when the request carried one. */
        val proofClaims: JsonObject? get() = header("DPoP")?.let { decodeJwtPart(it, 1) }
        val proofHeader: JsonObject? get() = header("DPoP")?.let { decodeJwtPart(it, 0) }

        val responseJson: JsonObject? get() = responseBody?.let { runCatching { Json.parseToJsonElement(it).jsonObject }.getOrNull() }

        override fun toString(): String = "$method $url -> $status"
    }

    private val lock = Any()
    private val recorded = mutableListOf<Entry>()

    val entries: List<Entry> get() = synchronized(lock) { recorded.toList() }

    fun clear() = synchronized(lock) { recorded.clear() }

    fun matching(method: String, pathSuffix: String): List<Entry> =
        entries.filter { it.method == method && it.path.endsWith(pathSuffix) }

    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val body = request.body?.let { body ->
            if (body.isOneShot() || body.isDuplex()) null
            else Buffer().also { body.writeTo(it) }.readUtf8()
        }
        val response = chain.proceed(request)
        val responseBody = response.peekBody(1_048_576).string()
        synchronized(lock) {
            recorded += Entry(
                method = request.method,
                url = request.url.toString(),
                headers = request.headers.toMultimap(),
                body = body,
                status = response.code,
                responseHeaders = response.headers.toMultimap(),
                responseBody = responseBody,
            )
        }
        return response
    }

    companion object {
        fun decodeJwtPart(jwt: String, index: Int): JsonObject? = runCatching {
            Json.parseToJsonElement(String(Base64.getUrlDecoder().decode(jwt.split('.')[index]), Charsets.UTF_8)).jsonObject
        }.getOrNull()

        fun base64UrlSha256(value: String): String {
            val digest = java.security.MessageDigest.getInstance("SHA-256").digest(value.toByteArray(Charsets.US_ASCII))
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
        }
    }
}
