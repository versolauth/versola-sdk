package versola.oauth.conformance

import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import mockwebserver3.Dispatcher
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import okhttp3.Headers
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okio.Buffer

/**
 * The fault-injection seam of `conformance/README.md`: a reverse proxy in front of the staged
 * provider that the SDK is pointed at as its issuer. Every request is forwarded with the
 * proxy's own origin as `Host`, so a provider that builds its issuer, its endpoints and its
 * login form's action from the request (Keycloak in development mode does) announces the proxy
 * as itself, and the SDK's issuer check, the ID token's `iss` and the redirect's `iss` all agree
 * without the provider being told about the proxy.
 *
 * A test installs rewrites per path for one scenario: `omit-discovery-field` is a rewrite of
 * the discovery document, an ID-token fault is a rewrite of the token response (re-signed with
 * the harness's key, which a substituted JWKS serves), a dead revocation endpoint is a canned
 * 503. With nothing installed the proxy is transparent.
 */
class ProviderProxy(private val provider: Provider) : Dispatcher() {

    private val server = MockWebServer()
    private val upstream = OkHttpClient.Builder().followRedirects(false).followSslRedirects(false).build()

    /** Answers a request instead of forwarding it; null forwards. Checked before [rewrites]. */
    @Volatile var intercept: (RecordedRequest) -> MockResponse? = { null }

    /** Rewrites a forwarded response's body for a path suffix; the status and headers stay. */
    private val rewrites = CopyOnWriteArrayList<Pair<String, (String) -> String>>()

    /** Headers added to every forwarded response for a path suffix (a `Date`, for the skew scenarios). */
    private val addedHeaders = CopyOnWriteArrayList<Pair<String, Headers>>()

    val requests = CopyOnWriteArrayList<RecordedRequest>()

    /** `scheme://host:port` of the proxy: the origin the provider announces as its own. */
    val origin: String get() = server.url("/").toString().trimEnd('/')

    /** The issuer the SDK is configured with: the provider's issuer path at the proxy's origin. */
    val issuer: String get() = origin + provider.issuerPath

    /** [port] 0 picks a free one; a provider that is told the proxy's address in advance (Hydra) needs a fixed one. */
    fun start(port: Int = 0) {
        server.dispatcher = this
        server.start(port)
    }

    fun stop() = server.close()

    fun rewrite(pathSuffix: String, body: (String) -> String) {
        rewrites += pathSuffix to body
    }

    fun rewriteJson(pathSuffix: String, body: (JsonObject) -> JsonObject) = rewrite(pathSuffix) { raw ->
        body(Json.parseToJsonElement(raw).jsonObject).toString()
    }

    fun addHeaders(pathSuffix: String, headers: Headers) {
        addedHeaders += pathSuffix to headers
    }

    fun clearRewrites() {
        rewrites.clear()
        addedHeaders.clear()
        intercept = { null }
    }

    fun requestsTo(pathSuffix: String): List<RecordedRequest> = requests.filter { it.url.encodedPath.endsWith(pathSuffix) }

    override fun dispatch(request: RecordedRequest): MockResponse {
        requests += request
        intercept(request)?.let { return it }
        val url = provider.origin + request.url.encodedPath + (request.url.encodedQuery?.let { "?$it" } ?: "")
        val headers = Headers.Builder().apply {
            request.headers.forEach { (name, value) ->
                // Host is the point; the hop-by-hop and length headers are OkHttp's to set, and
                // without a client Accept-Encoding OkHttp asks for gzip and decodes it itself.
                if (name.lowercase() !in setOf("host", "content-length", "transfer-encoding", "connection", "accept-encoding")) {
                    add(name, value)
                }
            }
            set("Host", server.url("/").let { "${it.host}:${it.port}" })
        }.build()
        val method = request.method ?: "GET"
        val body = request.body?.takeIf { method != "GET" && method != "HEAD" }?.let { bytes ->
            bytes.toByteArray().toRequestBody(request.headers["Content-Type"]?.toMediaTypeOrNull())
        }
        val forwarded = Request.Builder().url(url).headers(headers).method(method, body).build()
        return upstream.newCall(forwarded).execute().use { response ->
            var text = response.body.string()
            val path = request.url.encodedPath
            rewrites.filter { path.endsWith(it.first) }.forEach { (_, rewrite) -> text = rewrite(text) }
            MockResponse.Builder().apply {
                code(response.code)
                response.headers.forEach { (name, value) ->
                    if (name.lowercase() !in setOf("content-length", "content-encoding", "transfer-encoding", "connection")) {
                        addHeader(name, value)
                    }
                }
                addedHeaders.filter { path.endsWith(it.first) }.forEach { (_, extra) -> extra.forEach { (n, v) -> setHeader(n, v) } }
                body(Buffer().write(text.toByteArray()))
            }.build()
        }
    }
}
