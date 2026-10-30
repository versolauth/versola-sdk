package versola.oauth.conformance

import java.util.concurrent.CopyOnWriteArrayList
import mockwebserver3.Dispatcher
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * A protected resource that accepts the staged provider's access tokens (scenario 24's second
 * precondition): `/api` answers 200 with the token's subject when the provider's UserInfo
 * endpoint accepts the bearer token, and 401 with a `Bearer` challenge otherwise, as a resource
 * server validating opaque tokens by introspection would. `/redirect` answers a 302 to another
 * origin, for the assertion that the authenticated client does not follow one (scenario 32), and
 * `/unavailable` a 503 with `Retry-After: 7`, for the one that it returns a status as the response
 * it is (scenario 34).
 *
 * The token is checked at the provider's UserInfo endpoint through the proxy, because a
 * provider that derives its issuer from the request (Keycloak) issued the token for the proxy's
 * origin and refuses it at its own. The resource's own client carries no transcript
 * interceptor, so the check shows in `ProviderProxy.requests` but never in the SDK's transcript.
 */
class ResourceServer(private val provider: Provider, private val proxy: ProviderProxy) : Dispatcher() {

    private val server = MockWebServer()
    private val http = OkHttpClient()
    val requests = CopyOnWriteArrayList<RecordedRequest>()

    /** `http://localhost:<port>`; loopback, which the facade's origin check allows over http. */
    val origin: String get() = server.url("/").toString().trimEnd('/')

    fun start() {
        server.dispatcher = this
        server.start()
    }

    fun stop() = server.close()

    fun url(path: String): String = origin + path

    override fun dispatch(request: RecordedRequest): MockResponse {
        requests += request
        val token = request.headers["Authorization"]?.takeIf { it.startsWith("Bearer ") }?.removePrefix("Bearer ")
        val subject = token?.let { subjectOf(it) }
        return when {
            subject == null -> MockResponse.Builder().code(401).setHeader("WWW-Authenticate", "Bearer realm=\"resource\"").build()
            request.url.encodedPath == "/unavailable" ->
                MockResponse.Builder().code(503).setHeader("Retry-After", "7").build()
            request.url.encodedPath == "/redirect" ->
                MockResponse.Builder().code(302).setHeader("Location", "https://elsewhere.example.com/landing").build()
            else -> MockResponse.Builder().code(200).setHeader("Content-Type", "application/json").body("""{"sub":"$subject"}""").build()
        }
    }

    /** The provider's advertised UserInfo endpoint, read once from its own discovery and re-rooted at the proxy. */
    private val userinfo: String by lazy {
        val discovery = http.newCall(Request.Builder().url(provider.issuer + "/.well-known/openid-configuration").build()).execute().text()
        val endpoint = Regex(""""userinfo_endpoint"\s*:\s*"([^"]+)"""").find(discovery)?.groupValues?.get(1)
            ?: error("the provider advertises no userinfo_endpoint; the resource server cannot check tokens")
        endpoint.replace(provider.origin, proxy.origin)
    }

    private fun subjectOf(token: String): String? {
        return http.newCall(Request.Builder().url(userinfo).header("Authorization", "Bearer $token").build()).execute().use { response ->
            if (response.code != 200) return null
            Regex(""""sub"\s*:\s*"([^"]+)"""").find(response.body.string())?.groupValues?.get(1)
        }
    }
}
