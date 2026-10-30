package versola.oauth.flutter.conformance

import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import versola.oauth.conformance.ResourceServer
import versola.oauth.flutter.ErrorCategoryMessage

/**
 * `32-protected-origins` through the bridge. The subject is the authenticated client, which
 * Flutter reaches as `OAuthClient.httpClient()`: Dart sends one `httpRequest` and the plugin runs it
 * with `OAuthClient.call`, the SDK's own client, so each test below sends the request the way the
 * Dart client does ([DartSide.httpRequest]) and reads what reached the wire off the SDK's
 * transcript (the driver's HTTP client records every network request, replays included).
 *
 * Differences from the native twin: `create` accepts an empty `protectedOrigins` (the facade
 * demands origins of the authenticated client, not of the configuration), so the "constructing
 * with an empty or non-https set" assertion is the first request through the client, which is
 * refused before anything is sent: `httpClient()` returns synchronously and cannot ask native.
 * The DPoP half (htu without query, ath) is scenario 33's bridge test.
 *
 * Two tests keep the pre-`httpClient()` shape on purpose: the token `accessToken()` returns is
 * accepted by the provider's resource (the escape hatch still works), and `create` still refuses a
 * `protectedOrigins` entry that is not an origin.
 */
class Scenario32ProtectedOriginsBridgeTest : BridgeConformance() {

    private val extraServers = mutableListOf<ResourceServer>()
    private val rawServers = mutableListOf<MockWebServer>()

    @org.junit.After
    fun stopServers() {
        extraServers.forEach { it.stop() }
        rawServers.forEach { it.close() }
    }

    private fun secondResource(): ResourceServer = ResourceServer(provider, proxy).also {
        it.start()
        extraServers += it
    }

    private fun rawServer(): MockWebServer = MockWebServer().also {
        it.start()
        rawServers += it
    }

    private fun MockWebServer.origin(): String = url("/").toString().trimEnd('/')

    private fun tokenPath(bridge: Bridge) = bridge.observe("discovery") { metadata() }.tokenEndpoint.substringAfter(proxy.origin)

    @Test
    fun `bridge - the token that crosses is accepted at the configured origin and the SDK sends nothing there itself`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()
        val token = bridge.dart.accessToken().token()
        val subject = checkNotNull(bridge.dart.claims()).subject

        // The app attaches the token itself, as it would without httpClient(): the configured origin accepts it, with a path and a query.
        val configured = appCall(token, resource.url("/api"))
        val withPathAndQuery = appCall(token, resource.url("/api/items?page=2"))
        val configuredBody = configured.use { it.body.string() }
        withPathAndQuery.close()
        assertEquals(200, configured.code)
        assertEquals(200, withPathAndQuery.code)
        assertTrue(configuredBody.contains(subject))
        assertEquals("Bearer", token.tokenType)
        // The SDK itself never contacted the resource, and a request the app makes without the token is not the SDK's to fix.
        assertTrue(transcript.entries.none { it.url.startsWith(resource.origin) })
        assertEquals(1, transcript.matching("POST", tokenPath(bridge)).size)
    }

    @Test
    fun `bridge - a non-https origin and an origin with a path are refused by create`() {
        val plain = dart().create(message(protectedOrigins = setOf("http://api.example.com"))).failure()
        assertError(plain, ErrorCategoryMessage.CONFIGURATION, "invalidConfiguration")
        val withPath = dart().create(message(protectedOrigins = setOf("https://api.example.com/v1"))).failure()
        assertError(withPath, ErrorCategoryMessage.CONFIGURATION, "invalidConfiguration")
    }

    @Test
    fun `bridge - httpRequest attaches the token to the configured origin with any path and query, and to nothing else`() {
        val second = secondResource()
        val bridge = bridge()
        bridge.dart.login().assertOk()
        val tokenPath = tokenPath(bridge)

        val configured = bridge.dart.httpRequest(resource.url("/api")).response()
        val withPathAndQuery = bridge.dart.httpRequest(resource.url("/api/items?page=2")).response()
        // The same host on another port, and the same server under another host name.
        val otherPort = bridge.dart.httpRequest(second.url("/api")).response()
        val otherHost = bridge.dart.httpRequest(resource.origin.replace("localhost", "127.0.0.1") + "/api").response()

        assertEquals(200, configured.status)
        assertEquals(200, withPathAndQuery.status)
        assertEquals(401, otherPort.status)
        assertEquals(401, otherHost.status)
        assertTrue(String(configured.body), String(configured.body).contains(checkNotNull(bridge.dart.claims()).subject))
        val sent = transcript.entries.filter { it.url.contains("/api") }
        assertEquals(4, sent.size)
        sent.filter { it.url.startsWith(resource.origin) }.forEach { assertTrue(it.header("Authorization")!!.startsWith("Bearer ")) }
        sent.filter { !it.url.startsWith(resource.origin) }.forEach { assertNull(it.header("Authorization")) }
        // A 401 from an origin that is not protected does not spend the refresh token.
        assertEquals(1, transcript.matching("POST", tokenPath).size)
    }

    @Test
    fun `bridge - a redirect from a protected origin is returned with its Location and not followed`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()

        val redirected = bridge.dart.httpRequest(resource.url("/redirect")).response()

        assertEquals(302, redirected.status)
        assertEquals(listOf("https://elsewhere.example.com/landing"), redirected.headerValues("Location"))
        assertTrue(transcript.entries.none { it.url.contains("elsewhere.example.com") })
        assertEquals(1, transcript.entries.count { it.url.contains("/redirect") })
    }

    @Test
    fun `bridge - an Authorization header the app set on a protected origin is replaced by the SDK's, and left alone elsewhere`() {
        val second = secondResource()
        val bridge = bridge()
        bridge.dart.login().assertOk()
        val appHeaders = listOf("Authorization" to "Bearer app-supplied", "authorization" to "Bearer app-supplied-too", "DPoP" to "app-forged")

        val protected = bridge.dart.httpRequest(resource.url("/api"), headers = appHeaders).response()
        val unprotected = bridge.dart.httpRequest(second.url("/api"), headers = appHeaders).response()

        assertEquals("the SDK's token is the one the resource saw", 200, protected.status)
        val own = transcript.entries.single { it.url.startsWith(resource.origin) && it.url.contains("/api") }
        assertEquals(1, own.headerCount("Authorization"))
        assertTrue(own.header("Authorization")!!, own.header("Authorization")!!.startsWith("Bearer ") && !own.header("Authorization")!!.contains("app-supplied"))
        assertEquals("a bearer session sends no proof, and the app's is dropped", 0, own.headerCount("DPoP"))
        // Another origin is the app's: its headers go out as written and the 401 is returned, no refresh.
        assertEquals(401, unprotected.status)
        val elsewhere = transcript.entries.single { it.url.startsWith(second.origin) }
        assertEquals(listOf("Bearer app-supplied", "Bearer app-supplied-too"), elsewhere.headers.entries.single { it.key.equals("Authorization", true) }.value)
        assertEquals("app-forged", elsewhere.header("DPoP"))
        assertEquals(1, transcript.matching("POST", tokenPath(bridge)).size)
    }

    @Test
    fun `bridge - origins given per client replace the configured ones for that client`() {
        val second = secondResource()
        val bridge = bridge()
        bridge.dart.login().assertOk()

        val first = bridge.dart.httpRequest(resource.url("/api"), origins = listOf(second.origin)).response()
        val other = bridge.dart.httpRequest(second.url("/api"), origins = listOf(second.origin)).response()

        assertEquals("the configured origin is not in this client's set, so it gets no token", 401, first.status)
        assertEquals(200, other.status)
        assertNull(transcript.entries.single { it.url.startsWith(resource.origin) && it.url.contains("/api") }.header("Authorization"))
        assertTrue(transcript.entries.single { it.url.startsWith(second.origin) }.header("Authorization")!!.startsWith("Bearer "))
    }

    @Test
    fun `bridge - an empty origin set and a non-https origin are refused with InvalidConfiguration before anything is sent`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()
        val sentBefore = transcript.entries.size

        assertError(bridge.dart.httpRequest(resource.url("/api"), origins = emptyList()).failure(), ErrorCategoryMessage.CONFIGURATION, "invalidConfiguration")
        assertError(bridge.dart.httpRequest(resource.url("/api"), origins = listOf("http://api.example.com")).failure(), ErrorCategoryMessage.CONFIGURATION, "invalidConfiguration")
        assertError(bridge.dart.httpRequest(resource.url("/api"), origins = listOf("https://api.example.com/v1")).failure(), ErrorCategoryMessage.CONFIGURATION, "invalidConfiguration")
        assertEquals(sentBefore, transcript.entries.size)
    }

    @Test
    fun `bridge - a client configured with no protected origins refuses the request unless it names origins`() {
        val bridge = bridge(protectedOrigins = emptySet())
        bridge.dart.login().assertOk()
        val sentBefore = transcript.entries.size

        val refused = bridge.dart.httpRequest(resource.url("/api")).failure()

        assertError(refused, ErrorCategoryMessage.CONFIGURATION, "invalidConfiguration")
        assertEquals(sentBefore, transcript.entries.size)
        assertEquals(200, bridge.dart.httpRequest(resource.url("/api"), origins = listOf(resource.origin)).response().status)
    }

    @Test
    fun `bridge - a request that is not an HTTP request is refused with a fixed text that does not quote the header`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()

        val relative = bridge.dart.httpRequest("/api").failure()
        val badHeader = bridge.dart.httpRequest(resource.url("/api"), headers = listOf("X-Bad" to "Bearer s3cr3t\nX-Injected: y")).failure()
        val getWithBody = bridge.dart.httpRequest(resource.url("/api"), body = byteArrayOf(1)).failure()

        listOf(relative, badHeader, getWithBody).forEach { assertError(it, ErrorCategoryMessage.CONFIGURATION, "invalidConfiguration") }
        assertTrue(!badHeader.toString().contains("s3cr3t"))
        assertTrue(transcript.entries.none { it.url.contains("/api") })
    }

    @Test
    fun `bridge - a 503 with Retry-After is returned as the response after exactly one request`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()

        val unavailable = bridge.dart.httpRequest(resource.url("/unavailable")).response()

        assertEquals(503, unavailable.status)
        assertEquals(listOf("7"), unavailable.headerValues("Retry-After"))
        assertEquals(1, transcript.entries.count { it.url.contains("/unavailable") })
    }

    @Test
    fun `bridge - request bytes and response bytes cross unchanged, a repeated response header keeps both values`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()
        val server = rawServer()
        server.enqueue(
            MockResponse.Builder().code(200).addHeader("Set-Cookie", "a=1; Path=/").addHeader("Set-Cookie", "b=2; Path=/")
                .addHeader("Content-Type", "application/octet-stream").body(okio.Buffer().write(ByteArray(256) { (255 - it).toByte() })).build(),
        )
        val everyByte = ByteArray(256) { it.toByte() }

        val response = bridge.dart.httpRequest(
            server.origin() + "/upload", method = "POST", headers = listOf("Content-Type" to "application/octet-stream"),
            body = everyByte, origins = listOf(server.origin()),
        ).response()

        val received = server.takeRequest()
        assertEquals("POST", received.method)
        assertEquals(everyByte.toList(), received.body!!.toByteArray().toList())
        assertEquals("application/octet-stream", received.headers["Content-Type"])
        assertEquals(200, response.status)
        assertEquals(ByteArray(256) { (255 - it).toByte() }.toList(), response.body.toList())
        assertEquals(listOf("a=1; Path=/", "b=2; Path=/"), response.headerValues("Set-Cookie"))
    }

    @Test
    fun `bridge - a 401 refreshes once and the request is replayed with its body and the new token`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()
        val tokenPath = tokenPath(bridge)
        val server = rawServer()
        server.enqueue(MockResponse.Builder().code(401).setHeader("WWW-Authenticate", "Bearer error=\"invalid_token\"").build())
        server.enqueue(MockResponse.Builder().code(200).body("done").build())

        val response = bridge.dart.httpRequest(
            server.origin() + "/orders", method = "POST", body = "item=1".toByteArray(), origins = listOf(server.origin()),
        ).response()

        assertEquals(200, response.status)
        assertEquals("done", String(response.body))
        val first = server.takeRequest()
        val replay = server.takeRequest()
        assertEquals("item=1", first.body!!.utf8())
        assertEquals("the body is sent again", "item=1", replay.body!!.utf8())
        assertNotEquals("the replay carries the refreshed token", first.headers["Authorization"], replay.headers["Authorization"])
        assertEquals("one refresh, spent once", 2, transcript.matching("POST", tokenPath).size)
        assertEquals("refresh_token", transcript.matching("POST", tokenPath)[1].form["grant_type"])
    }

    @Test
    fun `bridge - a second 401 after the refresh is a refused session, not a second refresh`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()
        val tokenPath = tokenPath(bridge)
        val server = rawServer()
        repeat(3) { server.enqueue(MockResponse.Builder().code(401).build()) }

        val error = bridge.dart.httpRequest(server.origin() + "/orders", origins = listOf(server.origin())).failure()

        assertError(error, ErrorCategoryMessage.REAUTHENTICATE, "sessionRejected")
        assertEquals(2, server.requestCount)
        assertEquals(2, transcript.matching("POST", tokenPath).size)
    }

    @Test
    fun `bridge - a step-up challenge is a StepUp error with its parameters and no refresh`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()
        val tokenPath = tokenPath(bridge)
        val server = rawServer()
        server.enqueue(
            MockResponse.Builder().code(401)
                .setHeader("WWW-Authenticate", "Bearer error=\"insufficient_user_authentication\", acr_values=\"urn:example:mfa\", max_age=300").build(),
        )

        val error = bridge.dart.httpRequest(server.origin() + "/transfer", origins = listOf(server.origin())).failure()

        assertError(error, ErrorCategoryMessage.STEP_UP, "stepUp")
        assertEquals(listOf("urn:example:mfa"), error.acrValues)
        assertEquals(300L, error.maxAge)
        assertEquals(1, server.requestCount)
        assertEquals("no refresh: the token is valid, its authentication context is not", 1, transcript.matching("POST", tokenPath).size)
    }

    @Test
    fun `bridge - a call that gets no HTTP response is a transport failure naming the exception class only`() {
        val bridge = bridge()
        bridge.dart.login().assertOk()
        val server = rawServer()
        val origin = server.origin()
        server.close() // nothing listens on the port any more

        val result = bridge.dart.httpRequest("$origin/gone/s3cr3t-path", origins = listOf(origin))

        val failure = result as? versola.oauth.flutter.HttpTransportFailure ?: throw AssertionError("expected a transport failure, got $result")
        assertTrue(failure.exception, failure.exception.endsWith("Exception"))
        assertTrue(!result.toString().contains("s3cr3t-path"))
    }
}
