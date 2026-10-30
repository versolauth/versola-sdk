package versola.oauth.flutter

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Buffer
import versola.oauth.core.IdTokenRejection
import versola.oauth.core.SessionState
import versola.oauth.core.TokenBinding
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaError.Configuration.Detail
import versola.oauth.core.VersolaError.Reauthenticate.Reason
import versola.oauth.core.VersolaError.Recoverable.Cause

/** The flattening is the contract with Dart's `errorFromMessage`: category, then the case name. */
class MappingTest {
    @Test
    fun everyRecoverableCauseKeepsItsCategoryAndPayload() {
        val network = VersolaError.Recoverable(Cause.Network(detail = "timeout", attempts = 3, elapsedMillis = 1200)).toMessage()
        assertEquals(ErrorCategoryMessage.RECOVERABLE, network.category)
        assertEquals("network", network.kind)
        assertEquals("timeout", network.detail)
        assertEquals(3L, network.attempts)
        assertEquals(1200L, network.elapsedMillis)

        val server = VersolaError.Recoverable(Cause.Server(status = 429, retryAfterMillis = 30_000, attempts = 1, elapsedMillis = 40)).toMessage()
        assertEquals(ErrorCategoryMessage.RECOVERABLE, server.category)
        assertEquals("server", server.kind)
        assertEquals(429L, server.status)
        assertEquals(30_000L, server.retryAfterMillis)
        assertEquals(1L, server.attempts)

        // No Retry-After is no field, not a zero: an app that waits zero is hammering.
        val plain = VersolaError.Recoverable(Cause.Server(status = 500)).toMessage()
        assertEquals(500L, plain.status)
        assertNull(plain.retryAfterMillis)

        val loop = VersolaError.Recoverable(Cause.NonceLoop("https://api.example.com")).toMessage()
        assertEquals("nonceLoop", loop.kind)
        assertEquals("https://api.example.com", loop.origin)
        assertEquals("userCancelled", VersolaError.Recoverable(Cause.UserCancelled).toMessage().kind)
        assertEquals("unlockRequired", VersolaError.Recoverable(Cause.UnlockRequired).toMessage().kind)
    }

    @Test
    fun reauthenticateCarriesTheInteractionCode() {
        val m = VersolaError.Reauthenticate(Reason.InteractionRequired("login_required")).toMessage()
        assertEquals(ErrorCategoryMessage.REAUTHENTICATE, m.category)
        assertEquals("interactionRequired", m.kind)
        assertEquals("login_required", m.code)
        assertNull(VersolaError.Reauthenticate(Reason.SessionExpired).toMessage().code)
    }

    @Test
    fun stepUpIsItsOwnCategoryWithTheChallenge() {
        val m = VersolaError.StepUp(listOf("urn:acr:mfa"), 300).toMessage()
        assertEquals(ErrorCategoryMessage.STEP_UP, m.category)
        assertEquals(listOf("urn:acr:mfa"), m.acrValues)
        assertEquals(300L, m.maxAge)
    }

    @Test
    fun configurationDetailsKeepTheirFields() {
        val rejected = VersolaError.Configuration(Detail.TokenRequestRejected("invalid_grant", "expired")).toMessage()
        assertEquals(ErrorCategoryMessage.CONFIGURATION, rejected.category)
        assertEquals("tokenRequestRejected", rejected.kind)
        assertEquals("invalid_grant", rejected.code)
        assertEquals("expired", rejected.errorDescription)

        val idToken = VersolaError.Configuration(Detail.IdTokenRejected(IdTokenRejection.AccessTokenHash)).toMessage()
        assertEquals("idTokenRejected", idToken.kind)
        assertEquals("accessTokenHash", idToken.idTokenRejection)

        val issuer = VersolaError.Configuration(Detail.DiscoveryIssuerMismatch("https://a.example.com", "https://b.example.com")).toMessage()
        assertEquals("https://a.example.com", issuer.expected)
        assertEquals("https://b.example.com", issuer.received)
    }

    @Test
    fun anExceptionThatIsNotAnSdkErrorCrossesAsAConfigurationNamingOnlyItsClass() {
        val m = IllegalStateException("refresh_token=do-not-leak").toErrorMessage()
        assertEquals(ErrorCategoryMessage.CONFIGURATION, m.category)
        assertEquals("invalidConfiguration", m.kind)
        assertEquals("unexpected IllegalStateException", m.detail)
        assertFalse(m.message.contains("do-not-leak"))
        // An SDK error keeps its own mapping through the same entry point.
        assertEquals("grantRejected", VersolaError.Reauthenticate(Reason.GrantRejected).toErrorMessage().kind)
    }

    @Test
    fun sessionStatesMapOneToOne() {
        val states = listOf(
            SessionState.Unauthenticated, SessionState.Authorizing, SessionState.Authenticated, SessionState.Refreshing,
            SessionState.StepUpRequired, SessionState.Locked, SessionState.LoggingOut,
        )
        assertEquals(SessionStateMessage.values().toList(), states.map { it.toMessage() })
    }

    @Test
    fun configurationMessageBuildsTheSdkConfiguration() {
        val c = ConfigurationMessage(
            issuer = "https://id.example.com",
            clientId = "app",
            redirectUri = "https://app.example.com/oauth",
            scopes = listOf("openid", "profile"),
            tokenBinding = TokenBindingMessage.DPOP_REQUIRE_HARDWARE,
            pushedAuthorization = PushedAuthorizationMessage.REQUIRED,
            protectedOrigins = listOf("https://api.example.com"),
            unlockPolicy = UnlockPolicyMessage.NONE,
            clockSkewToleranceSeconds = 30,
        ).toConfiguration()
        assertEquals("https://id.example.com", c.issuerIdentifier)
        assertEquals(setOf("openid", "profile"), c.effectiveScopes)
        assertEquals(TokenBinding.Dpop(requireHardware = true), c.tokenBinding)
        assertEquals(setOf("https://api.example.com"), c.protectedOrigins)
    }

    // MARK: HTTP

    private fun request(
        method: String = "GET",
        url: String = "https://api.example.com/items?page=2",
        headers: List<Pair<String, String>> = emptyList(),
        body: ByteArray? = null,
    ) = HttpRequestMessage(method, url, headers.map { HttpHeaderMessage(it.first, it.second) }, body)

    private fun bodyOf(request: Request): ByteArray = Buffer().also { request.body!!.writeTo(it) }.readByteArray()

    private fun refused(block: () -> Unit): VersolaError.Configuration = try {
        block()
        fail("expected the request to be refused")
        error("unreachable")
    } catch (e: VersolaError.Configuration) {
        e
    }

    @Test
    fun aRequestKeepsItsMethodUrlHeadersAndBytes() {
        val sent = request(
            method = "POST",
            headers = listOf("X-Trace" to "abc", "Content-Type" to "application/json"),
            body = "payload".toByteArray(),
        ).toRequest()

        assertEquals("POST", sent.method)
        assertEquals("https://api.example.com/items?page=2", sent.url.toString())
        assertEquals("abc", sent.header("x-trace"))
        assertEquals("application/json", sent.header("Content-Type"))
        assertEquals("payload", String(bodyOf(sent)))
    }

    @Test
    fun aRepeatedRequestHeaderKeepsEveryValueInOrder() {
        val sent = request(headers = listOf("Accept" to "a/b", "accept" to "c/d")).toRequest()

        assertEquals(listOf("a/b", "c/d"), sent.headers.values("Accept"))
    }

    @Test
    fun theMappingAddsNoAuthorizationAndKeepsTheAppsOwn() {
        // Replacing it on a protected origin is the SDK client's rule (VersolaInterceptorTest); on any
        // other origin the app's header must reach the wire as written, so the glue neither adds nor drops one.
        val none = request().toRequest()
        assertNull(none.header("Authorization"))
        assertNull(none.header("DPoP"))
        val own = request(headers = listOf("Authorization" to "Bearer app-own")).toRequest()
        assertEquals("Bearer app-own", own.header("Authorization"))
    }

    @Test
    fun anEmptyBodyIsFineForMethodsThatNeedOneAndNoBodyForGetAndHead() {
        assertEquals(0, bodyOf(request(method = "POST").toRequest()).size)
        assertEquals(0, bodyOf(request(method = "PUT", body = ByteArray(0)).toRequest()).size)
        assertNull(request(method = "GET", body = ByteArray(0)).toRequest().body)
        assertNull(request(method = "DELETE").toRequest().body)
    }

    @Test
    fun aBodyOnGetAndHeadIsRefusedAsInvalidConfigurationRatherThanDroppedOrCrashing() {
        listOf("GET", "HEAD").forEach { method ->
            val error = refused { request(method = method, body = byteArrayOf(1)).toRequest() }
            assertTrue(error.detail is Detail.InvalidConfiguration)
        }
    }

    @Test
    fun aRelativeUrlANonHttpSchemeAndAnUnparseableUrlAreRefusedWithoutEchoingThem() {
        listOf("/items", "ftp://api.example.com/x", "ws://api.example.com/x", "not a url").forEach { url ->
            val error = refused { request(url = url).toRequest() }
            assertTrue(error.detail is Detail.InvalidConfiguration)
            assertFalse(error.toString().contains(url))
        }
    }

    @Test
    fun aMalformedHeaderIsRefusedWithAFixedTextThatDoesNotQuoteItsValue() {
        val secret = "Bearer s3cr3t\u00e9"
        listOf("Authorization" to secret, "Bad Name" to "x", "X-Line" to "a\nb").forEach { header ->
            val error = refused { request(headers = listOf(header)).toRequest() }
            assertTrue(error.detail is Detail.InvalidConfiguration)
            assertFalse(error.toString().contains("s3cr3t"))
        }
    }

    @Test
    fun aResponseKeepsStatusReasonBytesAndEveryHeaderValueInOrder() {
        val response = Response.Builder()
            .request(Request.Builder().url("https://api.example.com/").build())
            .protocol(Protocol.HTTP_1_1)
            .code(401)
            .message("Unauthorized")
            .addHeader("WWW-Authenticate", "Bearer realm=\"a\"")
            .addHeader("WWW-Authenticate", "DPoP algs=\"ES256\"")
            .addHeader("Set-Cookie", "a=1; Path=/")
            .addHeader("Set-Cookie", "b=2; Path=/")
            .body(byteArrayOf(0, 1, 2, 3).toResponseBody())
            .build()

        val message = response.toMessage()

        assertEquals(401L, message.status)
        assertEquals("Unauthorized", message.reasonPhrase)
        assertEquals(listOf<Byte>(0, 1, 2, 3), message.body.toList())
        assertEquals(
            listOf("WWW-Authenticate" to "Bearer realm=\"a\"", "WWW-Authenticate" to "DPoP algs=\"ES256\"", "Set-Cookie" to "a=1; Path=/", "Set-Cookie" to "b=2; Path=/"),
            message.headers.map { it.name to it.value },
        )
    }

    @Test
    fun aRedirectAndAThrottledResponseAreMappedAsResponses() {
        listOf(302 to "Location", 429 to "Retry-After", 503 to "Retry-After").forEach { (code, name) ->
            val message = Response.Builder()
                .request(Request.Builder().url("https://api.example.com/").build())
                .protocol(Protocol.HTTP_2)
                .code(code)
                .message("")
                .addHeader(name, "7")
                .body(ByteArray(0).toResponseBody())
                .build()
                .toMessage()

            assertEquals(code.toLong(), message.status)
            assertNull("HTTP/2 has no reason phrase", message.reasonPhrase)
            assertEquals(listOf(name to "7"), message.headers.map { it.name to it.value })
        }
    }
}
