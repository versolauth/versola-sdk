package versola.sdk.flutter

import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Buffer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import versola.oauth.core.AuthorizationParameters
import versola.oauth.core.IdTokenRejection
import versola.oauth.core.SessionState
import versola.oauth.core.UnlockPolicy
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaError.Configuration.Detail
import versola.oauth.core.VersolaError.Reauthenticate.Reason
import versola.oauth.core.VersolaError.Recoverable.Cause
import versola.sdk.core.EdgeClientUnknown

/** The flattening is the contract with Dart's `errorFromMessage`: category, then the case name. */
class MappingTest {
    @Test
    fun theStableCodeCrossesAndIsNotTheProvidersOAuthCode() {
        val rejected = VersolaError.Configuration(Detail.TokenRequestRejected("invalid_scope", "no")).toMessage()
        assertEquals("configuration.token_request_rejected", rejected.sdkCode)
        assertEquals("invalid_scope", rejected.code)
        val denied = VersolaError.Reauthenticate(Reason.AuthorizationDenied).toMessage()
        assertEquals("reauthenticate.authorization_denied", denied.sdkCode)
        assertNull(denied.code)
        assertEquals("step_up", VersolaError.StepUp(listOf("c2"), null).toMessage().sdkCode)
        assertEquals("configuration.invalid_configuration", IllegalStateException("x").toErrorMessage().sdkCode)
    }

    @Test
    fun edgeClientUnknownCrossesAsTheUnknownDetailNamedWithItsStableCode() {
        val m = VersolaError.Configuration(EdgeClientUnknown("mobile-app")).toMessage()
        assertEquals(VersolaErrorCategoryMessage.CONFIGURATION, m.category)
        // No Dart enum value exists for it: `unknown`, never a guessed real case.
        assertEquals("unknown", m.kind)
        assertEquals("edge_client_unknown", m.detail)
        assertEquals("configuration.edge_client_unknown", m.sdkCode)
    }

    @Test
    fun accountMismatchIsItsOwnRecoverableCauseWithItsStableCode() {
        val m = VersolaError.Recoverable(Cause.AccountMismatch).toMessage()
        assertEquals(VersolaErrorCategoryMessage.RECOVERABLE, m.category)
        assertEquals("accountMismatch", m.kind)
        assertEquals("recoverable.account_mismatch", m.sdkCode)
    }

    @Test
    fun everyRecoverableCauseKeepsItsCategoryAndPayload() {
        val network = VersolaError.Recoverable(Cause.Network(detail = "timeout", attempts = 3, elapsedMillis = 1200)).toMessage()
        assertEquals("network", network.kind)
        assertEquals("timeout", network.detail)
        assertEquals(3L, network.attempts)
        assertEquals(1200L, network.elapsedMillis)

        val server = VersolaError.Recoverable(Cause.Server(status = 429, retryAfterMillis = 30_000, attempts = 1, elapsedMillis = 40)).toMessage()
        assertEquals("server", server.kind)
        assertEquals(429L, server.status)
        assertEquals(30_000L, server.retryAfterMillis)

        // No Retry-After is no field, not a zero: an app that waits zero is hammering.
        assertNull(VersolaError.Recoverable(Cause.Server(status = 500)).toMessage().retryAfterMillis)

        val loop = VersolaError.Recoverable(Cause.NonceLoop("https://id.example.com")).toMessage()
        assertEquals("nonceLoop", loop.kind)
        assertEquals("https://id.example.com", loop.origin)
        assertEquals("userCancelled", VersolaError.Recoverable(Cause.UserCancelled).toMessage().kind)
        assertEquals("systemCancelled", VersolaError.Recoverable(Cause.SystemCancelled).toMessage().kind)
        assertEquals("pendingRequestExpired", VersolaError.Recoverable(Cause.PendingRequestExpired).toMessage().kind)
        assertEquals("unlockRequired", VersolaError.Recoverable(Cause.UnlockRequired).toMessage().kind)
    }

    @Test
    fun reauthenticateCarriesTheInteractionCode() {
        val m = VersolaError.Reauthenticate(Reason.InteractionRequired("login_required")).toMessage()
        assertEquals(VersolaErrorCategoryMessage.REAUTHENTICATE, m.category)
        assertEquals("interactionRequired", m.kind)
        assertEquals("login_required", m.code)
        assertNull(VersolaError.Reauthenticate(Reason.SessionExpired).toMessage().code)
    }

    @Test
    fun stepUpIsItsOwnCategoryWithTheChallenge() {
        val m = VersolaError.StepUp(listOf("sensitive"), 300).toMessage()
        assertEquals(VersolaErrorCategoryMessage.STEP_UP, m.category)
        assertEquals(listOf("sensitive"), m.acrValues)
        assertEquals(300L, m.maxAge)
    }

    @Test
    fun configurationDetailsKeepTheirFields() {
        val idToken = VersolaError.Configuration(Detail.IdTokenRejected(IdTokenRejection.AccessTokenHash)).toMessage()
        assertEquals("idTokenRejected", idToken.kind)
        assertEquals("accessTokenHash", idToken.idTokenRejection)

        val issuer = VersolaError.Configuration(Detail.IssuerMismatch("https://a.example.com", "https://b.example.com")).toMessage()
        assertEquals("issuerMismatch", issuer.kind)
        assertEquals("https://a.example.com", issuer.expected)
        assertEquals("https://b.example.com", issuer.received)

        val hardware = VersolaError.Configuration(Detail.HardwareBindingUnavailable("software key")).toMessage()
        assertEquals("hardwareBindingUnavailable", hardware.kind)
        assertEquals("software key", hardware.detail)
    }

    @Test
    fun anExceptionThatIsNotAnSdkErrorCrossesAsAConfigurationNamingOnlyItsClass() {
        val m = IllegalStateException("refresh_token=do-not-leak").toErrorMessage()
        assertEquals(VersolaErrorCategoryMessage.CONFIGURATION, m.category)
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
        assertEquals(VersolaSessionStateMessage.values().toList(), states.map { it.toMessage() })
    }

    // MARK: Configuration and options

    private fun configurationMessage(issuer: String? = null) = VersolaConfigurationMessage(
        edgeUrl = "https://id.example.com",
        clientId = "app",
        redirectUri = "https://app.example.com/oauth",
        issuer = issuer,
        postLogoutRedirectUri = "https://app.example.com/signed-out",
        requireHardwareKey = true,
        unlockPolicy = VersolaUnlockPolicyMessage.ON_APP_UNLOCK,
        clockSkewToleranceSeconds = 30,
    )

    @Test
    fun theConfigurationMessageBuildsTheSdkConfiguration() {
        val c = configurationMessage().toConfiguration()
        assertEquals("https://id.example.com", c.edgeUrl)
        assertEquals("app", c.clientId)
        assertEquals("https://app.example.com/oauth", c.redirectUri)
        assertEquals("https://app.example.com/signed-out", c.postLogoutRedirectUri)
        assertTrue(c.requireHardwareKey)
        assertEquals(UnlockPolicy.OnAppUnlock, c.unlockPolicy)
        assertEquals(30L, c.clockSkewTolerance.inWholeSeconds)
    }

    @Test
    fun withoutAnIssuerTheSdkDefaultsItToTheEdgeAndAGivenOneIsKeptAsWritten() {
        assertEquals("https://id.example.com", configurationMessage(issuer = null).toConfiguration().issuer)
        assertEquals("https://id.example.com/", configurationMessage(issuer = "https://id.example.com/").toConfiguration().issuer)
    }

    @Test
    fun aConfigurationTheSdkRefusesIsRefusedBySdkAndNotRepairedHere() {
        val bad = configurationMessage().copy(redirectUri = "myapp://callback")
        try {
            bad.toConfiguration()
            fail("a private-use scheme must be refused")
        } catch (e: VersolaError.Configuration) {
            assertTrue(e.detail is Detail.InvalidConfiguration)
        }
        val loose = configurationMessage().copy(edgeUrl = "https://id.example.com/path")
        try {
            loose.toConfiguration()
            fail("an edge URL with a path must be refused")
        } catch (e: VersolaError.Configuration) {
            assertTrue(e.detail is Detail.InvalidConfiguration)
        }
    }

    @Test
    fun theRetryPolicyCrossesWholeAndAbsentMeansTheSdkDefault() {
        val withPolicy = configurationMessage().copy(
            retryPolicy = VersolaRetryPolicyMessage(
                maxAttemptsPerOrigin = 2, maxTotalAttempts = 3, initialBackoffMillis = 250,
                backoffMultiplier = 1.5, maxBackoffMillis = 4000, totalBudgetMillis = 10_000,
            ),
        ).toConfiguration().retryPolicy
        assertEquals(2, withPolicy.maxAttemptsPerOrigin)
        assertEquals(3, withPolicy.maxTotalAttempts)
        assertEquals(250L, withPolicy.initialBackoff.inWholeMilliseconds)
        assertEquals(1.5, withPolicy.backoffMultiplier, 0.0)
        assertEquals(10_000L, withPolicy.totalBudget.inWholeMilliseconds)
        assertEquals(versola.oauth.core.RetryPolicy.Default, configurationMessage().toConfiguration().retryPolicy)
    }

    @Test
    fun everyLoginOptionReachesTheSdkOptionsUntouched() {
        val claims = """{"id_token":{"email":{"essential":true}}}"""
        val details = """[{"type":"payment"}]"""
        val o = VersolaLoginOptionsMessage(
            scopes = listOf("profile", "email"),
            acrValues = listOf("sensitive"),
            maxAge = 300,
            prompt = VersolaPromptMessage.SELECT_ACCOUNT,
            loginHint = "alice@example.com",
            uiLocales = listOf("de", "en"),
            resources = listOf("https://api.example.com"),
            claims = claims,
            authorizationDetails = details,
            ephemeralBrowser = true,
        ).toLoginOptions()
        assertEquals(setOf("profile", "email"), o.scopes)
        assertEquals(listOf("sensitive"), o.acrValues)
        assertEquals(300L, o.maxAge)
        assertEquals(AuthorizationParameters.Prompt.SelectAccount, o.prompt)
        assertEquals("alice@example.com", o.loginHint)
        assertEquals(listOf("de", "en"), o.uiLocales)
        assertEquals(listOf("https://api.example.com"), o.resources)
        assertEquals(claims, o.claims)
        assertEquals(details, o.authorizationDetails)
        assertTrue(o.ephemeralBrowser)
    }

    private fun optionsMessage(prompt: VersolaPromptMessage? = null) = VersolaLoginOptionsMessage(
        scopes = emptyList(), acrValues = emptyList(), prompt = prompt, uiLocales = emptyList(),
        resources = emptyList(), ephemeralBrowser = false,
    )

    @Test
    fun everyPromptMapsToItsOwnCase() {
        val expected = mapOf(
            VersolaPromptMessage.NONE to AuthorizationParameters.Prompt.None,
            VersolaPromptMessage.LOGIN to AuthorizationParameters.Prompt.Login,
            VersolaPromptMessage.CONSENT to AuthorizationParameters.Prompt.Consent,
            VersolaPromptMessage.SELECT_ACCOUNT to AuthorizationParameters.Prompt.SelectAccount,
            VersolaPromptMessage.CREATE to AuthorizationParameters.Prompt.Create,
        )
        assertEquals(VersolaPromptMessage.values().toSet(), expected.keys)
        expected.forEach { (message, prompt) ->
            assertEquals(prompt, optionsMessage(prompt = message).toLoginOptions().prompt)
        }
        assertNull(optionsMessage().toLoginOptions().prompt)
    }

    // MARK: HTTP

    private fun request(
        method: String = "GET",
        url: String = "https://id.example.com/resources/items?page=2",
        headers: List<Pair<String, String>> = emptyList(),
        body: ByteArray? = null,
    ) = VersolaHttpRequestMessage(method, url, headers.map { VersolaHttpHeaderMessage(it.first, it.second) }, body)

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
        assertEquals("https://id.example.com/resources/items?page=2", sent.url.toString())
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
        // Replacing it on the edge is the SDK client's rule; on any other origin the app's header
        // must reach the wire as written, so the glue neither adds nor drops one.
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
        listOf("/items", "ftp://id.example.com/x", "ws://id.example.com/x", "not a url").forEach { url ->
            val error = refused { request(url = url).toRequest() }
            assertTrue(error.detail is Detail.InvalidConfiguration)
            assertFalse(error.toString().contains(url))
        }
    }

    @Test
    fun aMalformedHeaderIsRefusedWithAFixedTextThatDoesNotQuoteItsValue() {
        val secret = "Bearer s3cr3té"
        listOf("Authorization" to secret, "Bad Name" to "x", "X-Line" to "a\nb").forEach { header ->
            val error = refused { request(headers = listOf(header)).toRequest() }
            assertTrue(error.detail is Detail.InvalidConfiguration)
            assertFalse(error.toString().contains("s3cr3t"))
        }
    }

    @Test
    fun aResponseKeepsStatusReasonBytesAndEveryHeaderValueInOrder() {
        val response = Response.Builder()
            .request(Request.Builder().url("https://id.example.com/").build())
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
                .request(Request.Builder().url("https://id.example.com/").build())
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
