package versola.sdk

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import okhttp3.Request
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import versola.oauth.core.AuthorizationParameters
import versola.oauth.core.IdTokenRejection
import versola.oauth.core.SessionState
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaInternalApi
import versola.oauth.core.VersolaLogger
import versola.sdk.dpop.KeyAttestation

private val counter = AtomicInteger()

private class CollectingLogger : VersolaLogger {
    val lines = CopyOnWriteArrayList<String>()
    override fun info(message: String) {
        lines += message
    }

    override fun warn(message: String) {
        lines += message
    }
}

/**
 * The `Versola` facade against an edge played by a socket server (`spec/versola-sdk-api.md`
 * sections 5 to 12), with a scripted browser and a JVM stand-in for the Keystore.
 *
 * What this proves is the rule, against stubs: the edge here holds no keys and verifies no proof,
 * and its ID token carries a dummy signature (the SDK is not asked to verify one). What the real
 * Keystore tiers, `AuthTabAuthorizationSession`, a server that checks the proofs and the cells
 * would add is the device and conformance tiers' (scenario 21 in `:conformance-android`). The
 * key's attestation is `Software` here, read back from a stand-in provider that has no `KeyInfo`.
 */
@OptIn(VersolaInternalApi::class)
@RunWith(RobolectricTestRunner::class)
class VersolaTest {

    private val application = ApplicationProvider.getApplicationContext<Application>()
    private val clientId = "client-${counter.incrementAndGet()}"
    private val edge = FakeEdge(clientId)
    private val browser = ScriptedBrowser(edge)
    private val logger = CollectingLogger()
    private val realKeystore: java.security.Provider? = java.security.Security.getProvider("AndroidKeyStore")
    private val scopes = CoroutineScope(Dispatchers.Default)

    @Before
    fun start() {
        Versola.forgetAll()
        java.security.Security.removeProvider("AndroidKeyStore")
        java.security.Security.insertProviderAt(SharedNamespaceAndroidKeyStore(), 1)
    }

    @After
    fun stop() {
        java.security.Security.removeProvider("AndroidKeyStore")
        realKeystore?.let { java.security.Security.insertProviderAt(it, 1) }
        Versola.forgetAll()
        scopes.cancel()
        edge.close()
    }

    private fun configuration() = VersolaConfiguration(
        edgeUrl = edge.url,
        clientId = clientId,
        redirectUri = REDIRECT_URI,
        postLogoutRedirectUri = POST_LOGOUT_REDIRECT_URI,
        logger = logger,
    )

    private fun versola(configuration: VersolaConfiguration = configuration()): Versola =
        Versola.create(application, configuration, browser, ReversingKeyProvider)

    private fun <T> bounded(block: suspend () -> T): T = runBlocking { withTimeout(30_000) { block() } }

    private suspend fun failure(block: suspend () -> Unit): VersolaError {
        try {
            block()
        } catch (e: VersolaError) {
            return e
        }
        fail("expected a VersolaError")
        throw AssertionError()
    }

    private fun configurationDetail(error: VersolaError): VersolaError.Configuration.Detail {
        assertTrue("expected Configuration, was $error", error is VersolaError.Configuration)
        return (error as VersolaError.Configuration).detail
    }

    private fun recoverableReason(error: VersolaError): VersolaError.Recoverable.Cause {
        assertTrue("expected Recoverable, was $error", error is VersolaError.Recoverable)
        return (error as VersolaError.Recoverable).reason
    }

    // --- login ---

    @Test
    fun `login starts at edge with the options given and nothing that is edge's, and opens the endpoint edge answered`() = bounded {
        val versola = versola()
        val options = LoginOptions(
            scopes = setOf("profile"),
            acrValues = listOf(Acr.Sensitive),
            maxAge = 300,
            prompt = AuthorizationParameters.Prompt.Login,
            loginHint = "alice@example.com",
            uiLocales = listOf("de", "en"),
            resources = listOf("https://api.example.com/a", "https://api.example.com/b"),
            claims = """{"id_token":{"email":null}}""",
            authorizationDetails = """[{"type":"payment"}]""",
        )

        versola.login(options)

        val start = edge.requestsTo("/native/start/").single()
        assertEquals("POST", start.method)
        assertEquals("/native/start/$clientId", start.path)
        assertEquals(REDIRECT_URI, start.field("redirect_uri"))
        val scope = start.field("scope")!!.split(' ').toSet()
        assertTrue("scope was $scope", scope.containsAll(listOf("openid", "offline_access", "profile")))
        val nonce = start.field("nonce")!!
        assertTrue("a nonce is at least 128 bits (22 base64url characters), was ${nonce.length}", nonce.length >= 22)
        assertEquals("sensitive", start.field("acr_values"))
        assertEquals("300", start.field("max_age"))
        assertEquals("login", start.field("prompt"))
        assertEquals("alice@example.com", start.field("login_hint"))
        assertEquals("de en", start.field("ui_locales"))
        assertEquals(listOf("https://api.example.com/a", "https://api.example.com/b"), start.form["resource"])
        assertEquals("""{"id_token":{"email":null}}""", start.field("claims"))
        assertEquals("""[{"type":"payment"}]""", start.field("authorization_details"))
        for (edges in listOf("client_id", "state", "response_type", "code_challenge", "code_challenge_method", "dpop_jkt")) {
            assertFalse("$edges is edge's, not the device's", start.form.containsKey(edges))
        }
        assertEquals(1, start.headerCount("DPoP"))
        assertEquals("POST", start.proofClaims!!["htm"])
        assertEquals("${edge.url}/native/start/$clientId", start.proofClaims!!["htu"])

        val opened = browser.opened.single()
        assertEquals(edge.authorizationEndpoint, opened.substringBefore('?'))
        assertEquals(setOf("client_id", "request_uri"), queryOf(opened).keys)
        assertEquals(clientId, queryOf(opened)["client_id"])
        assertEquals(edge.starts.single().requestUri, queryOf(opened)["request_uri"])

        assertEquals(
            "the SDK asked for no discovery document and no key set",
            emptyList<String>(),
            edge.requests.map { it.path }.filter { it.contains("/.well-known/") || it.contains("jwks") },
        )
        assertEquals(
            "auth's mutual-TLS addresses are signed for and never dialled",
            emptyList<String>(),
            edge.requestsTo("/auth-mtls").map { it.path },
        )
    }

    @Test
    fun `login redeems the code at edge with state, iss and the blob, and the claims come from the ID token`() = bounded {
        val versola = versola()
        assertNull(versola.claims)

        versola.login()

        val started = edge.starts.single()
        val complete = edge.requestsTo("/native/complete/").single()
        assertEquals("the-code", complete.field("code"))
        assertEquals(started.state, complete.field("state"))
        assertEquals(edge.url, complete.field("iss"))
        assertEquals(started.blob, complete.field("blob"))
        assertFalse("the verifier is sealed in the blob and never on the device", complete.form.containsKey("code_verifier"))
        assertEquals(1, complete.headerCount("DPoP"))
        assertEquals("proof signed for the token_endpoint of start, not for edge", edge.tokenEndpoint, complete.proofClaims!!["htu"])
        assertNull(complete.proofClaims!!["ath"])

        assertEquals(SessionState.Authenticated, versola.currentSessionState())
        val claims = versola.claims!!
        assertEquals("alice", claims.subject)
        assertEquals(edge.url, claims.issuer)
        assertEquals(listOf(clientId), claims.audience)
    }

    @Test
    fun `the nonce the ID token must carry is the one sent to start`() = bounded {
        val versola = versola()

        versola.login()

        // The edge echoes the nonce it was sent into the ID token; a login that succeeded
        // therefore compared that very value.
        val sent = edge.requestsTo("/native/start/").single().field("nonce")!!
        assertEquals(sent, jwtClaims(edge.issued.single().idToken)["nonce"])
    }

    @Test
    fun `the session goes Unauthenticated, Authorizing, Authenticated and no other state`() = bounded {
        val versola = versola()
        val states = CopyOnWriteArrayList<SessionState>()
        scopes.launch { versola.sessionState.collect { if (states.lastOrNull() != it) states += it } }
        browser.gate = CompletableDeferred()

        val login = scopes.async { versola.login() }
        awaitState(states, SessionState.Authorizing)
        browser.gate!!.complete(Unit)
        login.await()
        awaitState(states, SessionState.Authenticated)

        assertEquals(listOf(SessionState.Unauthenticated, SessionState.Authorizing, SessionState.Authenticated), states.toList())
    }

    private suspend fun awaitState(states: List<SessionState>, wanted: SessionState) {
        // A bounded wait for the collector, which runs on another dispatcher, to catch up.
        withTimeout(10_000) { while (states.lastOrNull() != wanted) yield() }
    }

    // --- the redirect, before any network call ---

    @Test
    fun `a redirect whose iss is not the configured issuer fails with IssuerMismatch and no complete request is sent`() = bounded {
        val versola = versola()
        browser.iss = "https://evil.example.com"

        val error = failure { versola.login() }

        val detail = configurationDetail(error) as VersolaError.Configuration.Detail.IssuerMismatch
        assertEquals(edge.url, detail.expected)
        assertEquals("https://evil.example.com", detail.received)
        assertEquals(emptyList<String>(), edge.requestsTo("/native/complete").map { it.path })
        assertEquals(SessionState.Unauthenticated, versola.currentSessionState())
        assertNull(versola.claims)
    }

    @Test
    fun `a redirect without iss fails with IssuerMismatch and no complete request is sent`() = bounded {
        val versola = versola()
        browser.iss = null

        val error = failure { versola.login() }

        val detail = configurationDetail(error) as VersolaError.Configuration.Detail.IssuerMismatch
        assertEquals(edge.url, detail.expected)
        assertNull(detail.received)
        assertEquals(emptyList<String>(), edge.requestsTo("/native/complete").map { it.path })
        assertEquals(SessionState.Unauthenticated, versola.currentSessionState())
    }

    // spec/versola-sdk-api.md section 3: the issuer is compared "by simple string comparison, no
    // normalisation", a trailing slash included, and "an explicit issuer is kept byte for byte". A
    // deployment that writes its issuer with a slash must therefore sign in when the redirect's iss
    // and the ID token's iss carry it. Added as a finding: see the report (core strips the slash).
    @Test
    fun `an issuer configured with a trailing slash signs in when the redirect and the ID token carry that slash`() = bounded {
        val issuer = edge.url + "/"
        val versola = versola(
            VersolaConfiguration(
                edgeUrl = edge.url,
                clientId = clientId,
                redirectUri = REDIRECT_URI,
                issuer = issuer,
                postLogoutRedirectUri = POST_LOGOUT_REDIRECT_URI,
                logger = logger,
            ),
        )
        browser.iss = issuer
        edge.tokenIssuer = issuer

        versola.login()

        assertEquals(SessionState.Authenticated, versola.currentSessionState())
        assertEquals(issuer, edge.requestsTo("/native/complete/").single().field("iss"))
        assertEquals(issuer, versola.claims!!.issuer)
    }

    @Test
    fun `a redirect whose iss differs only by a trailing slash is refused, the comparison being byte for byte`() = bounded {
        val versola = versola()
        browser.iss = edge.url + "/"

        val error = failure { versola.login() }

        assertTrue(configurationDetail(error) is VersolaError.Configuration.Detail.IssuerMismatch)
        assertEquals(emptyList<String>(), edge.requestsTo("/native/complete").map { it.path })
    }

    // --- the ID token ---

    private fun assertIdTokenRejected(reason: IdTokenRejection, overrides: Map<String, Any?>) = bounded {
        val versola = versola()
        edge.claimOverrides = overrides

        val error = failure { versola.login() }

        val detail = configurationDetail(error) as VersolaError.Configuration.Detail.IdTokenRejected
        assertEquals(reason, detail.reason)
        assertEquals(SessionState.Unauthenticated, versola.currentSessionState())
        assertNull(versola.claims)
        // Nothing was stored: a fresh instance over the same storage restores no session.
        Versola.forgetAll()
        assertEquals(SessionState.Unauthenticated, versola(configuration()).currentSessionState())
    }

    @Test
    fun `an ID token with another nonce fails login with IdTokenRejected(Nonce) and stores nothing`() =
        assertIdTokenRejected(IdTokenRejection.Nonce, mapOf("nonce" to "not-the-nonce-that-was-sent"))

    @Test
    fun `an ID token without a nonce fails login with IdTokenRejected(Nonce) and stores nothing`() =
        assertIdTokenRejected(IdTokenRejection.Nonce, mapOf("nonce" to null))

    @Test
    fun `an ID token for another audience fails login with IdTokenRejected(Audience) and stores nothing`() =
        assertIdTokenRejected(IdTokenRejection.Audience, mapOf("aud" to "another-client"))

    @Test
    fun `an ID token from another issuer fails login with IdTokenRejected(Issuer) and stores nothing`() =
        assertIdTokenRejected(IdTokenRejection.Issuer, mapOf("iss" to "https://evil.example.com"))

    @Test
    fun `an expired ID token fails login with IdTokenRejected(Expired) and stores nothing`() =
        assertIdTokenRejected(IdTokenRejection.Expired, mapOf("exp" to FakeEdge.now() - 3600, "iat" to FakeEdge.now() - 7200))

    @Test
    fun `an ID token that is not a JWS fails login with IdTokenRejected(Malformed) and stores nothing`() =
        assertIdTokenRejected(IdTokenRejection.Malformed, mapOf("sub" to null))

    // --- what start may answer ---

    private fun assertStartMalformed(overrides: Map<String, Any?>) = bounded {
        val versola = versola()
        edge.startOverrides = overrides

        val error = failure { versola.login() }

        assertTrue(
            "expected TokenResponseMalformed, was ${configurationDetail(error)}",
            configurationDetail(error) is VersolaError.Configuration.Detail.TokenResponseMalformed,
        )
        assertEquals("the browser is never opened", emptyList<String>(), browser.opened.toList())
        assertEquals(SessionState.Unauthenticated, versola.currentSessionState())
        assertEquals(1, edge.requestsTo("/native/start/").size)
    }

    @Test
    fun `a start answer without authorization_endpoint is Configuration(TokenResponseMalformed) and the browser stays closed`() =
        assertStartMalformed(mapOf("authorization_endpoint" to null))

    @Test
    fun `a start answer with expires_in 0 is Configuration(TokenResponseMalformed) and the browser stays closed`() =
        assertStartMalformed(mapOf("expires_in" to 0))

    @Test
    fun `a start answer whose token_endpoint is http on a host that is not loopback is Configuration(TokenResponseMalformed)`() =
        assertStartMalformed(mapOf("token_endpoint" to "http://auth.example.com/token"))

    @Test
    fun `a start answer whose authorization_endpoint is http on a host that is not loopback is Configuration(TokenResponseMalformed)`() =
        assertStartMalformed(mapOf("authorization_endpoint" to "http://id.example.com/authorize"))

    @Test
    fun `a start answer without a blob is Configuration(TokenResponseMalformed) and the browser stays closed`() =
        assertStartMalformed(mapOf("blob" to null))

    // --- stepUp ---

    @Test
    fun `stepUp with no session is Configuration(InvalidConfiguration) and opens no browser`() = bounded {
        val versola = versola()

        val error = failure { versola.stepUp(VersolaError.StepUp(listOf("sensitive"), 300)) }

        assertTrue(configurationDetail(error) is VersolaError.Configuration.Detail.InvalidConfiguration)
        assertEquals(emptyList<String>(), browser.opened.toList())
        assertEquals(emptyList<String>(), edge.requests.map { it.path })
    }

    @Test
    fun `stepUp sends the challenge's acr_values and max_age and the scope the first login was granted`() = bounded {
        val versola = versola()
        versola.login(LoginOptions(scopes = setOf("profile", "email")))

        versola.stepUp(VersolaError.StepUp(listOf("sensitive"), 60))

        val second = edge.requestsTo("/native/start/")[1]
        assertEquals("sensitive", second.field("acr_values"))
        assertEquals("60", second.field("max_age"))
        assertEquals(
            setOf("openid", "offline_access", "profile", "email"),
            second.field("scope")!!.split(' ').toSet(),
        )
        assertEquals(SessionState.Authenticated, versola.currentSessionState())
        assertEquals("alice", versola.claims!!.subject)
    }

    @Test
    fun `stepUp with options overrides the remembered scopes and still takes acr_values from the challenge`() = bounded {
        val versola = versola()
        versola.login(LoginOptions(scopes = setOf("profile")))

        versola.stepUp(VersolaError.StepUp(listOf("sensitive"), 60), LoginOptions(scopes = setOf("email"), acrValues = listOf("ignored")))

        val second = edge.requestsTo("/native/start/")[1]
        assertEquals(setOf("openid", "offline_access", "email"), second.field("scope")!!.split(' ').toSet())
        assertEquals("sensitive", second.field("acr_values"))
    }

    @Test
    fun `a stepUp that comes back as another user is AccountMismatch, keeps the session and revokes the refused token`() = bounded {
        val versola = versola()
        versola.login()
        val firstRefreshToken = edge.issued.single().refreshToken
        edge.subject = "mallory"
        edge.server.drain()

        val error = failure { versola.stepUp(VersolaError.StepUp(listOf("sensitive"), 60)) }

        assertEquals(VersolaError.Recoverable.Cause.AccountMismatch, recoverableReason(error))
        assertEquals("the session is the first user's", "alice", versola.claims!!.subject)
        assertEquals(SessionState.Authenticated, versola.currentSessionState())
        // Detached: awaited with a bound, not slept for.
        val revoke = edge.server.await { it.path == "/native/revoke/$clientId" }
        assertNotNull("the refused refresh token was not revoked", revoke)
        val refused = edge.issued.last().refreshToken
        assertEquals(refused, revoke!!.field("token"))
        assertTrue("it is the new grant's token, not the session's", refused != firstRefreshToken)
        assertEquals(edge.revocationEndpoint, revoke.proofClaims!!["htu"])
    }

    @Test
    fun `a stepUp that comes back as the same user succeeds and replaces the grant`() = bounded {
        val versola = versola()
        versola.login()

        versola.stepUp(VersolaError.StepUp(listOf("sensitive"), 60))

        assertEquals(2, edge.issued.size)
        assertEquals(SessionState.Authenticated, versola.currentSessionState())
        assertEquals("alice", versola.claims!!.subject)
        assertEquals("a successful step-up revokes nothing", emptyList<String>(), edge.requestsTo("/native/revoke").map { it.path })
    }

    // --- logout ---

    @Test
    fun `logout without endSession opens no browser, revokes at edge and ends Unauthenticated`() = bounded {
        val versola = versola()
        versola.login()
        val opened = browser.opened.size

        val outcome = versola.logout(LogoutOptions(endSession = false))

        assertEquals("no browser opened on sign-out", opened, browser.opened.size)
        val revoke = edge.requestsTo("/native/revoke/").single()
        assertEquals(edge.issued.single().refreshToken, revoke.field("token"))
        assertEquals("refresh_token", revoke.field("token_type_hint"))
        assertEquals(edge.revocationEndpoint, revoke.proofClaims!!["htu"])
        assertTrue(outcome.tokenRevoked)
        assertFalse(outcome.sessionEnded)
        assertEquals(SessionState.Unauthenticated, versola.currentSessionState())
        assertNull(versola.claims)
    }

    @Test
    fun `logout by default ends the session at the issuer's logout page with id_token_hint, client_id and state`() = bounded {
        val versola = versola()
        versola.login()

        val outcome = versola.logout()

        val endSession = browser.opened.last()
        assertEquals("${edge.url}/logout", endSession.substringBefore('?'))
        val query = queryOf(endSession)
        assertEquals(edge.issued.single().idToken, query["id_token_hint"])
        assertEquals(clientId, query["client_id"])
        assertTrue("state is present", !query["state"].isNullOrEmpty())
        assertEquals(POST_LOGOUT_REDIRECT_URI, query["post_logout_redirect_uri"])
        assertTrue(outcome.tokenRevoked)
        assertTrue(outcome.sessionEnded)
        assertEquals(SessionState.Unauthenticated, versola.currentSessionState())
        assertNull(versola.claims)
    }

    @Test
    fun `logout with no session still ends Unauthenticated and reports nothing revoked`() = bounded {
        val versola = versola()

        val outcome = versola.logout(LogoutOptions(endSession = false))

        assertFalse(outcome.tokenRevoked)
        assertEquals(emptyList<String>(), edge.requests.map { it.path })
        assertEquals(SessionState.Unauthenticated, versola.currentSessionState())
    }

    // --- the authenticated client ---

    @Test
    fun `httpClient attaches Authorization DPoP and a proof to a request to the edge origin`() = bounded {
        val versola = versola()
        versola.login()

        val code = withContext(Dispatchers.IO) {
            versola.httpClient().newCall(Request.Builder().url("${edge.url}/resources/items?page=2").get().build()).execute().use { it.code }
        }

        assertEquals(200, code)
        val served = edge.requestsTo("/resources/").single()
        assertEquals("DPoP ${edge.issued.single().accessToken}", served.header("Authorization"))
        assertEquals(1, served.headerCount("DPoP"))
        val proof = served.proofClaims!!
        assertEquals("GET", proof["htm"])
        assertEquals("${edge.url}/resources/items", proof["htu"])
        assertNotNull("ath binds the proof to the access token", proof["ath"])
    }

    @Test
    fun `httpClient attaches nothing to a request to another origin`() = bounded {
        val versola = versola()
        versola.login()

        FakeEdge("other").use { other ->
            val code = withContext(Dispatchers.IO) {
                versola.httpClient().newCall(Request.Builder().url("${other.url}/resources/items").get().build()).execute().use { it.code }
            }

            assertEquals(200, code)
            val served = other.requestsTo("/resources/").single()
            assertNull(served.header("Authorization"))
            assertNull(served.header("DPoP"))
        }
    }

    @Test
    fun `call raises the error taxonomy itself and attaches the same headers`() = bounded {
        val versola = versola()
        versola.login()

        val response = versola.call(Request.Builder().url("${edge.url}/resources/items").get().build())

        assertEquals(200, response.use { it.code })
        assertEquals("DPoP ${edge.issued.single().accessToken}", edge.requestsTo("/resources/").single().header("Authorization"))
    }

    @Test
    fun `an unauthenticated client has no token to attach and the call fails before it reaches edge`() = bounded {
        val versola = versola()

        val error = failure { versola.call(Request.Builder().url("${edge.url}/resources/items").get().build()).close() }

        assertTrue("was $error", error is VersolaError.Reauthenticate)
        assertEquals(emptyList<String>(), edge.requestsTo("/resources/").map { it.path })
    }

    // --- the key ---

    @Test
    fun `keyAttestation reads the tier back from the key, which here is Software because the stand-in has no KeyInfo`() = bounded {
        val versola = versola()

        // The tier is read back from the key (`KeystoreDpopKey.attestationOf`), never from what was
        // asked for. The JVM stand-in provider has no KeyFactory to read a security level from, so
        // Software is the honest answer; StrongBox and TEE are the device tier's (`:dpop` androidTest).
        assertEquals(KeyAttestation.Software, versola.keyAttestation())
        assertEquals("the key is generated once", KeyAttestation.Software, versola.keyAttestation())
    }

    // --- the pending request's lifetime ---

    @Test
    fun `a login whose start answered expires_in 60 ends with PendingRequestExpired when the browser never answers`() = runTest {
        val versola = versola()
        browser.hold = true

        val error = failure { versola.login() }

        assertEquals(VersolaError.Recoverable.Cause.PendingRequestExpired, recoverableReason(error))
        assertEquals(1, browser.opened.size)
        assertEquals(SessionState.Unauthenticated, versola.currentSessionState())
        assertEquals("no code is redeemed after the expiry", emptyList<String>(), edge.requestsTo("/native/complete").map { it.path })
    }
}
