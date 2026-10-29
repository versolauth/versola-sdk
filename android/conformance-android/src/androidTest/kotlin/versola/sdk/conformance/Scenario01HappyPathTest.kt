package versola.sdk.conformance

import android.app.Application
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import versola.sdk.Versola
import versola.oauth.core.SessionState
import versola.oauth.core.VersolaError
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.FormBody
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Scenarios 01, 02 (its direct-flow half), 11 and 18 against the staged stack: discovery,
 * authorize, exchange, an authenticated call through edge, a refresh renewed in place, and
 * logout — each step asserted from the transcript of what the SDK actually sent, not from
 * the call having succeeded.
 *
 * The browser leg is [HttpLoginBrowser]; everything else is `Versola.configure()` as an app
 * would call it.
 */
@RunWith(AndroidJUnit4::class)
class Scenario01HappyPathTest {

    private val stack = Stack.fromArguments()
    private val application = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext as Application
    private val transcript = Transcript()
    private val http = OkHttpClient.Builder()
        .addNetworkInterceptor(transcript)
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()
    private lateinit var upstream: MockWebServer

    @Before
    fun startUpstream() {
        upstream = MockWebServer()
        upstream.start(stack.upstreamPort)
        // Every scenario ends in logout(), which is what leaves the shared credential store
        // empty for the next one; the files are not deleted underneath a live DataStore.
    }

    @After
    fun stopUpstream() {
        upstream.close()
    }

    @Test
    fun discoveryAuthorizeExchangeCallRefreshAndLogoutAgainstTheStagedStack() = runBlocking {
        val central = CentralClient(stack, http)
        val fixture = central.provisionStandardFixture(
            redirectUri = "https://conformance.versola.test/oauth",
            upstream = stack.upstreamUrlFromEdge,
        )
        val browser = HttpLoginBrowser(http, fixture.login, fixture.password)
        val versola = Versola.configure(
            context = application,
            issuer = stack.authUrl,
            clientId = fixture.clientId,
            redirectUri = fixture.redirectUri,
            httpClient = http,
            edgeBaseUrl = stack.edgeUrl,
            browser = browser,
        )
        // Whatever a previous scenario left behind in the shared store ends here, through the
        // SDK rather than by deleting files under a live DataStore.
        if (versola.sessionState.first() != SessionState.Unauthenticated) versola.logout()
        val states = mutableListOf<SessionState>()
        val collecting = async(Dispatchers.IO, start = CoroutineStart.UNDISPATCHED) {
            versola.sessionState.collect { if (states.lastOrNull() != it) states += it }
        }

        // ---- 01: login ------------------------------------------------------------------
        versola.login(setOf("openid", "profile"))

        // Fetched once per install and cached on disk across scenarios, so the wire entry is
        // asserted when this scenario is the one that fetched it; the document itself comes
        // from the SDK either way.
        transcript.matching("GET", "/.well-known/openid-configuration").firstOrNull()?.let { discovery ->
            assertEquals(200, discovery.status)
            for (field in listOf("authorization_endpoint", "token_endpoint", "dpop_signing_alg_values_supported")) {
                assertNotNull("discovery lacks $field", discovery.responseJson!![field])
            }
        }
        val metadata = versola.metadata()
        assertTrue(metadata.supportsDpop)

        val authorizeUri = browser.opened.first()
        val query = authorizeUri.toHttpUrl()
        assertEquals("code", query.queryParameter("response_type"))
        assertEquals("S256", query.queryParameter("code_challenge_method"))
        assertEquals(fixture.redirectUri, query.queryParameter("redirect_uri"))
        assertEquals(fixture.clientId, query.queryParameter("client_id"))
        val state = query.queryParameter("state")!!
        val nonce = query.queryParameter("nonce")!!
        assertTrue("state must carry at least 128 bits", state.length >= 22)
        assertTrue("nonce must carry at least 128 bits", nonce.length >= 22)
        assertNotEquals(state, nonce)
        assertTrue(query.queryParameter("scope")!!.split(' ').containsAll(listOf("openid", "profile", "offline_access")))
        val jkt = query.queryParameter("dpop_jkt")!!

        val exchange = transcript.matching("POST", "/token").single()
        assertEquals(200, exchange.status)
        val form = exchange.form
        assertEquals("authorization_code", form["grant_type"])
        assertEquals(fixture.clientId, form["client_id"])
        assertFalse("a public client has no secret to send", form.containsKey("client_secret"))
        // The PKCE binding, end to end: the challenge the browser carried is the digest of the
        // verifier the exchange presented.
        assertEquals(query.queryParameter("code_challenge"), Transcript.base64UrlSha256(form["code_verifier"]!!))
        assertEquals(1, exchange.headerCount("DPoP"))
        assertNull(exchange.header("Idempotency-Key"))
        val exchangeProof = exchange.proofClaims!!
        assertEquals("POST", exchangeProof["htm"]!!.jsonPrimitive.content)
        assertEquals(metadata.tokenEndpoint, exchangeProof["htu"]!!.jsonPrimitive.content)
        assertNull("no ath at the token endpoint", exchangeProof["ath"])
        assertNotNull(exchangeProof["jti"])
        assertEquals("dpop+jwt", exchange.proofHeader!!["typ"]!!.jsonPrimitive.content)
        val issued = exchange.responseJson!!
        assertEquals("DPoP", issued["token_type"]!!.jsonPrimitive.content)
        val accessToken = issued["access_token"]!!.jsonPrimitive.content
        val refreshToken = issued["refresh_token"]!!.jsonPrimitive.content
        assertNotNull(issued["id_token"])
        // Bound at the authorization request to the key that redeemed it (RFC 9449 §10).
        assertEquals(jkt, Transcript.decodeJwtPart(accessToken, 1)!!["cnf"]!!.jsonObject["jkt"]!!.jsonPrimitive.content)

        // ---- 01: the authenticated call through edge --------------------------------------
        upstream.enqueue(MockResponse.Builder().code(200).setHeader("Content-Type", "application/json").body("""{"items":[]}""").build())
        val proxied = callUntilRoutable(versola, central, "${stack.edgeUrl}/resources/${fixture.resourceId}/items")
        assertEquals(200, proxied)
        val edgeCalls = transcript.matching("GET", "/resources/${fixture.resourceId}/items")
        val served = edgeCalls.last()
        assertEquals("DPoP $accessToken", served.header("Authorization"))
        val edgeProof = served.proofClaims!!
        assertEquals("GET", edgeProof["htm"]!!.jsonPrimitive.content)
        assertEquals(served.url.substringBefore('?'), edgeProof["htu"]!!.jsonPrimitive.content)
        assertEquals(Transcript.base64UrlSha256(accessToken), edgeProof["ath"]!!.jsonPrimitive.content)
        // Scenario 04: edge demanded a nonce once, the retry carried it, auth's exchange did not.
        val challenged = edgeCalls.firstOrNull { it.status == 401 }
        if (challenged != null) {
            val edgeNonce = challenged.responseHeader("DPoP-Nonce")!!
            assertEquals(edgeNonce, served.proofClaims!!["nonce"]!!.jsonPrimitive.content)
            assertNull(exchangeProof["nonce"])
        }
        assertEquals(1, upstream.requestCount)

        // ---- 02 / 11: refresh, renewed in place -------------------------------------------
        transcript.clear()
        versola.refresh()
        val refresh = transcript.matching("POST", "/token").single()
        assertEquals("refresh_token", refresh.form["grant_type"])
        assertEquals(refreshToken, refresh.form["refresh_token"])
        assertNotNull("every refresh carries an idempotency key", refresh.header("Idempotency-Key"))
        assertEquals(1, refresh.headerCount("DPoP"))
        val renewed = refresh.responseJson!!
        assertEquals("DPoP", renewed["token_type"]!!.jsonPrimitive.content)
        assertEquals("a bound refresh token is renewed, not rotated", refreshToken, renewed["refresh_token"]!!.jsonPrimitive.content)
        assertNotEquals(accessToken, renewed["access_token"]!!.jsonPrimitive.content)

        // ---- session states so far ----------------------------------------------------------
        withContext(Dispatchers.IO) { Thread.sleep(200) }
        assertEquals(
            listOf(SessionState.Unauthenticated, SessionState.Authorizing, SessionState.Authenticated, SessionState.Refreshing, SessionState.Authenticated),
            states.toList(),
        )

        // ---- 18: logout -----------------------------------------------------------------------
        // A proof minted now, by the key the grant is bound to, for the replay below: logout
        // destroys the key, and a replay signed by a new one would be refused for the key
        // rather than for the revocation this is meant to prove. Unused, so not a jti replay.
        val tokenEndpoint = metadata.tokenEndpoint
        val replayProof = versola.dpop!!.proof("POST", tokenEndpoint)
        transcript.clear()
        versola.logout()
        val revoke = transcript.matching("POST", "/revoke").single()
        assertEquals(200, revoke.status)
        assertEquals(refreshToken, revoke.form["token"])
        assertEquals(fixture.clientId, revoke.form["client_id"])
        assertNull(revoke.header("DPoP"))
        val endSession = browser.opened.last()
        assertTrue(endSession.startsWith(metadata.endSessionEndpoint!!))
        // The hint is the *last* ID token held: the refresh renewed it (auth issues one on every
        // grant with `openid`), and the stored copy followed, so the hint is as fresh as the session.
        assertNotNull(renewed["id_token"])
        assertEquals(renewed["id_token"]!!.jsonPrimitive.content, endSession.toHttpUrl().queryParameter("id_token_hint"))
        assertNotNull(endSession.toHttpUrl().queryParameter("state"))
        // The current value, not the collector's view: the collector runs on another
        // dispatcher and may not have seen the last transition yet.
        assertEquals(SessionState.Unauthenticated, versola.sessionState.first())
        assertFalse(application.noBackupFilesDir.resolve("versola/pending-authorization").exists())

        // The grant is dead at the server: replaying the refresh token is invalid_grant.
        val replay = http.newCall(
            Request.Builder().url(tokenEndpoint)
                .header("DPoP", replayProof)
                .post(FormBody.Builder().add("grant_type", "refresh_token").add("refresh_token", refreshToken).add("client_id", fixture.clientId).build())
                .build(),
        ).execute().use { it.code to it.body.string() }
        assertEquals(400, replay.first)
        assertTrue(replay.second, replay.second.contains("invalid_grant"))

        // And a new login starts over with a different key.
        transcript.clear()
        versola.login(setOf("openid"))
        val secondJkt = browser.opened.last().toHttpUrl().queryParameter("dpop_jkt")
        assertNotEquals("the DPoP key is destroyed on logout", jkt, secondJkt)
        versola.logout()

        collecting.cancelAndJoin()
    }

    /**
     * Edge's resource and permission caches lag central by one notification, so the first
     * calls may answer 404 (no resource yet) or 403 (no permission yet). Each attempt re-syncs
     * and retries, the way `EdgeFixture.awaitProxy` does; anything else is the answer.
     */
    private suspend fun callUntilRoutable(versola: Versola, central: CentralClient, url: String): Int {
        repeat(30) {
            val code = try {
                versola.call(Request.Builder().url(url).get().build()).use { it.code }
            } catch (e: VersolaError) {
                throw AssertionError("the authenticated call failed: $e", e)
            }
            if (code != 404 && code != 403) return code
            central.syncConfiguration()
            withContext(Dispatchers.IO) { Thread.sleep(1000) }
        }
        error("edge never routed $url")
    }
}
