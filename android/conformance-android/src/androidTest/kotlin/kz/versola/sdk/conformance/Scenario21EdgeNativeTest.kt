package kz.versola.sdk.conformance

import android.app.Application
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kz.versola.sdk.Versola
import kz.versola.sdk.core.BackChannel
import kz.versola.sdk.core.SessionState
import kz.versola.sdk.core.VersolaError
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
 * Scenario 21, with 22's blob-less replay and 18 through `/native/revoke`: the SDK on a
 * `fapi2` tenant, where it cannot be a public client of auth and goes through edge's native
 * endpoints instead. Asserted from the transcript, as in [Scenario01HappyPathTest].
 */
@RunWith(AndroidJUnit4::class)
class Scenario21EdgeNativeTest {

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
        application.noBackupFilesDir.resolve("versola").deleteRecursively()
    }

    @After
    fun stopUpstream() {
        upstream.close()
    }

    @Test
    fun loginRefreshCallAndLogoutThroughEdgeOnAFapi2Tenant() = runBlocking {
        val central = CentralClient(stack, http)
        val fixture = central.provisionNativeFixture(
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
            backChannel = BackChannel.Edge,
            browser = browser,
        )
        val states = mutableListOf<SessionState>()
        val collecting = async(Dispatchers.IO, start = CoroutineStart.UNDISPATCHED) {
            versola.sessionState.collect { if (states.lastOrNull() != it) states += it }
        }

        // ---- start → authorize → complete ----------------------------------------------------
        loginUntilFronted(versola, central, setOf("openid"))

        val document = transcript.matching("GET", "/.well-known/openid-configuration").single().responseJson!!
        val start = transcript.matching("POST", "/native/start/${fixture.clientId}").last { it.status == 200 }
        val startForm = start.form
        assertEquals(fixture.redirectUri, startForm["redirect_uri"])
        assertTrue(startForm["scope"]!!.split(' ').containsAll(listOf("openid", "offline_access")))
        assertNotNull(startForm["nonce"])
        for (theirs in listOf("code_challenge", "code_challenge_method", "state", "response_type", "dpop_jkt", "client_id")) {
            assertFalse("$theirs is edge's, not the device's", startForm.containsKey(theirs))
        }
        assertEquals(1, start.headerCount("DPoP"))
        val startProof = start.proofClaims!!
        assertEquals("POST", startProof["htm"]!!.jsonPrimitive.content)
        assertEquals(start.url, startProof["htu"]!!.jsonPrimitive.content)
        assertNull(startProof["ath"])
        val started = start.responseJson!!
        val deviceJkt = thumbprint(start.proofHeader!!["jwk"]!!.jsonObject)

        val authorizeUri = browser.opened.first().toHttpUrl()
        assertEquals(document["authorization_endpoint"]!!.jsonPrimitive.content, authorizeUri.toString().substringBefore('?'))
        assertEquals(setOf("client_id", "request_uri"), authorizeUri.queryParameterNames)
        assertEquals(fixture.clientId, authorizeUri.queryParameter("client_id"))
        assertEquals(started["request_uri"]!!.jsonPrimitive.content, authorizeUri.queryParameter("request_uri"))

        val complete = transcript.matching("POST", "/native/complete/${fixture.clientId}").single()
        assertEquals(200, complete.status)
        val completeForm = complete.form
        assertEquals(started["state"]!!.jsonPrimitive.content, completeForm["state"])
        assertEquals(started["blob"]!!.jsonPrimitive.content, completeForm["blob"])
        assertEquals(stack.authUrl, completeForm["iss"]!!.trimEnd('/'))
        assertNotNull(completeForm["code"])
        assertFalse("the verifier is sealed in the blob and never on the device", completeForm.containsKey("code_verifier"))
        val completeProof = complete.proofClaims!!
        assertEquals(started["token_endpoint"]!!.jsonPrimitive.content, completeProof["htu"]!!.jsonPrimitive.content)
        assertNotEquals("signed for auth's listener, not for edge", complete.url, completeProof["htu"]!!.jsonPrimitive.content)
        assertNull(completeProof["ath"])
        val issued = complete.responseJson!!
        assertEquals("DPoP", issued["token_type"]!!.jsonPrimitive.content)
        val accessToken = issued["access_token"]!!.jsonPrimitive.content
        val refreshToken = issued["refresh_token"]!!.jsonPrimitive.content
        val cnf = Transcript.decodeJwtPart(accessToken, 1)!!["cnf"]!!.jsonObject
        assertEquals(deviceJkt, cnf["jkt"]!!.jsonPrimitive.content)
        assertNull("never edge's certificate, which every installation shares", cnf["x5t#S256"])
        assertTrue(application.noBackupFilesDir.resolve("versola/native-endpoints.json").exists())

        // ---- 22: the code without its blob is refused, and was not spent ------------------------
        val code = completeForm["code"]!!
        val withoutBlob = http.newCall(
            Request.Builder().url(complete.url)
                .header("DPoP", versola.dpop!!.proof("POST", started["token_endpoint"]!!.jsonPrimitive.content))
                .post(FormBody.Builder().add("code", code).add("state", completeForm["state"]!!).add("iss", completeForm["iss"]!!).build())
                .build(),
        ).execute().use { it.code to it.body.string() }
        assertEquals(400, withoutBlob.first)
        assertTrue(withoutBlob.second, withoutBlob.second.contains("invalid_request"))

        // ---- the authenticated call through edge -----------------------------------------------
        upstream.enqueue(MockResponse.Builder().code(200).setHeader("Content-Type", "application/json").body("""{"items":[]}""").build())
        assertEquals(200, callUntilRoutable(versola, central, "${stack.edgeUrl}/resources/${fixture.resourceId}/items"))
        val served = transcript.matching("GET", "/resources/${fixture.resourceId}/items").last()
        assertEquals("DPoP $accessToken", served.header("Authorization"))
        assertEquals(Transcript.base64UrlSha256(accessToken), served.proofClaims!!["ath"]!!.jsonPrimitive.content)
        assertEquals(1, upstream.requestCount)

        // ---- refresh through /native/token -------------------------------------------------------
        transcript.clear()
        versola.refresh()
        val refresh = transcript.matching("POST", "/native/token/${fixture.clientId}").single()
        assertEquals(200, refresh.status)
        assertEquals("refresh_token", refresh.form["grant_type"])
        assertEquals(refreshToken, refresh.form["refresh_token"])
        assertFalse(refresh.form.containsKey("client_id"))
        assertNotNull(refresh.header("Idempotency-Key"))
        assertEquals(started["token_endpoint"]!!.jsonPrimitive.content, refresh.proofClaims!!["htu"]!!.jsonPrimitive.content)
        val renewed = refresh.responseJson!!
        assertEquals(refreshToken, renewed["refresh_token"]!!.jsonPrimitive.content)
        assertEquals("DPoP", renewed["token_type"]!!.jsonPrimitive.content)

        withContext(Dispatchers.IO) { Thread.sleep(200) }
        assertEquals(
            listOf(SessionState.Unauthenticated, SessionState.Authorizing, SessionState.Authenticated, SessionState.Refreshing, SessionState.Authenticated),
            states.toList(),
        )

        // ---- 18 through /native/revoke -------------------------------------------------------------
        val replayProof = versola.dpop!!.proof("POST", started["token_endpoint"]!!.jsonPrimitive.content)
        transcript.clear()
        versola.logout()
        val revoke = transcript.matching("POST", "/native/revoke/${fixture.clientId}").single()
        assertEquals(200, revoke.status)
        assertEquals(refreshToken, revoke.form["token"])
        assertEquals(started["revocation_endpoint"]!!.jsonPrimitive.content, revoke.proofClaims!!["htu"]!!.jsonPrimitive.content)
        val endSession = browser.opened.last().toHttpUrl()
        assertEquals(renewed["id_token"]!!.jsonPrimitive.content, endSession.queryParameter("id_token_hint"))
        assertEquals(SessionState.Unauthenticated, states.last())

        val replay = http.newCall(
            Request.Builder().url("${stack.edgeUrl}/native/token/${fixture.clientId}")
                .header("DPoP", replayProof)
                .post(FormBody.Builder().add("grant_type", "refresh_token").add("refresh_token", refreshToken).build())
                .build(),
        ).execute().use { it.code to it.body.string() }
        assertEquals(400, replay.first)
        assertTrue(replay.second, replay.second.contains("invalid_grant"))

        collecting.cancelAndJoin()
    }

    /**
     * A client central registered a moment ago reaches edge's cache (404 on `/native/start`)
     * and auth's (401 `invalid_client` from `/par`, relayed) by a notification the registering
     * call does not wait for — `NativeAppFlowSpec.start` retries the same way.
     */
    private suspend fun loginUntilFronted(versola: Versola, central: CentralClient, scopes: Set<String>) {
        var last: VersolaError? = null
        repeat(30) {
            try {
                versola.login(scopes)
                return
            } catch (e: VersolaError.Configuration) {
                val detail = e.detail
                val transient = detail is VersolaError.Configuration.Detail.EdgeClientUnknown ||
                    (detail is VersolaError.Configuration.Detail.AuthorizationRejected && detail.code == "invalid_client")
                if (!transient) throw e
                last = e
                central.syncConfiguration()
                withContext(Dispatchers.IO) { Thread.sleep(1000) }
            }
        }
        throw AssertionError("edge never fronted the client: $last")
    }

    private suspend fun callUntilRoutable(versola: Versola, central: CentralClient, url: String): Int {
        repeat(30) {
            val code = versola.call(Request.Builder().url(url).get().build()).use { it.code }
            if (code != 404 && code != 403) return code
            central.syncConfiguration()
            withContext(Dispatchers.IO) { Thread.sleep(1000) }
        }
        error("edge never routed $url")
    }

    /** RFC 7638: SHA-256 over the canonical `{"crv","kty","x","y"}` member set, base64url. */
    private fun thumbprint(jwk: JsonObject): String {
        val canonical = """{"crv":"${jwk["crv"]!!.jsonPrimitive.content}","kty":"${jwk["kty"]!!.jsonPrimitive.content}",""" +
            """"x":"${jwk["x"]!!.jsonPrimitive.content}","y":"${jwk["y"]!!.jsonPrimitive.content}"}"""
        return Base64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(Charsets.UTF_8)))
    }
}
