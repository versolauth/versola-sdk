package versola.sdk.conformance

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
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import versola.oauth.core.VersolaInternalApi
import versola.sdk.LoginOptions
import versola.sdk.Versola
import versola.sdk.VersolaConfiguration
import versola.sdk.dpop.DpopProofFactory
import versola.sdk.dpop.KeystoreDpopKey
import versola.sdk.core.EdgeClientUnknown
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
 * Scenario 21, with 22's blob-less replay and 18 through `/native/revoke`: the SDK on a
 * `fapi2` tenant, where it cannot be a public client of auth and goes through edge's native
 * endpoints, the only way the `Versola` facade signs in (`spec/versola-sdk-api.md`). Asserted
 * from the transcript of what the SDK actually sent, not from the call having succeeded. This is
 * also the driver's only scenario for the facade's happy path: the old scenario 01 test, which
 * drove a direct back channel on a `standard` tenant, went with that back channel, and the steps
 * it covered (login, the authenticated call with `ath`, a refresh renewed in place, logout and a
 * new key after it) are asserted here through the native endpoints.
 *
 * The browser leg is [HttpLoginBrowser]; everything else is `Versola.create()` as an app would
 * call it. Instrumented: needs an emulator and the staged stack.
 */
@OptIn(VersolaInternalApi::class)
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
        val configuration = VersolaConfiguration(
            edgeUrl = stack.edgeUrl,
            clientId = fixture.clientId,
            redirectUri = fixture.redirectUri,
            issuer = stack.issuer,
            httpClient = http,
        )
        val versola = Versola.create(application, configuration, browser)
        // Whatever a previous scenario left behind in the shared store ends here, through the
        // SDK rather than by deleting files under a live DataStore.
        if (versola.sessionState.first() != SessionState.Unauthenticated) versola.logout()
        val states = mutableListOf<SessionState>()
        val collecting = async(Dispatchers.IO, start = CoroutineStart.UNDISPATCHED) {
            versola.sessionState.collect { if (states.lastOrNull() != it) states += it }
        }

        // ---- start → authorize → complete ----------------------------------------------------
        loginUntilFronted(versola, central, setOf("openid"))

        // The SDK reads no discovery document and no key set: nothing of the kind was requested.
        assertEquals(
            "the SDK requested a discovery document or a key set",
            emptyList<String>(),
            transcript.entries.map { it.path }.filter { it.contains("/.well-known/") || it.endsWith("/jwks") },
        )
        // Nor does it call auth itself: what reached auth's address is the browser's pages.
        assertEquals(
            "the SDK called auth directly",
            emptyList<String>(),
            transcript.entries.filter { it.url.startsWith(stack.authUrl) }.map { it.path }
                .filter { it.endsWith("/token") || it.endsWith("/revoke") || it.endsWith("/par") },
        )
        val start = transcript.matching("POST", "/native/start/${fixture.clientId}").last { it.status == 200 }
        val startForm = start.form
        assertEquals(fixture.redirectUri, startForm["redirect_uri"])
        assertTrue(startForm["scope"]!!.split(' ').containsAll(listOf("openid", "offline_access")))
        val nonce = startForm["nonce"]!!
        assertTrue("nonce must carry at least 128 bits", nonce.length >= 22)
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
        assertNotEquals("state is edge's and the nonce the device's", started["state"]!!.jsonPrimitive.content, nonce)

        val authorizeUri = browser.opened.first().toHttpUrl()
        // The authorization_endpoint of the start answer, as edge wrote it.
        assertEquals(started["authorization_endpoint"]!!.jsonPrimitive.content, authorizeUri.toString().substringBefore('?'))
        assertEquals(setOf("client_id", "request_uri"), authorizeUri.queryParameterNames)
        assertEquals(fixture.clientId, authorizeUri.queryParameter("client_id"))
        assertEquals(started["request_uri"]!!.jsonPrimitive.content, authorizeUri.queryParameter("request_uri"))

        val complete = transcript.matching("POST", "/native/complete/${fixture.clientId}").single()
        assertEquals(200, complete.status)
        val completeForm = complete.form
        assertEquals(started["state"]!!.jsonPrimitive.content, completeForm["state"])
        assertEquals(started["blob"]!!.jsonPrimitive.content, completeForm["blob"])
        assertEquals("the redirect's iss is the configured issuer, as written", stack.issuer, completeForm["iss"])
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
        // A proof of the device key, minted for the replay without any capability of the facade's
        // (it has none): the same Keystore entry is opened under its alias and checked to be the key
        // that signed `/native/start`, so a refusal below is for the missing blob and not a key mismatch.
        val deviceProofs = deviceProofs(configuration, deviceJkt)
        val withoutBlob = http.newCall(
            Request.Builder().url(complete.url)
                .header("DPoP", deviceProofs.proof("POST", started["token_endpoint"]!!.jsonPrimitive.content))
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
        val replayProof = deviceProofs.proof("POST", started["token_endpoint"]!!.jsonPrimitive.content)
        transcript.clear()
        versola.logout()
        val revoke = transcript.matching("POST", "/native/revoke/${fixture.clientId}").single()
        assertEquals(200, revoke.status)
        assertEquals(refreshToken, revoke.form["token"])
        assertEquals(started["revocation_endpoint"]!!.jsonPrimitive.content, revoke.proofClaims!!["htu"]!!.jsonPrimitive.content)
        val endSession = browser.opened.last().toHttpUrl()
        assertEquals(renewed["id_token"]!!.jsonPrimitive.content, endSession.queryParameter("id_token_hint"))
        // The current value, not the collector's view: the collector runs on another
        // dispatcher and may not have seen the last transition yet.
        assertEquals(SessionState.Unauthenticated, versola.sessionState.first())

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
                versola.login(LoginOptions(scopes = scopes))
                return
            } catch (e: VersolaError.Configuration) {
                val detail = e.detail
                val transient = detail is EdgeClientUnknown ||
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

    /**
     * Proofs by the device key the facade generated, for the two replays above, without a
     * proof-minting capability on `Versola` (security review F6): the key is opened under the alias
     * the facade stores it by, which is `versola-sdk-` plus the configuration's storage key (the
     * first 16 characters of the base64url SHA-256 of `edge origin, issuer, client id`, newline
     * separated) plus `.dpop`. That formula is internal to the SDK and repeated here; the
     * `expectedJkt` check fails loudly if it ever drifts, and `isGrantHeld = { true }` makes an
     * absent key an error rather than a new key. `logout()` destroys the key, so the replay proof
     * is minted before it.
     */
    private suspend fun deviceProofs(configuration: VersolaConfiguration, expectedJkt: String): DpopProofFactory {
        val storageKey = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256")
                .digest("${configuration.edgeUrl.trimEnd('/')}\n${configuration.issuer}\n${configuration.clientId}".toByteArray(Charsets.UTF_8)),
        ).take(16)
        val key = KeystoreDpopKey(alias = "versola-sdk-$storageKey.dpop", isGrantHeld = { true })
        assertEquals("not the key of this session: the alias formula drifted", expectedJkt, key.jkt())
        return DpopProofFactory(key)
    }

    /** RFC 7638: SHA-256 over the canonical `{"crv","kty","x","y"}` member set, base64url. */
    private fun thumbprint(jwk: JsonObject): String {
        val canonical = """{"crv":"${jwk["crv"]!!.jsonPrimitive.content}","kty":"${jwk["kty"]!!.jsonPrimitive.content}",""" +
            """"x":"${jwk["x"]!!.jsonPrimitive.content}","y":"${jwk["y"]!!.jsonPrimitive.content}"}"""
        return Base64.getUrlEncoder().withoutPadding()
            .encodeToString(MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(Charsets.UTF_8)))
    }
}
