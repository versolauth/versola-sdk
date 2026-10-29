package versola.samples.oauth

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.math.BigInteger
import java.net.URLDecoder
import java.net.URLEncoder
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import mockwebserver3.Dispatcher
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.RecordedRequest
import okhttp3.Request
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import versola.oauth.OAuthClient
import versola.oauth.OAuthConfiguration
import versola.oauth.core.BrowserAuthorizationSession
import versola.oauth.core.BrowserOutcome
import versola.oauth.core.SessionState

/**
 * Discovery, sign-in, an authenticated call, userinfo and sign-out against a provider on a
 * MockWebServer, run by `connectedAndroidTest` on a device: the generic facade end to end on
 * the real Keystore (no key provider is substituted). The build file says why this runs on the
 * debug build and not the minified one.
 *
 * Only the browser leg is replaced, through the opt-in overload of `OAuthClient.create`: a test
 * cannot drive an Auth Tab, and the contract stays URI-only.
 */
@RunWith(AndroidJUnit4::class)
class SmokeTest {

    private val context: Context = ApplicationProvider.getApplicationContext()
    private val server = MockWebServer()
    private val requests = CopyOnWriteArrayList<RecordedRequest>()
    private lateinit var provider: Provider
    private lateinit var browser: FakeBrowser

    /** Unique per run: the SDK keeps one client and one stored session per issuer and client id. */
    private val clientId = "smoke-${UUID.randomUUID()}"

    @Before
    fun start() {
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                requests += request
                return when (request.url.encodedPath) {
                    "/.well-known/openid-configuration" -> provider.json(provider.discovery())
                    "/jwks" -> provider.json(provider.jwks())
                    "/token" -> provider.json(tokenResponse())
                    "/userinfo" -> provider.json("""{"sub":"alice","name":"Alice"}""")
                    "/revoke" -> MockResponse.Builder().code(200).build()
                    "/api" -> MockResponse.Builder().code(200).body("ok").build()
                    else -> MockResponse.Builder().code(404).build()
                }
            }
        }
        server.start()
        provider = Provider(server)
        browser = FakeBrowser(provider.issuer)
    }

    @After
    fun stop() {
        server.close()
    }

    private fun tokenResponse(): String {
        val idToken = provider.idToken(nonce = checkNotNull(browser.nonceSeen), audience = clientId)
        return """{"access_token":"at","token_type":"Bearer","expires_in":3600,""" +
            """"id_token":"$idToken","refresh_token":"rt"}"""
    }

    @Test
    fun discoverySignInAuthenticatedCallUserInfoAndSignOutSurviveMinification() = runBlocking {
        val client = OAuthClient.create(
            context,
            OAuthConfiguration(
                issuer = provider.issuer,
                clientId = clientId,
                redirectUri = REDIRECT_URI,
                postLogoutRedirectUri = "https://app.example.com/signed-out",
                scopes = setOf("openid", "profile"),
                protectedOrigins = setOf(provider.issuer),
            ),
            browser = browser,
        )

        client.login()

        assertEquals(SessionState.Authenticated, client.sessionState.first())
        assertEquals("alice", client.claims?.subject)

        val response = client.call(Request.Builder().url("${provider.issuer}/api").build())
        response.use { assertEquals(200, it.code) }
        val api = requests.single { it.url.encodedPath == "/api" }
        assertEquals("Bearer at", api.headers["Authorization"])

        assertEquals("alice", client.userInfo().subject)

        val outcome = client.logout()

        assertTrue(outcome.tokenRevoked)
        assertNotNull(requests.singleOrNull { it.url.encodedPath == "/revoke" })
        assertEquals(SessionState.Unauthenticated, client.sessionState.first())
    }

    private companion object {
        const val REDIRECT_URI = "https://app.example.com/oauth"
    }
}

/** A provider on a MockWebServer: discovery, JWKS and a signer for its ID tokens. */
private class Provider(private val server: MockWebServer) {
    /** `http://127.0.0.1:port`: the facade allows cleartext to loopback only. */
    val issuer: String = server.url("/").toString().trimEnd('/')
    private val keys: KeyPair = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    fun discovery(): String = buildString {
        append("""{"issuer":"$issuer","authorization_endpoint":"$issuer/authorize","token_endpoint":"$issuer/token",""")
        append(""""jwks_uri":"$issuer/jwks","userinfo_endpoint":"$issuer/userinfo",""")
        append(""""revocation_endpoint":"$issuer/revoke","end_session_endpoint":"$issuer/logout",""")
        append(""""code_challenge_methods_supported":["S256"],"id_token_signing_alg_values_supported":["RS256"],""")
        append(""""scopes_supported":["openid","profile"],"response_types_supported":["code"]}""")
    }

    fun jwks(): String {
        val public = keys.public as RSAPublicKey
        return """{"keys":[{"kty":"RSA","kid":"k1","alg":"RS256","use":"sig","n":"${unsigned(public.modulus)}","e":"${unsigned(public.publicExponent)}"}]}"""
    }

    fun idToken(nonce: String, audience: String, subject: String = "alice"): String {
        val now = System.currentTimeMillis() / 1000
        val encoder = Base64.getUrlEncoder().withoutPadding()
        val header = encoder.encodeToString("""{"alg":"RS256","kid":"k1","typ":"JWT"}""".toByteArray())
        val payload = encoder.encodeToString(
            """{"iss":"$issuer","sub":"$subject","aud":"$audience","exp":${now + 3600},"iat":$now,"nonce":"$nonce","auth_time":$now}""".toByteArray(),
        )
        val signature = Signature.getInstance("SHA256withRSA").apply {
            initSign(keys.private)
            update("$header.$payload".toByteArray())
        }.sign()
        return "$header.$payload.${encoder.encodeToString(signature)}"
    }

    fun json(body: String): MockResponse = MockResponse.Builder()
        .code(200)
        .setHeader("Content-Type", "application/json")
        .body(body)
        .build()

    private fun unsigned(value: BigInteger): String {
        val bytes = value.toByteArray()
        val trimmed = if (bytes[0] == 0.toByte()) bytes.copyOfRange(1, bytes.size) else bytes
        return Base64.getUrlEncoder().withoutPadding().encodeToString(trimmed)
    }
}

/** Answers the request with a redirect for the state it carried, as a user who signed in would. */
private class FakeBrowser(private val issuer: String) : BrowserAuthorizationSession {
    @Volatile
    var nonceSeen: String? = null

    override suspend fun authorize(uri: String): BrowserOutcome {
        val query = uri.substringAfter('?').split('&')
            .associate { it.substringBefore('=') to URLDecoder.decode(it.substringAfter('='), "UTF-8") }
        // The end-session request carries no nonce; keep the one the sign-in saw.
        query["nonce"]?.let { nonceSeen = it }
        val state = query.getValue("state")
        return BrowserOutcome.Redirect(
            "https://app.example.com/oauth?code=the-code&state=$state&iss=${URLEncoder.encode(issuer, "UTF-8")}",
        )
    }

    override suspend fun awaitPendingRedirect(): BrowserOutcome = awaitCancellation()
}
