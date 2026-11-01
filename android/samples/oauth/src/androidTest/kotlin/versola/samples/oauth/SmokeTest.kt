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
import versola.oauth.core.CredentialKeyProvider
import versola.oauth.core.SessionState
import versola.oauth.core.TokenBinding
import versola.oauth.core.VersolaError

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

    /** Audit tests: the provider advertises ES256 DPoP and issues DPoP-bound tokens. */
    @Volatile
    private var dpop = false

    @Volatile
    private var refreshed = false

    private fun tokenBody(): String = when {
        refreshed -> """{"access_token":"at2","token_type":"DPoP","expires_in":3600,"refresh_token":"rt2"}"""
        dpop -> tokenResponse().replace(""""token_type":"Bearer"""", """"token_type":"DPoP"""")
        else -> tokenResponse()
    }

    private fun jwkOf(proof: String): String =
        String(Base64.getUrlDecoder().decode(proof.substringBefore('.'))).substringAfter(""""jwk":""").substringBefore('}')

    @Before
    fun start() {
        server.dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                requests += request
                return when (request.url.encodedPath) {
                    "/.well-known/openid-configuration" -> provider.json(provider.discovery(dpop = dpop))
                    "/jwks" -> provider.json(provider.jwks())
                    "/token" -> provider.json(tokenBody())
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

    /**
     * AUDIT: Z1 (HIGH), device tier, the real AndroidKeyStore. OAuthClient gives the AES storage key
     * and the EC DPoP key the identical alias; the Keystore namespace is per app and a generate under
     * an existing alias replaces the entry whatever its type, so after a process restart the
     * stored refresh token is undecryptable (silent logout) or the proof key (jkt) has changed.
     */
    @Test
    fun auditZ1ADpopSessionSurvivesAProcessRestartWithItsRefreshTokenAndItsKey() = runBlocking {
        dpop = true
        val configuration = OAuthConfiguration(
            issuer = provider.issuer,
            clientId = clientId,
            redirectUri = REDIRECT_URI,
            postLogoutRedirectUri = "https://app.example.com/signed-out",
            scopes = setOf("openid"),
            tokenBinding = TokenBinding.Dpop(),
        )
        // On the real Keystore the collision can already break the first login: the pending request's
        // storage key replaces the DPoP key the code exchange is about to sign with.
        runCatching { OAuthClient.create(context, configuration, browser = browser).login() }.onFailure {
            throw AssertionError("a DPoP login must complete on the real Keystore, but failed with $it", it)
        }
        val jwkAtLogin = jwkOf(requests.last { it.url.encodedPath == "/token" }.headers["DPoP"]!!)
        refreshed = true

        OAuthClient.forgetAll()
        val restarted = OAuthClient.create(context, configuration, browser = browser)
        val outcome = runCatching { restarted.refresh() }
        // A second restart: whichever key the first one replaced, this one reads what it left.
        OAuthClient.forgetAll()
        val third = OAuthClient.create(context, configuration, browser = browser)
        val again = runCatching { third.refresh() }

        try {
            assertTrue("the stored refresh token must still decrypt after a restart: ${outcome.exceptionOrNull()}", outcome.isSuccess)
            assertEquals(
                "the proof key must be the one the grant was bound to",
                jwkAtLogin,
                jwkOf(requests.last { it.url.encodedPath == "/token" }.headers["DPoP"]!!),
            )
            assertTrue("and after a second restart: ${again.exceptionOrNull()}", again.isSuccess)
        } finally {
            runCatching { third.logout() }
            OAuthClient.forgetAll()
        }
    }

    /**
     * AUDIT: Z11 (PLAUSIBLE / design), device tier. The grant carries no jkt, so a DPoP key that vanished from the
     * Keystore (restore onto another device, a Keystore wipe) is silently regenerated and the refresh goes out
     * signed by a different key. Correct: a typed Reauthenticate and no token request. The wrapping key is
     * substituted (a pass-through) so the Z1 alias collision cannot be what ends the session.
     */
    @Test
    fun auditZ11ADpopKeyThatVanishedFromTheKeystoreIsATypedReauthenticationNotANewKey() = runBlocking {
        dpop = true
        val configuration = OAuthConfiguration(
            issuer = provider.issuer,
            clientId = clientId,
            redirectUri = REDIRECT_URI,
            postLogoutRedirectUri = "https://app.example.com/signed-out",
            scopes = setOf("openid"),
            tokenBinding = TokenBinding.Dpop(),
        )
        val passThrough = object : CredentialKeyProvider {
            override suspend fun wrap(plaintext: ByteArray): ByteArray = plaintext.reversedArray()
            override suspend fun unwrap(blob: ByteArray): ByteArray = blob.reversedArray()
        }
        OAuthClient.create(context, configuration, browser = browser, keyProvider = passThrough).login()
        val tokenRequestsAtLogin = requests.count { it.url.encodedPath == "/token" }
        refreshed = true
        val keyStore = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.aliases().toList().filter { it.startsWith("versola-oauth-") }.forEach(keyStore::deleteEntry)

        OAuthClient.forgetAll()
        val restarted = OAuthClient.create(context, configuration, browser = browser, keyProvider = passThrough)
        val error = runCatching { restarted.refresh() }.exceptionOrNull()
        val tokenRequestsAfter = requests.count { it.url.encodedPath == "/token" }
        OAuthClient.forgetAll()
        keyStore.aliases().toList().filter { it.startsWith("versola-oauth-") }.forEach(keyStore::deleteEntry)

        assertTrue("expected a typed Reauthenticate, got $error", error is VersolaError.Reauthenticate)
        assertEquals("no token request may be signed by a freshly minted key", tokenRequestsAtLogin, tokenRequestsAfter)
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

    fun discovery(dpop: Boolean = false): String = buildString {
        append("""{"issuer":"$issuer","authorization_endpoint":"$issuer/authorize","token_endpoint":"$issuer/token",""")
        append(""""jwks_uri":"$issuer/jwks","userinfo_endpoint":"$issuer/userinfo",""")
        append(""""revocation_endpoint":"$issuer/revoke","end_session_endpoint":"$issuer/logout",""")
        if (dpop) append(""""dpop_signing_alg_values_supported":["ES256"],""")
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
