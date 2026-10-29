package versola.oauth.conformance

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import okhttp3.Request
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import versola.oauth.core.SessionState
import versola.oauth.core.VersolaError

/** `24-generic-happy-path`: sign-in, authenticated call and sign-out through the generic facade. */
class Scenario24GenericHappyPathTest : ProviderConformance() {

    @Test
    fun `sign-in, authenticated call, userinfo and sign-out against the staged provider`() = runTest {
        val client = client()
        // Discovery first (the one request of it; the login reuses the cached document), for
        // the paths the assertions below are keyed on.
        val metadata = client.metadata()
        // The ID token must be validated before Authenticated is published: the state the
        // SDK is in when it asks for the keys is the proof (second assertion).
        var stateAtJwksFetch: SessionState? = null
        proxy.rewrite(metadata.jwksUri!!.substringAfter(proxy.origin)) { body ->
            stateAtJwksFetch = runBlocking { client.state() }
            body
        }

        client.login()

        assertEquals(SessionState.Authenticated, client.state())
        assertEquals(SessionState.Authorizing, stateAtJwksFetch)
        val claims = checkNotNull(client.claims) { "claims after login" }
        assertTrue(claims.subject.isNotBlank())
        // The issuer as discovery announces it, trailing slash included (Hydra, Auth0).
        assertEquals(metadata.issuer, claims.issuer)

        // Exactly one discovery request; the request the browser opened is code + S256 with
        // state and nonce, either in the query or pushed first (PAR when advertised).
        assertEquals(1, transcript.matching("GET", "/.well-known/openid-configuration").size)
        val opened = browser.opened.single()
        assertTrue(opened.startsWith(metadata.authorizationEndpoint + "?"))
        val authorizationParameters = if (metadata.pushedAuthorizationRequestEndpoint != null) {
            theRequest("POST", metadata.pushedAuthorizationRequestEndpoint!!.substringAfter(proxy.origin)).form
        } else {
            opened.query()
        }
        assertEquals("code", authorizationParameters["response_type"])
        assertEquals("S256", authorizationParameters["code_challenge_method"])
        assertTrue(authorizationParameters.containsKey("state"))
        assertTrue(authorizationParameters.containsKey("nonce"))
        assertFalse(transcript.entries.any { it.form.containsKey("client_secret") })

        // The token request: a public client, the verifier, nothing non-standard.
        val token = theRequest("POST", metadata.tokenEndpoint.substringAfter(proxy.origin))
        assertEquals("authorization_code", token.form["grant_type"])
        assertTrue(token.form.containsKey("code"))
        assertTrue(token.form.containsKey("code_verifier"))
        assertEquals(Provider.REDIRECT_URI, token.form["redirect_uri"])
        assertEquals(Provider.CLIENT_ID, token.form["client_id"])
        assertNoSecretOnTheWire(token)
        assertNull(token.header("Idempotency-Key"))

        // The authenticated client attaches the token to the configured origin and nothing else.
        val protected = client.call(Request.Builder().url(resource.url("/api")).build())
        assertEquals(200, protected.code)
        assertTrue(protected.body.string().contains(claims.subject))
        val elsewhere = client.call(Request.Builder().url(proxy.origin + "/elsewhere").build())
        elsewhere.close()
        assertTrue(transcript.entries.filter { it.url.startsWith(resource.origin) }.all { it.header("Authorization")?.startsWith("Bearer ") == true })
        assertNull(transcript.entries.single { it.url == proxy.origin + "/elsewhere" }.header("Authorization"))

        val userInfo = client.userInfo()
        assertEquals(claims.subject, userInfo.subject)

        val outcome = client.logout()

        assertEquals(SessionState.Unauthenticated, client.state())
        assertNull(client.claims)
        assertEquals(metadata.revocationEndpoint != null, outcome.tokenRevoked)
        assertEquals(metadata.endSessionEndpoint != null, outcome.sessionEnded)
        if (metadata.revocationEndpoint != null) {
            val revoke = theRequest("POST", metadata.revocationEndpoint!!.substringAfter(proxy.origin))
            assertEquals("refresh_token", revoke.form["token_type_hint"])
            assertEquals(Provider.CLIENT_ID, revoke.form["client_id"])
            assertNoSecretOnTheWire(revoke)
            // RFC 7009's observable for a public client: the revoked refresh token no longer
            // buys a token. The value is the one the token response carried.
            val refreshToken = token.responseJson!!["refresh_token"]!!.toString().trim('"')
            val replay = okhttp3.OkHttpClient().newCall(
                Request.Builder().url(metadata.tokenEndpoint).post(
                    okhttp3.FormBody.Builder()
                        .add("grant_type", "refresh_token")
                        .add("refresh_token", refreshToken)
                        .add("client_id", Provider.CLIENT_ID)
                        .build(),
                ).build(),
            ).execute()
            val replayBody = replay.text()
            assertEquals(replayBody, 400, replay.code)
            assertTrue(replayBody, replayBody.contains("invalid_grant"))
        }
        if (metadata.endSessionEndpoint != null) {
            val endSession = browser.opened.last()
            assertTrue(endSession.startsWith(metadata.endSessionEndpoint + "?"))
            assertTrue(endSession.query().containsKey("id_token_hint"))
            assertEquals(Provider.POST_LOGOUT_REDIRECT_URI, endSession.query()["post_logout_redirect_uri"])
        }
        // The store holds nothing credential-shaped: the next token is a sign-in, not a refresh.
        val error = failsWith<VersolaError.Reauthenticate> { runBlocking { client.accessToken() } }
        assertNotNull(error)
        assertEquals(1, transcript.matching("POST", metadata.tokenEndpoint.substringAfter(proxy.origin)).size)
    }
}

/** The query of a URI as a decoded map. */
fun String.query(): Map<String, String> = substringAfter('?', "").split('&').filter { it.contains('=') }.associate {
    java.net.URLDecoder.decode(it.substringBefore('='), "UTF-8") to java.net.URLDecoder.decode(it.substringAfter('='), "UTF-8")
}
