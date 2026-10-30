package versola.oauth.flutter.conformance

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import versola.oauth.conformance.Provider
import versola.oauth.flutter.ErrorCategoryMessage
import versola.oauth.flutter.SessionStateMessage

/**
 * `24-generic-happy-path` through the bridge: sign-in, authenticated call and sign-out, every
 * operation sent through the plugin's host API. The assertions are the native driver's
 * (`Scenario24GenericHappyPathTest`); where the native test used what Flutter does not have (the
 * authenticated OkHttp client), the call is the app's own, with the token `accessToken()` hands
 * over, and the half that asserted the interceptor's origin matching has no bridge equivalent
 * (`spec/oauth-sdk-api.md` section 10).
 */
class Scenario24GenericHappyPathBridgeTest : BridgeConformance() {

    @Test
    fun `bridge - sign-in, the app's own authenticated call, userinfo and sign-out against the staged provider`() {
        val bridge = bridge()
        val dart = bridge.dart
        val subscription = dart.sessionStates()
        val sentAtSubscribe = messenger.sentOn(subscription.channel)
        assertEquals("one state collection while a Dart subscription is open", 1, nativeStateCollections())
        // Discovery first (the one request of it; the login reuses the cached document), for the
        // paths the assertions below are keyed on.
        val metadata = bridge.observe("discovery") { metadata() }
        // The ID token must be validated before Authenticated is published: the state the SDK is
        // in when it asks for the keys is the proof (second assertion). Asked through the bridge,
        // from the proxy's thread, while the login call is still open.
        var stateAtJwksFetch: SessionStateMessage? = null
        proxy.rewrite(metadata.jwksUri!!.substringAfter(proxy.origin)) { body ->
            stateAtJwksFetch = dart.sessionState()
            body
        }

        dart.login().assertOk()

        assertEquals(SessionStateMessage.AUTHENTICATED, dart.sessionState())
        // The native side sent the login's states on the event channel while the subscription was open.
        assertTrue("states sent during login", messenger.sentOn(subscription.channel) > sentAtSubscribe)
        assertEquals(SessionStateMessage.AUTHORIZING, stateAtJwksFetch)
        val claims = checkNotNull(dart.claims()) { "claims after login" }
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
            opened.queryMap()
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

        // The one credential that crosses: the access token, bearer, usable by the app at the
        // protected resource. The SDK itself sends nothing to the resource: attaching the token is
        // the app's when it uses accessToken(); the authenticated client, httpClient(), is scenario 32's bridge tests.
        val accessToken = dart.accessToken().token()
        assertTokenIsUsableAtTheResource(accessToken, claims.subject)
        assertTrue(transcript.entries.none { it.url.startsWith(resource.origin) })

        assertEquals(claims.subject, dart.userInfo().subject())

        val outcome = dart.logout()

        assertEquals(SessionStateMessage.UNAUTHENTICATED, dart.sessionState())
        assertNull(dart.claims())
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
            val replay = app.newCall(
                okhttp3.Request.Builder().url(metadata.tokenEndpoint).post(
                    okhttp3.FormBody.Builder()
                        .add("grant_type", "refresh_token")
                        .add("refresh_token", refreshToken)
                        .add("client_id", Provider.CLIENT_ID)
                        .build(),
                ).build(),
            ).execute()
            val replayBody = replay.use { it.body.string() }
            assertEquals(replayBody, 400, replay.code)
            assertTrue(replayBody, replayBody.contains("invalid_grant"))
        }
        if (metadata.endSessionEndpoint != null) {
            val endSession = browser.opened.last()
            assertTrue(endSession.startsWith(metadata.endSessionEndpoint + "?"))
            assertTrue(endSession.queryMap().containsKey("id_token_hint"))
            assertEquals(Provider.POST_LOGOUT_REDIRECT_URI, endSession.queryMap()["post_logout_redirect_uri"])
        }
        // The store holds nothing credential-shaped: the next token is a sign-in, not a refresh.
        assertEquals(ErrorCategoryMessage.REAUTHENTICATE, dart.accessToken().failure().category)
        assertEquals(1, transcript.matching("POST", metadata.tokenEndpoint.substringAfter(proxy.origin)).size)

        // The state stream (flutter.md, Bridge): the seven states and no others, starting with the
        // restored one and ending where the session ended; the first value is the one `sessionState()` answers.
        Waiting.until("the stream delivers the signed-out state") { subscription.states.lastOrNull() == SessionStateMessage.UNAUTHENTICATED && SessionStateMessage.AUTHENTICATED in subscription.states }
        assertEquals(SessionStateMessage.UNAUTHENTICATED, subscription.states.first())
        assertTrue(subscription.states.indexOf(SessionStateMessage.AUTHENTICATED) > 0)
        // Cancelling the Dart subscription ends the native collection (flutter.md). Two observations,
        // because each alone can be fooled: the plugin has no collection left running, and the native
        // side sends nothing more on the channel across the next login's state changes. The test's own
        // listener is gone either way, so what is counted is the native side's sends, not Dart's receipts.
        subscription.cancel()
        assertEquals("state collections after cancel", 0, nativeStateCollections())
        val sentAtCancel = messenger.sentOn(subscription.channel)
        dart.login().assertOk()
        assertEquals(SessionStateMessage.AUTHENTICATED, dart.sessionState())
        assertEquals("messages sent on the channel after cancel", sentAtCancel, messenger.sentOn(subscription.channel))
    }
}
