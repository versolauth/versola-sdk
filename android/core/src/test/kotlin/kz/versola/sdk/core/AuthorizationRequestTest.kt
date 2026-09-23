package kz.versola.sdk.core

import java.net.URI
import java.net.URLDecoder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AuthorizationRequestTest {

    private val configuration = VersolaConfiguration.create(
        issuer = "https://id.versola.kz",
        clientId = "mobile-app",
        redirectUri = "https://app.example.com/oauth",
    )

    private fun query(uri: String): Map<String, String> =
        URI(uri).rawQuery.split('&').associate { pair ->
            val (name, value) = pair.split('=', limit = 2)
            URLDecoder.decode(name, "UTF-8") to URLDecoder.decode(value, "UTF-8")
        }

    @Test
    fun `carries what the authorization endpoint requires`() {
        val request = AuthorizationRequest.create(configuration, setOf("openid", "profile"))

        val parameters = query(request.toUri("https://id.versola.kz/authorize"))

        assertEquals("code", parameters["response_type"])
        assertEquals("mobile-app", parameters["client_id"])
        assertEquals("https://app.example.com/oauth", parameters["redirect_uri"])
        assertEquals("openid profile", parameters["scope"])
        assertEquals("S256", parameters["code_challenge_method"])
        assertEquals(request.state, parameters["state"])
        assertEquals(request.nonce, parameters["nonce"])
    }

    @Test
    fun `the code_challenge is the S256 challenge of the verifier that will be presented`() {
        // Scenario 01's first assertion. The exchange presents request.codeVerifier, so if
        // these two ever disagree the server answers invalid_grant and nothing says why.
        val request = AuthorizationRequest.create(configuration, setOf("openid"))

        val challenge = query(request.toUri("https://id.versola.kz/authorize"))["code_challenge"]

        assertEquals(request.codeVerifier.challengeS256(), challenge)
    }

    @Test
    fun `state fits the server's 128-character limit`() {
        // AuthorizeRequestParser.MaxStateLength: a longer state is refused outright, since it
        // would push the conversation cookie past the browsers' 4 KiB limit.
        val request = AuthorizationRequest.create(configuration, setOf("openid"))

        assertTrue(request.state.length <= 128)
    }

    @Test
    fun `spaces are percent-encoded rather than form-encoded`() {
        // URLEncoder emits '+' for a space, which not every server's query parser reads back
        // as a space — and both scope and acr_values are space-delimited.
        val request = AuthorizationRequest.create(
            configuration,
            scopes = setOf("openid", "profile"),
            acrValues = listOf("urn:mace:incommon:iap:silver", "phr"),
        )

        val uri = request.toUri("https://id.versola.kz/authorize")

        assertTrue(uri.contains("scope=openid%20profile"))
        assertFalse(uri.contains('+'))
    }

    @Test
    fun `optional parameters are omitted rather than sent empty`() {
        val request = AuthorizationRequest.create(configuration, setOf("openid"))

        val parameters = query(request.toUri("https://id.versola.kz/authorize"))

        assertNull(parameters["acr_values"])
        assertNull(parameters["max_age"])
    }

    @Test
    fun `step-up parameters are carried when present`() {
        val request = AuthorizationRequest.create(
            configuration,
            scopes = setOf("openid"),
            acrValues = listOf("phr"),
            maxAge = 300,
        )

        val parameters = query(request.toUri("https://id.versola.kz/authorize"))

        assertEquals("phr", parameters["acr_values"])
        assertEquals("300", parameters["max_age"])
    }

    @Test
    fun `an authorization endpoint that already has a query keeps it`() {
        val request = AuthorizationRequest.create(configuration, setOf("openid"))

        val uri = request.toUri("https://id.versola.kz/authorize?tenant=acme")

        assertTrue(uri.contains("?tenant=acme&response_type=code"))
    }

    @Test
    fun `the pending request records exactly what the redirect will be validated against`() {
        val request = AuthorizationRequest.create(
            configuration,
            scopes = setOf("openid", "profile"),
            acrValues = listOf("phr"),
            maxAge = 300,
        )

        val pending = request.toPending(createdAtEpochMillis = 1_000)

        assertEquals(request.state, pending.state)
        assertEquals(request.nonce, pending.nonce)
        assertEquals(request.codeVerifier.value, pending.codeVerifier)
        assertEquals(listOf("openid", "profile"), pending.scopes)
        assertEquals("https://app.example.com/oauth", pending.redirectUri)
        assertEquals(listOf("phr"), pending.acrValues)
        assertEquals(300L, pending.maxAge)
        assertEquals(1_000L, pending.createdAtEpochMillis)
    }

    @Test
    fun `two requests share no state, nonce or verifier`() {
        val first = AuthorizationRequest.create(configuration, setOf("openid"))
        val second = AuthorizationRequest.create(configuration, setOf("openid"))

        assertFalse(first.state == second.state)
        assertFalse(first.nonce == second.nonce)
        assertFalse(first.codeVerifier.value == second.codeVerifier.value)
    }
}
