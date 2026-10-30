package versola.oauth.core

import java.net.URI
import java.net.URLDecoder
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AuthorizationRequestTest {

    private val configuration = VersolaConfiguration.create(
        issuer = "https://id.versola.io",
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

        val parameters = query(request.toUri("https://id.versola.io/authorize"))

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

        val challenge = query(request.toUri("https://id.versola.io/authorize"))["code_challenge"]

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

        val uri = request.toUri("https://id.versola.io/authorize")

        assertTrue(uri.contains("scope=openid%20profile"))
        assertFalse(uri.contains('+'))
    }

    @Test
    fun `optional parameters are omitted rather than sent empty`() {
        val request = AuthorizationRequest.create(configuration, setOf("openid"))

        val parameters = query(request.toUri("https://id.versola.io/authorize"))

        assertNull(parameters["acr_values"])
        assertNull(parameters["max_age"])
        assertNull(parameters["dpop_jkt"])
    }

    @Test
    fun `dpop_jkt is carried verbatim, since the server compares it as a string`() {
        // `Dpop.Jkt.parse` refuses anything that is not a canonical 43-character thumbprint,
        // and the token endpoint compares byte-for-byte rather than decoding — so a value
        // altered in transit strands the code rather than failing the request.
        val thumbprint = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
        val request = AuthorizationRequest.create(configuration, setOf("openid"), dpopJkt = thumbprint)

        val uri = request.toUri("https://id.versola.io/authorize")

        assertEquals(thumbprint, query(uri)["dpop_jkt"])
        assertTrue(uri.contains("dpop_jkt=$thumbprint"))
    }

    @Test
    fun `step-up parameters are carried when present`() {
        val request = AuthorizationRequest.create(
            configuration,
            scopes = setOf("openid"),
            acrValues = listOf("phr"),
            maxAge = 300,
        )

        val parameters = query(request.toUri("https://id.versola.io/authorize"))

        assertEquals("phr", parameters["acr_values"])
        assertEquals("300", parameters["max_age"])
    }

    @Test
    fun `an authorization endpoint that already has a query keeps it`() {
        val request = AuthorizationRequest.create(configuration, setOf("openid"))

        val uri = request.toUri("https://id.versola.io/authorize?tenant=acme")

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

    private fun names(uri: String): List<String> =
        URI(uri).rawQuery.split('&').map { URLDecoder.decode(it.substringBefore('='), "UTF-8") }

    @Test
    fun `login parameters follow dpop_jkt in the order prompt, login_hint, ui_locales, resource, extras`() {
        val request = AuthorizationRequest.create(
            configuration,
            scopes = setOf("openid"),
            dpopJkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I",
            parameters = AuthorizationParameters(
                prompt = AuthorizationParameters.Prompt.SelectAccount,
                loginHint = "ada@example.com",
                uiLocales = listOf("kk-KZ", "ru"),
                resources = listOf("https://api.example.com/a", "https://api.example.com/b"),
                extra = linkedMapOf("audience" to "orders", "claims" to "{}"),
            ),
        )

        val uri = request.toUri("https://id.versola.io/authorize")

        assertEquals(
            listOf(
                "response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge",
                "code_challenge_method", "dpop_jkt", "prompt", "login_hint", "ui_locales", "resource",
                "resource", "audience", "claims",
            ),
            names(uri),
        )
        val parameters = query(uri)
        assertEquals("select_account", parameters["prompt"])
        assertEquals("ada@example.com", parameters["login_hint"])
        assertEquals("orders", parameters["audience"])
        assertEquals("{}", parameters["claims"])
    }

    @Test
    fun `ui_locales is one space-delimited value, percent-encoded rather than form-encoded`() {
        val request = AuthorizationRequest.create(
            configuration,
            scopes = setOf("openid"),
            parameters = AuthorizationParameters(uiLocales = listOf("kk-KZ", "ru", "en")),
        )

        val uri = request.toUri("https://id.versola.io/authorize")

        assertTrue(uri.contains("ui_locales=kk-KZ%20ru%20en"))
        assertFalse(uri.contains('+'))
    }

    @Test
    fun `resource is repeated once per value and never joined`() {
        val request = AuthorizationRequest.create(
            configuration,
            scopes = setOf("openid"),
            parameters = AuthorizationParameters(
                resources = listOf("https://api.example.com/a", "https://api.example.com/b"),
            ),
        )

        val uri = request.toUri("https://id.versola.io/authorize")

        val resources = URI(uri).rawQuery.split('&')
            .filter { it.startsWith("resource=") }
            .map { URLDecoder.decode(it.removePrefix("resource="), "UTF-8") }
        assertEquals(listOf("https://api.example.com/a", "https://api.example.com/b"), resources)
        assertTrue(uri.contains("resource=https%3A%2F%2Fapi.example.com%2Fa"))
    }

    @Test
    fun `extra parameters come after everything the SDK sets and are encoded like the rest`() {
        val request = AuthorizationRequest.create(
            configuration,
            scopes = setOf("openid"),
            parameters = AuthorizationParameters(
                resources = listOf("https://api.example.com/a"),
                extra = linkedMapOf("zeta" to "a b&c", "alpha" to "ü"),
            ),
        )

        val uri = request.toUri("https://id.versola.io/authorize")

        assertEquals(listOf("resource", "zeta", "alpha"), names(uri).takeLast(3))
        assertTrue(uri.contains("zeta=a%20b%26c"))
        assertTrue(uri.contains("alpha=%C3%BC"))
    }

    @Test
    fun `no login parameters leaves the query exactly as it was`() {
        val request = AuthorizationRequest.create(configuration, setOf("openid"))

        val parameters = query(request.toUri("https://id.versola.io/authorize"))

        for (name in listOf("prompt", "login_hint", "ui_locales", "resource")) assertNull(name, parameters[name])
    }

    @Test
    fun `an extra parameter that collides with one the SDK sets is refused at construction`() {
        for (reserved in listOf("redirect_uri", "state", "resource", "prompt", "client_secret")) {
            val error = assertThrows(VersolaError.Configuration::class.java) {
                AuthorizationParameters(extra = mapOf(reserved to "x"))
            }
            assertTrue(reserved, error.detail is VersolaError.Configuration.Detail.InvalidConfiguration)
        }
    }

    @Test
    fun `the pending request keeps the resources so the exchange can repeat them`() {
        val request = AuthorizationRequest.create(
            configuration,
            scopes = setOf("openid"),
            parameters = AuthorizationParameters(resources = listOf("https://api.example.com/a")),
        )

        val pending = request.toPending(createdAtEpochMillis = 1_000)

        assertEquals(listOf("https://api.example.com/a"), pending.resources)
    }

    @Test
    fun `a pending request persisted before resources existed decodes with none`() {
        val old = """{"state":"s","nonce":"n","codeVerifier":"v","scopes":["openid"],"redirectUri":"https://app.example.com/oauth","acrValues":[],"maxAge":null,"createdAtEpochMillis":1}"""

        val decoded = PendingAuthorizationCodec.decode(old.toByteArray())

        assertEquals(emptyList<String>(), decoded.resources)
        assertEquals(emptyMap<String, String>(), decoded.extension)
    }

    @Test
    fun `resources survive the codec and are not mistaken for a starter's artefact`() {
        val pending = AuthorizationRequest.create(
            configuration,
            scopes = setOf("openid"),
            parameters = AuthorizationParameters(resources = listOf("https://api.example.com/a")),
        ).toPending(1)

        val decoded = PendingAuthorizationCodec.decode(PendingAuthorizationCodec.encode(pending))

        assertEquals(listOf("https://api.example.com/a"), decoded.resources)
        assertEquals(emptyMap<String, String>(), decoded.extension)
    }

    @Test
    fun `the validator copies the resources onto the grant`() {
        val pending = AuthorizationRequest.create(
            configuration,
            scopes = setOf("openid"),
            parameters = AuthorizationParameters(resources = listOf("https://api.example.com/a")),
        ).toPending(1)

        val grant = AuthorizationResponseValidator.validate(
            redirect = "https://app.example.com/oauth?code=c&state=${pending.state}",
            pending = pending,
            issuer = "https://id.versola.io",
            issParameterSupported = false,
        )

        assertEquals(listOf("https://api.example.com/a"), grant.resources)
    }
}
