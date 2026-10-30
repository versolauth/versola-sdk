package versola.oauth.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

private const val ISSUER = "https://id.versola.io"

private fun pending(state: String = "the-state") = PendingAuthorizationRequest(
    state = state,
    nonce = "the-nonce",
    codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
    scopes = listOf("openid", "profile"),
    redirectUri = "https://app.example.com/oauth",
    acrValues = emptyList(),
    maxAge = null,
    createdAtEpochMillis = 0,
)

class AuthorizationResponseValidatorTest {

    @Test
    fun `accepts a redirect carrying a matching state, matching iss and a code`() {
        val grant = AuthorizationResponseValidator.validate(
            redirect = "https://app.example.com/oauth?code=the-code&state=the-state&iss=$ISSUER",
            pending = pending(),
            issuer = ISSUER,
            issParameterSupported = true,
        )

        assertEquals("the-code", grant.code)
        assertEquals("the-nonce", grant.nonce)
        assertEquals(setOf("openid", "profile"), grant.scopes)
    }

    @Test
    fun `state mismatch is Configuration, and is reached before anything else`() {
        // Scenario 15. The redirect below would also fail on iss and on the missing code;
        // state is checked first so neither gets the chance.
        val error = assertThrows(VersolaError.Configuration::class.java) {
            AuthorizationResponseValidator.validate(
                redirect = "https://app.example.com/oauth?state=not-the-state&iss=https://evil.example",
                pending = pending(),
                issuer = ISSUER,
                issParameterSupported = true,
            )
        }

        assertEquals(VersolaError.Configuration.Detail.StateMismatch, error.detail)
    }

    @Test
    fun `an absent state is a mismatch rather than a separate case`() {
        val error = assertThrows(VersolaError.Configuration::class.java) {
            AuthorizationResponseValidator.validate(
                redirect = "https://app.example.com/oauth?code=the-code",
                pending = pending(),
                issuer = ISSUER,
                issParameterSupported = false,
            )
        }

        assertEquals(VersolaError.Configuration.Detail.StateMismatch, error.detail)
    }

    @Test
    fun `iss naming a different issuer is Configuration, reported distinctly from a state mismatch`() {
        // Scenario 16.
        val error = assertThrows(VersolaError.Configuration::class.java) {
            AuthorizationResponseValidator.validate(
                redirect = "https://app.example.com/oauth?code=c&state=the-state&iss=https://evil.example",
                pending = pending(),
                issuer = ISSUER,
                issParameterSupported = true,
            )
        }

        assertEquals(
            VersolaError.Configuration.Detail.IssuerMismatch(ISSUER, "https://evil.example"),
            error.detail,
        )
    }

    @Test
    fun `iss omitted by a provider that advertises support is rejected identically`() {
        val error = assertThrows(VersolaError.Configuration::class.java) {
            AuthorizationResponseValidator.validate(
                redirect = "https://app.example.com/oauth?code=c&state=the-state",
                pending = pending(),
                issuer = ISSUER,
                issParameterSupported = true,
            )
        }

        assertEquals(VersolaError.Configuration.Detail.IssuerMismatch(ISSUER, null), error.detail)
    }

    @Test
    fun `iss omitted by a provider that does not advertise support is accepted`() {
        // RFC 9207 is not universal. A deployment that does not advertise it may legitimately
        // omit iss, and refusing that would make the SDK non-portable.
        val grant = AuthorizationResponseValidator.validate(
            redirect = "https://app.example.com/oauth?code=the-code&state=the-state",
            pending = pending(),
            issuer = ISSUER,
            issParameterSupported = false,
        )

        assertEquals("the-code", grant.code)
    }

    @Test
    fun `iss is compared as a string, so a trailing slash or another case is a mismatch`() {
        // RFC 9207 section 2.4: simple string comparison, no normalisation. A tolerance here is
        // the mix-up attack's room: `https://id.example.com/` and `https://id.example.com` are
        // two issuers.
        for (iss in listOf("$ISSUER/", ISSUER.uppercase(), "$ISSUER ", "${ISSUER}%2F")) {
            val error = assertThrows(VersolaError.Configuration::class.java) {
                AuthorizationResponseValidator.validate(
                    redirect = "https://app.example.com/oauth?code=c&state=the-state&iss=" + java.net.URLEncoder.encode(iss, "UTF-8"),
                    pending = pending(),
                    issuer = ISSUER,
                    issParameterSupported = true,
                )
            }
            assertTrue(iss, error.detail is VersolaError.Configuration.Detail.IssuerMismatch)
        }
    }

    @Test
    fun `access_denied is Reauthenticate, not Configuration`() {
        val error = assertThrows(VersolaError.Reauthenticate::class.java) {
            AuthorizationResponseValidator.validate(
                redirect = "https://app.example.com/oauth?error=access_denied&state=the-state",
                pending = pending(),
                issuer = ISSUER,
                issParameterSupported = false,
            )
        }

        assertEquals(VersolaError.Reauthenticate.Reason.AuthorizationDenied, error.reason)
    }

    @Test
    fun `the prompt-none trio is Reauthenticate`() {
        for (code in listOf("login_required", "consent_required", "interaction_required")) {
            val error = assertThrows(VersolaError.Reauthenticate::class.java) {
                AuthorizationResponseValidator.validate(
                    redirect = "https://app.example.com/oauth?error=$code&state=the-state",
                    pending = pending(),
                    issuer = ISSUER,
                    issParameterSupported = false,
                )
            }

            assertEquals(VersolaError.Reauthenticate.Reason.InteractionRequired(code), error.reason)
        }
    }

    @Test
    fun `every other authorization error is Configuration, including one the SDK does not know`() {
        for (code in listOf("invalid_request", "invalid_scope", "unmet_authentication_requirements", "invented_code")) {
            val error = assertThrows(VersolaError.Configuration::class.java) {
                AuthorizationResponseValidator.validate(
                    redirect = "https://app.example.com/oauth?error=$code&error_description=why&state=the-state",
                    pending = pending(),
                    issuer = ISSUER,
                    issParameterSupported = false,
                )
            }

            assertEquals(
                VersolaError.Configuration.Detail.AuthorizationRejected(code, "why"),
                error.detail,
            )
        }
    }

    @Test
    fun `an error is only read after state has been checked`() {
        // An injected error response with someone else's state must not be reported as the
        // user declining; it is a state mismatch like any other.
        val error = assertThrows(VersolaError.Configuration::class.java) {
            AuthorizationResponseValidator.validate(
                redirect = "https://app.example.com/oauth?error=access_denied&state=somebody-elses",
                pending = pending(),
                issuer = ISSUER,
                issParameterSupported = false,
            )
        }

        assertEquals(VersolaError.Configuration.Detail.StateMismatch, error.detail)
    }

    @Test
    fun `a redirect carrying neither code nor error is malformed`() {
        val error = assertThrows(VersolaError.Configuration::class.java) {
            AuthorizationResponseValidator.validate(
                redirect = "https://app.example.com/oauth?state=the-state",
                pending = pending(),
                issuer = ISSUER,
                issParameterSupported = false,
            )
        }

        assertEquals(
            VersolaError.Configuration.Detail.MalformedAuthorizationResponse,
            error.detail,
        )
    }

    @Test
    fun `a malformed percent-escape is Configuration rather than a raw decoder exception`() {
        // The redirect activity hands over whatever URI string the OS delivered — untrusted
        // external input. `URLDecoder.decode` throws `IllegalArgumentException` on a bare
        // "%", which must not escape past the `VersolaError` contract `complete()` cleans up
        // after (it only catches `VersolaError`).
        val error = assertThrows(VersolaError.Configuration::class.java) {
            AuthorizationResponseValidator.validate(
                redirect = "https://app.example.com/oauth?state=the-state&code=%",
                pending = pending(),
                issuer = ISSUER,
                issParameterSupported = false,
            )
        }

        assertEquals(
            VersolaError.Configuration.Detail.MalformedAuthorizationResponse,
            error.detail,
        )
    }

    @Test
    fun `a repeated parameter is malformed rather than last-wins`() {
        // Last-wins is how a smuggled parameter gets read; the server refuses duplicates for
        // the same reason (AuthorizeRequestParser.getParam).
        val error = assertThrows(VersolaError.Configuration::class.java) {
            AuthorizationResponseValidator.validate(
                redirect = "https://app.example.com/oauth?code=a&code=b&state=the-state",
                pending = pending(),
                issuer = ISSUER,
                issParameterSupported = false,
            )
        }

        assertEquals(
            VersolaError.Configuration.Detail.MalformedAuthorizationResponse,
            error.detail,
        )
    }

    @Test
    fun `percent-encoded parameters are decoded`() {
        val grant = AuthorizationResponseValidator.validate(
            redirect = "https://app.example.com/oauth?code=a%2Fb%2Bc&state=the-state",
            pending = pending(),
            issuer = ISSUER,
            issParameterSupported = false,
        )

        assertEquals("a/b+c", grant.code)
    }

    @Test
    fun `the grant does not print the code`() {
        val grant = AuthorizationResponseValidator.validate(
            redirect = "https://app.example.com/oauth?code=the-code&state=the-state",
            pending = pending(),
            issuer = ISSUER,
            issParameterSupported = false,
        )

        assertTrue(grant.toString().contains("redacted"))
    }
}
