package versola.oauth.flutter

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import versola.oauth.core.IdTokenRejection
import versola.oauth.core.SessionState
import versola.oauth.core.TokenBinding
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaError.Configuration.Detail
import versola.oauth.core.VersolaError.Reauthenticate.Reason
import versola.oauth.core.VersolaError.Recoverable.Cause

/** The flattening is the contract with Dart's `errorFromMessage`: category, then the case name. */
class MappingTest {
    @Test
    fun everyRecoverableCauseKeepsItsCategoryAndPayload() {
        val network = VersolaError.Recoverable(Cause.Network(detail = "timeout", attempts = 3, elapsedMillis = 1200)).toMessage()
        assertEquals(ErrorCategoryMessage.RECOVERABLE, network.category)
        assertEquals("network", network.kind)
        assertEquals("timeout", network.detail)
        assertEquals(3L, network.attempts)
        assertEquals(1200L, network.elapsedMillis)

        val server = VersolaError.Recoverable(Cause.Server(status = 429, retryAfterMillis = 30_000, attempts = 1, elapsedMillis = 40)).toMessage()
        assertEquals(ErrorCategoryMessage.RECOVERABLE, server.category)
        assertEquals("server", server.kind)
        assertEquals(429L, server.status)
        assertEquals(30_000L, server.retryAfterMillis)
        assertEquals(1L, server.attempts)

        // No Retry-After is no field, not a zero: an app that waits zero is hammering.
        val plain = VersolaError.Recoverable(Cause.Server(status = 500)).toMessage()
        assertEquals(500L, plain.status)
        assertNull(plain.retryAfterMillis)

        val loop = VersolaError.Recoverable(Cause.NonceLoop("https://api.example.com")).toMessage()
        assertEquals("nonceLoop", loop.kind)
        assertEquals("https://api.example.com", loop.origin)
        assertEquals("userCancelled", VersolaError.Recoverable(Cause.UserCancelled).toMessage().kind)
        assertEquals("unlockRequired", VersolaError.Recoverable(Cause.UnlockRequired).toMessage().kind)
    }

    @Test
    fun reauthenticateCarriesTheInteractionCode() {
        val m = VersolaError.Reauthenticate(Reason.InteractionRequired("login_required")).toMessage()
        assertEquals(ErrorCategoryMessage.REAUTHENTICATE, m.category)
        assertEquals("interactionRequired", m.kind)
        assertEquals("login_required", m.code)
        assertNull(VersolaError.Reauthenticate(Reason.SessionExpired).toMessage().code)
    }

    @Test
    fun stepUpIsItsOwnCategoryWithTheChallenge() {
        val m = VersolaError.StepUp(listOf("urn:acr:mfa"), 300).toMessage()
        assertEquals(ErrorCategoryMessage.STEP_UP, m.category)
        assertEquals(listOf("urn:acr:mfa"), m.acrValues)
        assertEquals(300L, m.maxAge)
    }

    @Test
    fun configurationDetailsKeepTheirFields() {
        val rejected = VersolaError.Configuration(Detail.TokenRequestRejected("invalid_grant", "expired")).toMessage()
        assertEquals(ErrorCategoryMessage.CONFIGURATION, rejected.category)
        assertEquals("tokenRequestRejected", rejected.kind)
        assertEquals("invalid_grant", rejected.code)
        assertEquals("expired", rejected.errorDescription)

        val idToken = VersolaError.Configuration(Detail.IdTokenRejected(IdTokenRejection.AccessTokenHash)).toMessage()
        assertEquals("idTokenRejected", idToken.kind)
        assertEquals("accessTokenHash", idToken.idTokenRejection)

        val issuer = VersolaError.Configuration(Detail.DiscoveryIssuerMismatch("https://a.example.com", "https://b.example.com")).toMessage()
        assertEquals("https://a.example.com", issuer.expected)
        assertEquals("https://b.example.com", issuer.received)
    }

    @Test
    fun anExceptionThatIsNotAnSdkErrorCrossesAsAConfigurationNamingOnlyItsClass() {
        val m = IllegalStateException("refresh_token=do-not-leak").toErrorMessage()
        assertEquals(ErrorCategoryMessage.CONFIGURATION, m.category)
        assertEquals("invalidConfiguration", m.kind)
        assertEquals("unexpected IllegalStateException", m.detail)
        assertFalse(m.message.contains("do-not-leak"))
        // An SDK error keeps its own mapping through the same entry point.
        assertEquals("grantRejected", VersolaError.Reauthenticate(Reason.GrantRejected).toErrorMessage().kind)
    }

    @Test
    fun sessionStatesMapOneToOne() {
        val states = listOf(
            SessionState.Unauthenticated, SessionState.Authorizing, SessionState.Authenticated, SessionState.Refreshing,
            SessionState.StepUpRequired, SessionState.Locked, SessionState.LoggingOut,
        )
        assertEquals(SessionStateMessage.values().toList(), states.map { it.toMessage() })
    }

    @Test
    fun configurationMessageBuildsTheSdkConfiguration() {
        val c = ConfigurationMessage(
            issuer = "https://id.example.com",
            clientId = "app",
            redirectUri = "https://app.example.com/oauth",
            scopes = listOf("openid", "profile"),
            tokenBinding = TokenBindingMessage.DPOP_REQUIRE_HARDWARE,
            pushedAuthorization = PushedAuthorizationMessage.REQUIRED,
            protectedOrigins = listOf("https://api.example.com"),
            unlockPolicy = UnlockPolicyMessage.NONE,
            clockSkewToleranceSeconds = 30,
        ).toConfiguration()
        assertEquals("https://id.example.com", c.issuerIdentifier)
        assertEquals(setOf("openid", "profile"), c.effectiveScopes)
        assertEquals(TokenBinding.Dpop(requireHardware = true), c.tokenBinding)
        assertEquals(setOf("https://api.example.com"), c.protectedOrigins)
    }
}
