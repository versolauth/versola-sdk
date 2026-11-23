package versola.oauth.core

import java.security.MessageDigest
import java.time.Instant
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * [TlsTrustedIdTokenValidator]: every claim check of [JwksIdTokenValidator], no signature check.
 * The tokens here carry a signature that is garbage on purpose; the claim cases mirror
 * [IdTokenValidatorTest] so that the two validators cannot drift apart unnoticed.
 */
class TlsTrustedIdTokenValidatorTest {

    private val issuer = "https://issuer.example.com"
    private val clientId = "client-1"
    private val now: Instant = Instant.ofEpochSecond(1_900_000_000)
    private val accessToken = "access-token-example"

    private fun validator(tolerance: kotlin.time.Duration = 60.seconds) = TlsTrustedIdTokenValidator(
        issuer = issuer,
        clientId = clientId,
        clockSkewTolerance = tolerance,
        clock = { now },
    )

    private fun secs(offset: Long): JsonElement = Jose.num(now.epochSecond + offset)

    private fun claims(vararg overrides: Pair<String, JsonElement?>): String {
        val map = linkedMapOf<String, JsonElement?>(
            "iss" to Jose.str(issuer),
            "sub" to Jose.str("user-1"),
            "aud" to Jose.str(clientId),
            "exp" to secs(3600),
            "iat" to secs(-10),
            "nonce" to Jose.str("nonce-1"),
        )
        for ((name, value) in overrides) map[name] = value
        return Jose.json(map.filterValues { it != null }.mapValues { it.value!! })
    }

    /** A token whose signature is not one: the validator under test must not look at it. */
    private fun token(vararg overrides: Pair<String, JsonElement?>, alg: String = "ES256") =
        Jose.b64("""{"alg":"$alg","typ":"JWT"}""") + "." + Jose.b64(claims(*overrides)) + "." + Jose.b64("not a signature")

    private suspend fun validate(
        token: String,
        nonce: String? = "nonce-1",
        access: String? = accessToken,
        maxAge: Long? = null,
        previous: IdTokenClaims? = null,
        validator: TlsTrustedIdTokenValidator = validator(),
    ): IdTokenClaims = validator.validate(token, nonce, access, maxAge, previous)

    private suspend fun rejection(block: suspend () -> Unit): IdTokenRejection {
        val error = runCatching { block() }.exceptionOrNull() ?: throw AssertionError("expected a failure")
        val configuration = error as? VersolaError.Configuration ?: throw AssertionError("not Configuration: $error")
        val detail = configuration.detail as? VersolaError.Configuration.Detail.IdTokenRejected
            ?: throw AssertionError("not IdTokenRejected: ${configuration.detail}")
        return detail.reason
    }

    private fun atHash(algorithm: String, access: String): String {
        val digest = MessageDigest.getInstance(algorithm).digest(access.toByteArray(Charsets.US_ASCII))
        return Jose.b64(digest.copyOfRange(0, digest.size / 2))
    }

    private fun previous(subject: String = "user-1", authTime: Instant? = null) = IdTokenClaims(
        subject = subject,
        issuer = issuer,
        audience = listOf(clientId),
        issuedAt = now.minusSeconds(1000),
        expiresAt = now.plusSeconds(1000),
        authTime = authTime,
    )

    // --- the point: no signature check ------------------------------------------------------

    @Test
    fun `a well-formed token with a garbage signature validates, because TLS stands in for the signature`() = runTest {
        val claims = validate(token("auth_time" to secs(-100), "acr" to Jose.str("urn:acr:2")))

        assertEquals("user-1", claims.subject)
        assertEquals(issuer, claims.issuer)
        assertEquals(listOf(clientId), claims.audience)
        assertEquals(now.minusSeconds(100), claims.authTime)
        assertEquals("urn:acr:2", claims.acr)
        assertNull(claims.authorizedParty)
    }

    @Test
    fun `a token with an empty signature validates too`() = runTest {
        val unsigned = Jose.b64("""{"alg":"ES256"}""") + "." + Jose.b64(claims()) + "."

        assertEquals("user-1", validate(unsigned).subject)
    }

    // --- algorithm --------------------------------------------------------------------------

    @Test
    fun `alg none is refused as Algorithm`() = runTest {
        assertEquals(IdTokenRejection.Algorithm, rejection { validate(token(alg = "none")) })
    }

    @Test
    fun `alg none in any case is refused as Algorithm`() = runTest {
        for (alg in listOf("None", "NONE", "nOnE")) {
            assertEquals(alg, IdTokenRejection.Algorithm, rejection { validate(token(alg = alg)) })
        }
    }

    @Test
    fun `alg none with an empty signature is refused as Algorithm and not as a malformed token`() = runTest {
        val unsigned = Jose.jws("none", null, claims())

        assertEquals(IdTokenRejection.Algorithm, rejection { validate(unsigned) })
    }

    // --- iss, aud, azp ----------------------------------------------------------------------

    @Test
    fun `a different iss is refused as Issuer`() = runTest {
        assertEquals(IdTokenRejection.Issuer, rejection { validate(token("iss" to Jose.str("https://evil.example.com"))) })
    }

    @Test
    fun `an iss differing only by a trailing slash is refused as Issuer`() = runTest {
        assertEquals(IdTokenRejection.Issuer, rejection { validate(token("iss" to Jose.str("$issuer/"))) })
    }

    @Test
    fun `a missing iss is refused as Issuer`() = runTest {
        assertEquals(IdTokenRejection.Issuer, rejection { validate(token("iss" to null)) })
    }

    @Test
    fun `the issuer is the one the validator was built with, whatever the token says it is`() = runTest {
        val other = TlsTrustedIdTokenValidator("https://other.example.com", clientId, clock = { now })

        assertEquals(IdTokenRejection.Issuer, rejection { validate(token(), validator = other) })
    }

    @Test
    fun `an aud without the client id is refused as Audience`() = runTest {
        assertEquals(IdTokenRejection.Audience, rejection { validate(token("aud" to Jose.str("another-client"))) })
    }

    @Test
    fun `a missing aud is refused as Audience`() = runTest {
        assertEquals(IdTokenRejection.Audience, rejection { validate(token("aud" to null)) })
    }

    @Test
    fun `several audiences without azp are refused as Audience`() = runTest {
        val aud = JsonArray(listOf(Jose.str(clientId), Jose.str("other")))

        assertEquals(IdTokenRejection.Audience, rejection { validate(token("aud" to aud)) })
    }

    @Test
    fun `an azp that is not the client id is refused as Audience`() = runTest {
        val aud = JsonArray(listOf(Jose.str(clientId), Jose.str("other")))

        assertEquals(IdTokenRejection.Audience, rejection { validate(token("aud" to aud, "azp" to Jose.str("other"))) })
        assertEquals(IdTokenRejection.Audience, rejection { validate(token("azp" to Jose.str("other"))) })
    }

    @Test
    fun `several audiences with azp equal to the client id validate`() = runTest {
        val aud = JsonArray(listOf(Jose.str(clientId), Jose.str("other")))

        val claims = validate(token("aud" to aud, "azp" to Jose.str(clientId)))

        assertEquals(clientId, claims.authorizedParty)
    }

    // --- exp, iat, nbf ----------------------------------------------------------------------

    @Test
    fun `an exp beyond the tolerance in the past is refused as Expired`() = runTest {
        assertEquals(IdTokenRejection.Expired, rejection { validate(token("exp" to secs(-61))) })
        assertEquals(IdTokenRejection.Expired, rejection { validate(token("exp" to secs(-60))) })
    }

    @Test
    fun `an exp inside the tolerance still validates`() = runTest {
        assertEquals("user-1", validate(token("exp" to secs(-59))).subject)
    }

    @Test
    fun `a missing iat is refused as IssuedAt`() = runTest {
        assertEquals(IdTokenRejection.IssuedAt, rejection { validate(token("iat" to null)) })
    }

    @Test
    fun `an iat in the future beyond the tolerance is refused as IssuedAt`() = runTest {
        assertEquals(IdTokenRejection.IssuedAt, rejection { validate(token("iat" to secs(61))) })
    }

    @Test
    fun `an iat in the future inside the tolerance validates`() = runTest {
        assertEquals("user-1", validate(token("iat" to secs(59))).subject)
    }

    @Test
    fun `an nbf in the future beyond the tolerance is refused as IssuedAt`() = runTest {
        assertEquals(IdTokenRejection.IssuedAt, rejection { validate(token("nbf" to secs(61))) })
    }

    // --- nonce ------------------------------------------------------------------------------

    @Test
    fun `a nonce that differs from the request's is refused as Nonce`() = runTest {
        assertEquals(IdTokenRejection.Nonce, rejection { validate(token("nonce" to Jose.str("nonce-2"))) })
        assertEquals(IdTokenRejection.Nonce, rejection { validate(token("nonce" to Jose.str("nonce-"))) })
    }

    @Test
    fun `a missing nonce when one was sent is refused as Nonce`() = runTest {
        assertEquals(IdTokenRejection.Nonce, rejection { validate(token("nonce" to null)) })
    }

    @Test
    fun `no nonce is required on a refresh`() = runTest {
        assertEquals("user-1", validate(token("nonce" to null), nonce = null, previous = previous()).subject)
    }

    // --- auth_time under max_age ------------------------------------------------------------

    @Test
    fun `an auth_time older than max_age is refused as AuthTime`() = runTest {
        assertEquals(IdTokenRejection.AuthTime, rejection { validate(token("auth_time" to secs(-361)), maxAge = 300) })
    }

    @Test
    fun `a missing auth_time under max_age is refused as AuthTime`() = runTest {
        assertEquals(IdTokenRejection.AuthTime, rejection { validate(token(), maxAge = 300) })
    }

    @Test
    fun `an auth_time within max_age validates, and none is required without max_age`() = runTest {
        assertEquals("user-1", validate(token("auth_time" to secs(-100)), maxAge = 300).subject)
        assertEquals("user-1", validate(token()).subject)
    }

    @Test
    fun `a refresh whose auth_time moved backwards is refused as AuthTime`() = runTest {
        val reason = rejection {
            validate(token("auth_time" to secs(-500)), nonce = null, previous = previous(authTime = now.minusSeconds(100)))
        }

        assertEquals(IdTokenRejection.AuthTime, reason)
    }

    // --- at_hash ----------------------------------------------------------------------------

    @Test
    fun `an at_hash that is the left half of the digest of the access token validates`() = runTest {
        val claims = validate(token("at_hash" to Jose.str(atHash("SHA-256", accessToken))))

        assertEquals(atHash("SHA-256", accessToken), claims.all["at_hash"])
    }

    @Test
    fun `an at_hash of another access token is refused as AccessTokenHash`() = runTest {
        val reason = rejection { validate(token("at_hash" to Jose.str(atHash("SHA-256", "another-token")))) }

        assertEquals(IdTokenRejection.AccessTokenHash, reason)
    }

    @Test
    fun `an at_hash computed with the wrong digest for the algorithm is refused as AccessTokenHash`() = runTest {
        val reason = rejection { validate(token("at_hash" to Jose.str(atHash("SHA-384", accessToken)))) }

        assertEquals(IdTokenRejection.AccessTokenHash, reason)
    }

    @Test
    fun `an at_hash under an algorithm that names no digest is refused as Algorithm and not passed`() = runTest {
        // Nothing verified the algorithm here, so a name outside the closed set can reach the
        // at_hash check; a claim that cannot be checked is a refusal.
        val reason = rejection { validate(token("at_hash" to Jose.str("anything"), alg = "HS256")) }

        assertEquals(IdTokenRejection.Algorithm, reason)
    }

    @Test
    fun `an at_hash is not checked when no access token was issued`() = runTest {
        assertEquals("user-1", validate(token("at_hash" to Jose.str("anything")), access = null).subject)
    }

    // --- sub on refresh, shape --------------------------------------------------------------

    @Test
    fun `a refresh whose sub changed is refused as Malformed`() = runTest {
        val reason = rejection { validate(token(), nonce = null, previous = previous(subject = "user-2")) }

        assertEquals(IdTokenRejection.Malformed, reason)
    }

    @Test
    fun `a refresh with the same sub validates`() = runTest {
        assertEquals("user-1", validate(token(), nonce = null, previous = previous()).subject)
    }

    @Test
    fun `a string that is not three segments is refused as Malformed`() = runTest {
        for (text in listOf("not-a-jwt", "a.b", "a.b.c.d", "")) {
            assertEquals(text, IdTokenRejection.Malformed, rejection { validate(text) })
        }
    }

    @Test
    fun `a missing sub or exp is refused as Malformed`() = runTest {
        assertEquals(IdTokenRejection.Malformed, rejection { validate(token("sub" to null)) })
        assertEquals(IdTokenRejection.Malformed, rejection { validate(token("exp" to null)) })
    }

    @Test
    fun `the claim checks run on a token the key-set validator would have refused for its signature`() = runTest {
        // Wrong issuer AND a bad signature: here the issuer is the first refusal, there is no signature to fail.
        assertEquals(IdTokenRejection.Issuer, rejection { validate(token("iss" to Jose.str("https://evil.example.com"))) })
    }
}
