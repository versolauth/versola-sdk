package versola.oauth.core

import java.security.KeyPair
import java.security.MessageDigest
import java.time.Instant
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class IdTokenValidatorTest {

    private val issuer = "https://issuer.example.com"
    private val clientId = "client-1"
    private val now: Instant = Instant.ofEpochSecond(1_900_000_000)
    private val accessToken = "access-token-example"

    private lateinit var server: MockWebServer
    private lateinit var uri: String

    @Before
    fun start() {
        server = MockWebServer()
        server.start()
        uri = server.url("/jwks.json").toString()
    }

    @After
    fun stop() {
        server.close()
    }

    private val jwksDocument = Jose.jwks(
        Jose.jwk(Jose.rsa, "rsa"),
        Jose.jwk(Jose.p256, "p256"),
        Jose.jwk(Jose.p384, "p384"),
        Jose.jwk(Jose.p521, "p521"),
    )

    private fun serve(body: String = jwksDocument) {
        server.enqueue(MockResponse.Builder().code(200).body(body).build())
    }

    private fun validator(
        allowed: List<String> = emptyList(),
        jwksUri: String? = uri,
        tolerance: kotlin.time.Duration = 60.seconds,
        jwks: JwksClient = JwksClient(OkHttpClient()),
    ) = JwksIdTokenValidator(
        issuer = issuer,
        clientId = clientId,
        jwksUri = { jwksUri },
        allowedAlgorithms = { allowed },
        jwks = jwks,
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

    private fun rsToken(vararg overrides: Pair<String, JsonElement?>) =
        Jose.jws("RS256", Jose.rsa.private, claims(*overrides), kid = "rsa")

    private suspend fun validate(
        token: String,
        nonce: String? = "nonce-1",
        access: String? = accessToken,
        maxAge: Long? = null,
        previous: IdTokenClaims? = null,
        validator: JwksIdTokenValidator = validator(),
    ): IdTokenClaims = validator.validate(token, nonce, access, maxAge, previous)

    private suspend fun rejection(block: suspend () -> Unit): IdTokenRejection {
        val error = failure(block)
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

    // --- positive, one per algorithm family -------------------------------------------------

    @Test
    fun `an RS256 token with matching claims validates and yields typed claims`() = runTest {
        serve()
        val token = rsToken(
            "auth_time" to secs(-100),
            "acr" to Jose.str("urn:mace:incommon:iap:silver"),
            "amr" to JsonArray(listOf(Jose.str("pwd"), Jose.str("otp"))),
        )

        val claims = validate(token)

        assertEquals("user-1", claims.subject)
        assertEquals(issuer, claims.issuer)
        assertEquals(listOf(clientId), claims.audience)
        assertEquals(now.plusSeconds(3600), claims.expiresAt)
        assertEquals(now.minusSeconds(10), claims.issuedAt)
        assertEquals(now.minusSeconds(100), claims.authTime)
        assertEquals("urn:mace:incommon:iap:silver", claims.acr)
        assertEquals(listOf("pwd", "otp"), claims.amr)
        assertNull(claims.authorizedParty)
    }

    @Test
    fun `PS256 PS384 and PS512 tokens validate`() = runTest {
        serve()
        val jwks = JwksClient(OkHttpClient())
        for (alg in listOf("PS256", "PS384", "PS512")) {
            val token = Jose.jws(alg, Jose.rsa.private, claims(), kid = "rsa")
            assertEquals(alg, "user-1", validate(token, validator = validator(jwks = jwks)).subject)
        }
    }

    @Test
    fun `RS384 and RS512 tokens validate`() = runTest {
        serve()
        val jwks = JwksClient(OkHttpClient())
        for (alg in listOf("RS384", "RS512")) {
            val token = Jose.jws(alg, Jose.rsa.private, claims(), kid = "rsa")
            assertEquals(alg, "user-1", validate(token, validator = validator(jwks = jwks)).subject)
        }
    }

    @Test
    fun `ES256 ES384 and ES512 tokens validate`() = runTest {
        serve()
        val jwks = JwksClient(OkHttpClient())
        val cases: List<Triple<String, KeyPair, String>> = listOf(
            Triple("ES256", Jose.p256, "p256"),
            Triple("ES384", Jose.p384, "p384"),
            Triple("ES512", Jose.p521, "p521"),
        )
        for ((alg, key, kid) in cases) {
            val token = Jose.jws(alg, key.private, claims(), kid = kid)
            assertEquals(alg, "user-1", validate(token, validator = validator(jwks = jwks)).subject)
        }
    }

    @Test
    fun `a token without a kid validates against the only key of its type`() = runTest {
        serve(Jose.jwks(Jose.jwk(Jose.rsa, "only-rsa"), Jose.jwk(Jose.p256, "an-ec-key")))

        val token = Jose.jws("RS256", Jose.rsa.private, claims(), kid = null)

        assertEquals("user-1", validate(token).subject)
    }

    @Test
    fun `an algorithm the provider advertises is accepted`() = runTest {
        serve()

        val claims = validate(rsToken(), validator = validator(allowed = listOf("ES256", "RS256")))

        assertEquals("user-1", claims.subject)
    }

    @Test
    fun `all holds every claim as its string form and leaves the nonce out`() = runTest {
        serve()
        val token = rsToken(
            "email_verified" to JsonPrimitive(true),
            "amr" to JsonArray(listOf(Jose.str("pwd"))),
            "custom_number" to JsonPrimitive(42),
        )

        val all = validate(token).all

        assertEquals("user-1", all["sub"])
        assertEquals(issuer, all["iss"])
        assertEquals("true", all["email_verified"])
        assertEquals("42", all["custom_number"])
        assertEquals("""["pwd"]""", all["amr"])
        assertEquals("${now.epochSecond + 3600}", all["exp"])
        assertNull(all["nonce"])
    }

    // --- Algorithm ---------------------------------------------------------------------------

    @Test
    fun `alg none is refused as Algorithm without a network request`() = runTest {
        val token = Jose.jws("none", null, claims(), kid = "rsa")

        assertEquals(IdTokenRejection.Algorithm, rejection { validate(token) })
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `HS256 is refused as Algorithm without a network request`() = runTest {
        // The key-confusion attack: an HMAC keyed with the provider's public key bytes.
        val header = """{"alg":"HS256","typ":"JWT","kid":"rsa"}"""
        val input = Jose.b64(header) + "." + Jose.b64(claims())
        val mac = javax.crypto.Mac.getInstance("HmacSHA256").apply {
            init(javax.crypto.spec.SecretKeySpec(Jose.rsa.public.encoded, "HmacSHA256"))
        }.doFinal(input.toByteArray())
        val token = input + "." + Jose.b64(mac)

        assertEquals(IdTokenRejection.Algorithm, rejection { validate(token) })
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `HS384 and HS512 are refused as Algorithm`() = runTest {
        for (alg in listOf("HS384", "HS512")) {
            val token = Jose.jws(alg, null, claims(), header = """{"alg":"$alg"}""")
            assertEquals(alg, IdTokenRejection.Algorithm, rejection { validate(token) })
        }
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `an algorithm outside the closed set is refused as Algorithm`() = runTest {
        val token = Jose.jws("ES256K", null, claims(), header = """{"alg":"ES256K"}""")

        assertEquals(IdTokenRejection.Algorithm, rejection { validate(token) })
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `an algorithm the provider does not advertise is refused as Algorithm without a network request`() = runTest {
        val token = rsToken()

        val reason = rejection { validate(token, validator = validator(allowed = listOf("ES256"))) }

        assertEquals(IdTokenRejection.Algorithm, reason)
        assertEquals(0, server.requestCount)
    }

    // --- Signature and key selection ---------------------------------------------------------

    @Test
    fun `a signature made by another key under the same kid is refused as Signature`() = runTest {
        serve()
        val token = Jose.jws("RS256", Jose.rsaOther.private, claims(), kid = "rsa")

        assertEquals(IdTokenRejection.Signature, rejection { validate(token) })
    }

    @Test
    fun `a payload altered after signing is refused as Signature`() = runTest {
        serve()
        val parts = rsToken().split('.')
        val forged = parts[0] + "." + Jose.b64(claims("sub" to Jose.str("admin"))) + "." + parts[2]

        assertEquals(IdTokenRejection.Signature, rejection { validate(forged) })
    }

    @Test
    fun `a kid naming a key of another type is refused as Signature`() = runTest {
        serve()
        val token = Jose.jws("ES256", Jose.p256.private, claims(), kid = "rsa")

        assertEquals(IdTokenRejection.Signature, rejection { validate(token) })
    }

    @Test
    fun `an unknown kid refetches the key set exactly once and a rotated-in key then validates`() = runTest {
        val jwks = JwksClient(OkHttpClient())
        serve(Jose.jwks(Jose.jwk(Jose.rsa, "rsa")))
        validate(rsToken(), validator = validator(jwks = jwks))
        assertEquals(1, server.requestCount)

        serve(Jose.jwks(Jose.jwk(Jose.rsa, "rsa"), Jose.jwk(Jose.rsaOther, "rotated")))
        val token = Jose.jws("RS256", Jose.rsaOther.private, claims(), kid = "rotated")
        val claims = validate(token, validator = validator(jwks = jwks))

        assertEquals("user-1", claims.subject)
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `a second unknown kid after the refetch is Signature and no third request is made`() = runTest {
        val jwks = JwksClient(OkHttpClient())
        serve(Jose.jwks(Jose.jwk(Jose.rsa, "rsa")))
        validate(rsToken(), validator = validator(jwks = jwks))
        serve(Jose.jwks(Jose.jwk(Jose.rsa, "rsa")))
        // A third response is queued so that a loop would be seen as a request, not a hang.
        serve(Jose.jwks(Jose.jwk(Jose.rsa, "rsa")))
        val token = Jose.jws("RS256", Jose.rsaOther.private, claims(), kid = "unknown")

        val reason = rejection { validate(token, validator = validator(jwks = jwks)) }

        assertEquals(IdTokenRejection.Signature, reason)
        assertEquals(2, server.requestCount)
    }

    @Test
    fun `an unknown kid on a cold cache costs one request not two`() = runTest {
        serve(Jose.jwks(Jose.jwk(Jose.rsa, "rsa")))
        serve(Jose.jwks(Jose.jwk(Jose.rsa, "rsa")))
        val token = Jose.jws("RS256", Jose.rsaOther.private, claims(), kid = "unknown")

        val reason = rejection { validate(token) }

        assertEquals(IdTokenRejection.Signature, reason)
        assertEquals(1, server.requestCount)
    }

    @Test
    fun `a token without a kid is refused when several keys of its type could have signed it`() = runTest {
        serve(Jose.jwks(Jose.jwk(Jose.rsa, "a"), Jose.jwk(Jose.rsaOther, "b")))
        val token = Jose.jws("RS256", Jose.rsa.private, claims(), kid = null)

        assertEquals(IdTokenRejection.Signature, rejection { validate(token) })
    }

    @Test
    fun `a key marked for encryption or pinned to another algorithm is not used`() = runTest {
        serve(Jose.jwks(Jose.jwk(Jose.rsa, "rsa", extra = "\"use\":\"enc\"")))
        assertEquals(IdTokenRejection.Signature, rejection { validate(rsToken()) })

        val pinned = JwksClient(OkHttpClient())
        serve(Jose.jwks(Jose.jwk(Jose.rsa, "rsa", alg = "RS512")))
        assertEquals(IdTokenRejection.Signature, rejection { validate(rsToken(), validator = validator(jwks = pinned)) })
    }

    @Test
    fun `a provider without a jwks_uri is ProviderUnsupported and nothing is fetched`() = runTest {
        val error = failure { validate(rsToken(), validator = validator(jwksUri = null)) }

        val configuration = error as VersolaError.Configuration
        assertEquals(
            VersolaError.Configuration.Detail.ProviderUnsupported("jwks_uri"),
            configuration.detail,
        )
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `an unreachable jwks_uri is a Network failure and not a rejection`() = runTest {
        val dead = uri
        server.close()

        val error = failure { validate(rsToken(), validator = validator(jwksUri = dead)) }

        val recoverable = error as VersolaError.Recoverable
        assertTrue(recoverable.reason is VersolaError.Recoverable.Cause.Network)
    }

    // --- iss, aud ----------------------------------------------------------------------------

    @Test
    fun `a different iss is refused as Issuer`() = runTest {
        serve()

        assertEquals(IdTokenRejection.Issuer, rejection { validate(rsToken("iss" to Jose.str("https://evil.example.com"))) })
    }

    @Test
    fun `an iss differing only by a trailing slash is refused as Issuer`() = runTest {
        serve()

        assertEquals(IdTokenRejection.Issuer, rejection { validate(rsToken("iss" to Jose.str("$issuer/"))) })
    }

    @Test
    fun `a missing iss is refused as Issuer`() = runTest {
        serve()

        assertEquals(IdTokenRejection.Issuer, rejection { validate(rsToken("iss" to null)) })
    }

    @Test
    fun `an aud without the client id is refused as Audience`() = runTest {
        serve()

        assertEquals(IdTokenRejection.Audience, rejection { validate(rsToken("aud" to Jose.str("another-client"))) })
    }

    @Test
    fun `a missing aud is refused as Audience`() = runTest {
        serve()

        assertEquals(IdTokenRejection.Audience, rejection { validate(rsToken("aud" to null)) })
    }

    @Test
    fun `several audiences without azp are refused as Audience`() = runTest {
        serve()
        val aud = JsonArray(listOf(Jose.str(clientId), Jose.str("other")))

        assertEquals(IdTokenRejection.Audience, rejection { validate(rsToken("aud" to aud)) })
    }

    @Test
    fun `several audiences with an azp that is not the client id are refused as Audience`() = runTest {
        serve()
        val aud = JsonArray(listOf(Jose.str(clientId), Jose.str("other")))

        val reason = rejection { validate(rsToken("aud" to aud, "azp" to Jose.str("other"))) }

        assertEquals(IdTokenRejection.Audience, reason)
    }

    @Test
    fun `several audiences with azp equal to the client id validate`() = runTest {
        serve()
        val aud = JsonArray(listOf(Jose.str("other"), Jose.str(clientId)))

        val claims = validate(rsToken("aud" to aud, "azp" to Jose.str(clientId)))

        assertEquals(listOf("other", clientId), claims.audience)
        assertEquals(clientId, claims.authorizedParty)
    }

    @Test
    fun `a single audience in an array validates without azp`() = runTest {
        serve()

        val claims = validate(rsToken("aud" to JsonArray(listOf(Jose.str(clientId)))))

        assertEquals(listOf(clientId), claims.audience)
    }

    @Test
    fun `an azp that is not the client id is refused as Audience even with one audience`() = runTest {
        serve()

        assertEquals(IdTokenRejection.Audience, rejection { validate(rsToken("azp" to Jose.str("other"))) })
    }

    // --- exp, iat ----------------------------------------------------------------------------

    @Test
    fun `an exp beyond the tolerance in the past is refused as Expired`() = runTest {
        serve()

        assertEquals(IdTokenRejection.Expired, rejection { validate(rsToken("exp" to secs(-61))) })
    }

    @Test
    fun `an exp exactly at now minus the tolerance is refused as Expired`() = runTest {
        serve()

        assertEquals(IdTokenRejection.Expired, rejection { validate(rsToken("exp" to secs(-60))) })
    }

    @Test
    fun `an exp inside the tolerance still validates`() = runTest {
        serve()

        assertEquals("user-1", validate(rsToken("exp" to secs(-59))).subject)
    }

    @Test
    fun `a missing iat is refused as IssuedAt`() = runTest {
        serve()

        assertEquals(IdTokenRejection.IssuedAt, rejection { validate(rsToken("iat" to null)) })
    }

    @Test
    fun `an iat in the future beyond the tolerance is refused as IssuedAt`() = runTest {
        serve()

        assertEquals(IdTokenRejection.IssuedAt, rejection { validate(rsToken("iat" to secs(61))) })
    }

    @Test
    fun `an iat in the future inside the tolerance validates`() = runTest {
        serve()

        assertEquals("user-1", validate(rsToken("iat" to secs(60))).subject)
    }

    @Test
    fun `a zero tolerance makes the clock exact`() = runTest {
        serve()
        val exact = validator(tolerance = 0.seconds)

        assertEquals(IdTokenRejection.IssuedAt, rejection { validate(rsToken("iat" to secs(1)), validator = exact) })
        assertEquals(IdTokenRejection.Expired, rejection { validate(rsToken("exp" to secs(0)), validator = exact) })
    }

    // --- nonce -------------------------------------------------------------------------------

    @Test
    fun `a nonce that differs from the request's is refused as Nonce`() = runTest {
        serve()

        assertEquals(IdTokenRejection.Nonce, rejection { validate(rsToken("nonce" to Jose.str("nonce-2"))) })
    }

    @Test
    fun `a nonce that is a prefix of the request's is refused as Nonce`() = runTest {
        serve()

        assertEquals(IdTokenRejection.Nonce, rejection { validate(rsToken("nonce" to Jose.str("nonce-"))) })
    }

    @Test
    fun `a missing nonce when one was sent is refused as Nonce`() = runTest {
        serve()

        assertEquals(IdTokenRejection.Nonce, rejection { validate(rsToken("nonce" to null)) })
    }

    @Test
    fun `no nonce is required on a refresh`() = runTest {
        serve()

        val claims = validate(rsToken("nonce" to null), nonce = null, previous = previous())

        assertEquals("user-1", claims.subject)
    }

    // --- auth_time and max_age ---------------------------------------------------------------

    @Test
    fun `a missing auth_time under max_age is refused as AuthTime`() = runTest {
        serve()

        assertEquals(IdTokenRejection.AuthTime, rejection { validate(rsToken(), maxAge = 300) })
    }

    @Test
    fun `an auth_time older than max_age is refused as AuthTime`() = runTest {
        serve()

        val reason = rejection { validate(rsToken("auth_time" to secs(-361)), maxAge = 300) }

        assertEquals(IdTokenRejection.AuthTime, reason)
    }

    @Test
    fun `an auth_time within max_age validates`() = runTest {
        serve()

        val claims = validate(rsToken("auth_time" to secs(-200)), maxAge = 300)

        assertEquals(now.minusSeconds(200), claims.authTime)
    }

    @Test
    fun `max_age zero is met by a login that happened moments ago`() = runTest {
        serve()

        assertEquals("user-1", validate(rsToken("auth_time" to secs(-2)), maxAge = 0).subject)
    }

    @Test
    fun `an auth_time is not required without max_age`() = runTest {
        serve()

        assertNull(validate(rsToken()).authTime)
    }

    // --- refresh -----------------------------------------------------------------------------

    @Test
    fun `a refresh whose sub changed is refused as Malformed`() = runTest {
        serve()

        val reason = rejection { validate(rsToken(), nonce = null, previous = previous(subject = "user-2")) }

        assertEquals(IdTokenRejection.Malformed, reason)
    }

    @Test
    fun `a refresh whose auth_time moved backwards is refused as AuthTime`() = runTest {
        serve()
        val before = previous(authTime = now.minusSeconds(500))

        val reason = rejection { validate(rsToken("auth_time" to secs(-600)), nonce = null, previous = before) }

        assertEquals(IdTokenRejection.AuthTime, reason)
    }

    @Test
    fun `a refresh with an unchanged or later auth_time validates`() = runTest {
        serve()
        val before = previous(authTime = now.minusSeconds(500))
        val jwks = JwksClient(OkHttpClient())

        val same = validate(rsToken("auth_time" to secs(-500)), nonce = null, previous = before, validator = validator(jwks = jwks))
        val later = validate(rsToken("auth_time" to secs(-100)), nonce = null, previous = before, validator = validator(jwks = jwks))

        assertEquals(now.minusSeconds(500), same.authTime)
        assertEquals(now.minusSeconds(100), later.authTime)
    }

    @Test
    fun `a refresh that omits auth_time validates`() = runTest {
        serve()

        val claims = validate(rsToken(), nonce = null, previous = previous(authTime = now.minusSeconds(500)))

        assertNull(claims.authTime)
    }

    // --- at_hash -----------------------------------------------------------------------------

    @Test
    fun `an RS256 at_hash that is the left half of SHA-256 of the access token validates`() = runTest {
        serve()

        val claims = validate(rsToken("at_hash" to Jose.str(atHash("SHA-256", accessToken))))

        assertEquals(atHash("SHA-256", accessToken), claims.all["at_hash"])
    }

    @Test
    fun `an RS256 at_hash of another access token is refused as AccessTokenHash`() = runTest {
        serve()

        val reason = rejection { validate(rsToken("at_hash" to Jose.str(atHash("SHA-256", "another-token")))) }

        assertEquals(IdTokenRejection.AccessTokenHash, reason)
    }

    @Test
    fun `an RS256 at_hash computed with SHA-384 is refused as AccessTokenHash`() = runTest {
        serve()

        val reason = rejection { validate(rsToken("at_hash" to Jose.str(atHash("SHA-384", accessToken)))) }

        assertEquals(IdTokenRejection.AccessTokenHash, reason)
    }

    @Test
    fun `an ES384 at_hash is the left half of SHA-384 of the access token`() = runTest {
        serve()
        fun token(hash: String) = Jose.jws(
            "ES384",
            Jose.p384.private,
            claims("at_hash" to Jose.str(hash)),
            kid = "p384",
        )
        val jwks = JwksClient(OkHttpClient())

        val claims = validate(token(atHash("SHA-384", accessToken)), validator = validator(jwks = jwks))
        val reason = rejection { validate(token(atHash("SHA-256", accessToken)), validator = validator(jwks = jwks)) }

        assertEquals("user-1", claims.subject)
        assertEquals(IdTokenRejection.AccessTokenHash, reason)
    }

    @Test
    fun `an at_hash is not checked when no access token was issued`() = runTest {
        serve()

        val claims = validate(rsToken("at_hash" to Jose.str("anything")), access = null)

        assertEquals("user-1", claims.subject)
    }

    @Test
    fun `a token without at_hash validates`() = runTest {
        serve()

        assertEquals("user-1", validate(rsToken()).subject)
    }

    // --- Malformed ---------------------------------------------------------------------------

    @Test
    fun `a string that is not a JWS is refused as Malformed without a network request`() = runTest {
        assertEquals(IdTokenRejection.Malformed, rejection { validate("not-a-jwt") })
        assertEquals(0, server.requestCount)
    }

    @Test
    fun `a missing sub is refused as Malformed`() = runTest {
        serve()

        assertEquals(IdTokenRejection.Malformed, rejection { validate(rsToken("sub" to null)) })
    }

    @Test
    fun `a missing exp is refused as Malformed`() = runTest {
        serve()

        assertEquals(IdTokenRejection.Malformed, rejection { validate(rsToken("exp" to null)) })
    }

    @Test
    fun `an exp given as a string is refused as Malformed`() = runTest {
        serve()

        assertEquals(IdTokenRejection.Malformed, rejection { validate(rsToken("exp" to Jose.str("1900000000"))) })
    }

    @Test
    fun `an aud of the wrong type is refused as Malformed`() = runTest {
        serve()

        assertEquals(IdTokenRejection.Malformed, rejection { validate(rsToken("aud" to Jose.num(5))) })
    }

    @Test
    fun `claims are not read before the signature is verified`() = runTest {
        serve()
        // Wrong issuer AND a bad signature: the signature is the first refusal.
        val token = Jose.jws("RS256", Jose.rsaOther.private, claims("iss" to Jose.str("https://evil.example.com")), kid = "rsa")

        assertEquals(IdTokenRejection.Signature, rejection { validate(token) })
    }
}
