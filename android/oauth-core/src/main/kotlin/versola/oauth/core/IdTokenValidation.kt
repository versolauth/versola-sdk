package versola.oauth.core

import java.security.MessageDigest
import java.time.Instant
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.toJavaDuration
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.doubleOrNull

/**
 * The ID-token checks of OpenID Connect Core 3.1.3.7 and 12.2, in the order of
 * `spec/oauth-sdk-api.md` section 11. Every refusal is `Configuration(IdTokenRejected(reason))`;
 * a provider that cannot be reached for its keys is `Recoverable(Network)` and one that
 * advertises no `jwks_uri` is `Configuration(ProviderUnsupported("jwks_uri"))`, both raised
 * before any claim is read, so a token is never half-judged.
 *
 * Fail closed throughout: nothing here has an off switch, and a claim that is present but of
 * the wrong type is [IdTokenRejection.Malformed] rather than ignored.
 *
 * @param issuer compared byte for byte with `iss`; supplied from discovery, since that is the
 *   value the provider signs tokens under (a configured value may differ by a trailing slash,
 *   which discovery tolerates and this check must not). Not trailing-slash-insensitive like
 *   discovery's check: that one guards where a document was fetched from, this one guards who
 *   signed a token, and a provider that issues `https://a/` and `https://a` is two issuers.
 * @param jwksUri supplier of the `jwks_uri` from discovery, null when it advertises none.
 * @param allowedAlgorithms the provider's `id_token_signing_alg_values_supported`; empty means
 *   it did not say, and the closed asymmetric set alone applies.
 * @param clockSkewTolerance how far the device clock may be from the provider's; applied to
 *   `exp`, `iat` and `auth_time`.
 * @param clock the injected time source (`android-kotlin.md`), never read directly.
 */
@VersolaInternalApi
public class JwksIdTokenValidator(
    private val issuer: suspend () -> String,
    private val clientId: String,
    jwksUri: suspend () -> String?,
    allowedAlgorithms: suspend () -> List<String>,
    jwks: JwksClient,
    private val clockSkewTolerance: Duration = 60.seconds,
    private val clock: () -> Instant = { Instant.now() },
) : IdTokenValidator {

    private val verifier = JwsVerifier(jwksUri, allowedAlgorithms, jwks)

    override suspend fun prepare() {
        verifier.warm()
    }

    override suspend fun validate(
        idToken: String,
        expectedNonce: String?,
        accessToken: String?,
        maxAge: Long?,
        previous: IdTokenClaims?,
        serverTime: Instant?,
    ): IdTokenClaims {
        val token = try {
            verifier.verify(idToken)
        } catch (e: JwsRejection) {
            throw rejected(e.reason)
        }
        try {
            return check(token, expectedNonce, accessToken, maxAge, previous, issuer(), serverTime)
        } catch (e: JwsRejection) {
            throw rejected(e.reason)
        }
    }

    private fun check(
        token: ParsedJws,
        expectedNonce: String?,
        accessToken: String?,
        maxAge: Long?,
        previous: IdTokenClaims?,
        issuer: String,
        serverTime: Instant?,
    ): IdTokenClaims {
        val payload = token.payload
        // The provider's own clock when it has just told us (the token response's `Date`):
        // the token was minted against that clock, so a device clock minutes off does not
        // turn every `iat` into "the future". Otherwise the injected clock.
        val now = serverTime ?: clock()
        val tolerance = clockSkewTolerance.toJavaDuration()

        // Types first, so that a claim of the wrong type is Malformed wherever it sits in the
        // order below; whether a value is acceptable is decided by the checks that follow.
        val iss = payload.text("iss")
        val sub = payload.text("sub") ?: throw JwsRejection(IdTokenRejection.Malformed, "no sub")
        val audience = payload.audience()
        val authorizedParty = payload.text("azp")
        val exp = payload.time("exp") ?: throw JwsRejection(IdTokenRejection.Malformed, "no exp")
        val iat = payload.time("iat")
        val nonce = payload.text("nonce")
        val authTime = payload.time("auth_time")
        val acr = payload.text("acr")
        val amr = payload.textList("amr")
        val atHash = payload.text("at_hash")

        // Core 3.1.3.7 step 2 and 3.
        if (iss != issuer) throw JwsRejection(IdTokenRejection.Issuer, "iss is not the issuer")

        // Steps 3 and 4. azp is checked whenever present, not only with several audiences: the
        // spec's SHOULD costs nothing, and an ID token issued to another party is not for us.
        if (audience == null || clientId !in audience) {
            throw JwsRejection(IdTokenRejection.Audience, "aud does not contain the client id")
        }
        if (audience.size > 1 && authorizedParty == null) {
            throw JwsRejection(IdTokenRejection.Audience, "several audiences and no azp")
        }
        if (authorizedParty != null && authorizedParty != clientId) {
            throw JwsRejection(IdTokenRejection.Audience, "azp is not the client id")
        }

        // Step 9: exp in the future, with the skew tolerance in the token's favour.
        if (!exp.isAfter(now.minus(tolerance))) throw JwsRejection(IdTokenRejection.Expired, "exp has passed")

        // iat must exist and must not lie in the future beyond the tolerance. A token issued
        // "tomorrow" is a clock the provider and the device disagree about, or a forgery.
        // How old it is is bounded by exp rather than by a second window here: providers
        // legitimately return a refreshed token whose iat predates the call by seconds, and an
        // arbitrary age cap would reject them (stated in the PR; one line to tighten).
        if (iat == null) throw JwsRejection(IdTokenRejection.IssuedAt, "no iat")
        if (iat.isAfter(now.plus(tolerance))) throw JwsRejection(IdTokenRejection.IssuedAt, "iat is in the future")

        // Step 11, login only. isEqual on the UTF-8 bytes, not ==: the nonce is a secret the
        // request put on the wire, and an early-exit compare leaks how much of it matched.
        if (expectedNonce != null) {
            if (nonce == null || !constantTimeEquals(nonce, expectedNonce)) {
                throw JwsRejection(IdTokenRejection.Nonce, "nonce is missing or not the request's")
            }
        }

        // Step 12: under max_age, auth_time is required and must be recent enough. The
        // tolerance is added to the window, otherwise max_age=0 could never be met by a login
        // that took a second.
        if (maxAge != null) {
            if (authTime == null) throw JwsRejection(IdTokenRejection.AuthTime, "no auth_time under max_age")
            val oldest = now.minusSeconds(maxAge).minus(tolerance)
            if (authTime.isBefore(oldest)) throw JwsRejection(IdTokenRejection.AuthTime, "auth_time is older than max_age")
        }

        // Refresh (Core 12.2): the new token must be about the same user and no earlier
        // authentication. The enum has no case for a changed subject, so it is Malformed: the
        // token is not a refresh of that session, which is a statement about its shape (it
        // names someone else) rather than about any one claim check. A refresh token swapped
        // to another account's is exactly the case this exists for.
        if (previous != null) {
            if (sub != previous.subject) throw JwsRejection(IdTokenRejection.Malformed, "sub changed on refresh")
            // A refreshed token may omit auth_time (12.2); one that carries it must not
            // claim an earlier authentication than the token it replaces.
            val before = previous.authTime
            if (authTime != null && before != null && authTime.isBefore(before)) {
                throw JwsRejection(IdTokenRejection.AuthTime, "auth_time moved backwards on refresh")
            }
        }

        // Core 3.1.3.6: base64url of the left half of the hash of the access token, the hash
        // being the one the JWS algorithm uses. Optional in the code flow, so absent is fine;
        // present and wrong is not.
        if (atHash != null && accessToken != null) {
            val algorithm = JwsAlgorithm.forName(token.alg!!)!!
            val digest = MessageDigest.getInstance(algorithm.digest).digest(accessToken.toByteArray(Charsets.US_ASCII))
            val expected = Base64Url.encode(digest.copyOfRange(0, digest.size / 2))
            if (!constantTimeEquals(atHash, expected)) {
                throw JwsRejection(IdTokenRejection.AccessTokenHash, "at_hash does not match the access token")
            }
        }

        return IdTokenClaims(
            subject = sub,
            issuer = iss,
            audience = audience,
            issuedAt = iat,
            expiresAt = exp,
            authTime = authTime,
            acr = acr,
            amr = amr ?: emptyList(),
            authorizedParty = authorizedParty,
            // The nonce is spent by this validation and is not exposed (IdTokenClaims KDoc).
            all = payload.filterKeys { it != "nonce" }.mapValues { (_, value) -> value.asText() },
        )
    }

    private fun rejected(reason: IdTokenRejection): VersolaError.Configuration =
        VersolaError.Configuration(VersolaError.Configuration.Detail.IdTokenRejected(reason))
}

private fun constantTimeEquals(a: String, b: String): Boolean =
    MessageDigest.isEqual(a.toByteArray(Charsets.UTF_8), b.toByteArray(Charsets.UTF_8))

/** A claim's JSON value as the string form `IdTokenClaims.all` promises: the content of a string or number, JSON for the rest. */
private fun JsonElement.asText(): String = if (this is JsonPrimitive) content else toString()

/** Absent is null; present but not a string is Malformed. */
private fun JsonObject.text(name: String): String? {
    val value = this[name] ?: return null
    if (value !is JsonPrimitive || !value.isString) throw JwsRejection(IdTokenRejection.Malformed, "$name is not a string")
    return value.content
}

private fun JsonObject.textList(name: String): List<String>? {
    val value = this[name] ?: return null
    if (value !is JsonArray) throw JwsRejection(IdTokenRejection.Malformed, "$name is not an array")
    return value.map {
        if (it !is JsonPrimitive || !it.isString) throw JwsRejection(IdTokenRejection.Malformed, "$name holds a non-string")
        it.content
    }
}

/** `aud` is a string or an array of strings (RFC 7519 4.1.3). */
private fun JsonObject.audience(): List<String>? {
    val value = this["aud"] ?: return null
    return if (value is JsonArray) textList("aud") else listOf(text("aud")!!)
}

/** Seconds since the epoch as a JSON number (RFC 7519 2, NumericDate); a string is not one. */
private fun JsonObject.time(name: String): Instant? {
    val value = this[name] ?: return null
    if (value !is JsonPrimitive || value.isString) throw JwsRejection(IdTokenRejection.Malformed, "$name is not a number")
    val seconds = value.doubleOrNull ?: throw JwsRejection(IdTokenRejection.Malformed, "$name is not a number")
    return Instant.ofEpochMilli((seconds * 1000).toLong())
}
