package versola.oauth.core

import java.time.Instant
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive

/**
 * The claims of a validated ID token (OpenID Connect Core 2). Standard claims are typed; every
 * claim, standard or not, is in [all] as the JSON value's string form, or as JSON for an object
 * or array. The raw token and the `nonce` are deliberately not here: the raw token is stored
 * encrypted for `id_token_hint` only, and the nonce is spent by validation.
 */
public class IdTokenClaims(
    public val subject: String,
    public val issuer: String,
    public val audience: List<String>,
    public val issuedAt: Instant,
    public val expiresAt: Instant,
    public val authTime: Instant? = null,
    public val acr: String? = null,
    public val amr: List<String> = emptyList(),
    public val authorizedParty: String? = null,
    public val all: Map<String, String> = emptyMap(),
) {
    /** The subject is a user identifier; it stays out of logs like every other one. */
    override fun toString(): String = "IdTokenClaims(issuer=$issuer, subject=redacted)"

    public companion object {
        /**
         * The claims of an ID token that was validated before it was stored, read back without
         * re-verifying: after process death a stored grant restores `Authenticated`, and the
         * app's `claims` and the refresh check against the previous `sub` need the values the
         * token carried. Nothing here is trusted beyond what the original validation proved;
         * `exp` of an ID token says nothing about the session. Null when the token no longer
         * parses, which a store that only holds what the SDK wrote never produces.
         */
        @VersolaInternalApi
        public fun ofStored(idToken: String): IdTokenClaims? {
            val payload = try {
                Jws.parse(idToken).payload
            } catch (e: Exception) {
                return null
            }
            fun text(name: String): String? = (payload[name] as? JsonPrimitive)?.takeIf { it.isString }?.content
            fun time(name: String): Instant? = (payload[name] as? JsonPrimitive)?.content?.toDoubleOrNull()
                ?.let { Instant.ofEpochMilli((it * 1000).toLong()) }
            fun list(name: String): List<String> = when (val value = payload[name]) {
                is JsonArray -> value.mapNotNull { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content }
                is JsonPrimitive -> listOfNotNull(value.takeIf { it.isString }?.content)
                else -> emptyList()
            }
            return IdTokenClaims(
                subject = text("sub") ?: return null,
                issuer = text("iss") ?: return null,
                audience = list("aud"),
                issuedAt = time("iat") ?: Instant.EPOCH,
                expiresAt = time("exp") ?: Instant.EPOCH,
                authTime = time("auth_time"),
                acr = text("acr"),
                amr = list("amr"),
                authorizedParty = text("azp"),
                all = payload.filterKeys { it != "nonce" }
                    .mapValues { (_, value) -> if (value is JsonPrimitive) value.content else value.toString() },
            )
        }
    }
}

/**
 * What an ID token must satisfy at login and at refresh (OpenID Connect Core 3.1.3.7, 12.2).
 * The coordinator calls this before the token response is persisted; a refusal is
 * `Configuration(IdTokenRejected(reason))` and nothing is stored.
 */
public interface IdTokenValidator {
    /**
     * Gets ready to validate: fetches what [validate] will need (the provider's key set) so that
     * the one step that cannot be repeated, the code exchange, is not followed by a fetch that
     * fails. Called before the browser opens, once per `login()`, and a failure is ignored,
     * because [validate] fetches again under the operation's retry budget. The default does
     * nothing.
     */
    public suspend fun prepare() {}

    /**
     * @param idToken the compact JWS off the token response.
     * @param expectedNonce the `nonce` the authorization request carried; null on a refresh,
     *   where the claim is not required.
     * @param accessToken the access token issued beside it, for `at_hash` when present.
     * @param maxAge the `max_age` the request carried, under which `auth_time` is required.
     * @param previous the claims of the ID token this one replaces, on a refresh: `sub` must
     *   not change and `auth_time` must not move backwards.
     * @param serverTime the provider's clock as the token response's `Date` header gave it,
     *   or null: `exp`, `iat` and `auth_time` are judged against it rather than the device's
     *   clock, so a device minutes off does not refuse every token (spec section 11).
     */
    public suspend fun validate(
        idToken: String,
        expectedNonce: String?,
        accessToken: String?,
        maxAge: Long?,
        previous: IdTokenClaims?,
        serverTime: Instant? = null,
    ): IdTokenClaims
}
