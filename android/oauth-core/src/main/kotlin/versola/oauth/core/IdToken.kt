package versola.oauth.core

import java.time.Instant

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
    override fun toString(): String = "IdTokenClaims(subject=$subject, issuer=$issuer)"
}

/**
 * What an ID token must satisfy at login and at refresh (OpenID Connect Core 3.1.3.7, 12.2).
 * The coordinator calls this before the token response is persisted; a refusal is
 * `Configuration(IdTokenRejected(reason))` and nothing is stored.
 */
public interface IdTokenValidator {
    /**
     * @param idToken the compact JWS off the token response.
     * @param expectedNonce the `nonce` the authorization request carried; null on a refresh,
     *   where the claim is not required.
     * @param accessToken the access token issued beside it, for `at_hash` when present.
     * @param maxAge the `max_age` the request carried, under which `auth_time` is required.
     * @param previous the claims of the ID token this one replaces, on a refresh: `sub` must
     *   not change and `auth_time` must not move backwards.
     */
    public suspend fun validate(
        idToken: String,
        expectedNonce: String?,
        accessToken: String?,
        maxAge: Long?,
        previous: IdTokenClaims?,
    ): IdTokenClaims
}
