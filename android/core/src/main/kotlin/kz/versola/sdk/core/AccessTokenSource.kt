package kz.versola.sdk.core

/**
 * What the authenticated client needs off a token response, and nothing else: the value to
 * present and whether it must be presented as `DPoP` rather than `Bearer`.
 *
 * Narrow on purpose. [TokenResponse] also carries the refresh token and the raw ID token, and
 * the HTTP layer has no use for either — a seam that hands over the whole response puts both
 * within reach of every interceptor and every test double written against it.
 *
 * The constructor is public because the caller is giving a token it already holds; nothing is
 * created here that was not already in hand.
 */
public class AccessToken(
    public val value: String,
    /**
     * RFC 9449 §5. Read off the issued `token_type` rather than off configuration: a
     * deployment may answer a key-bound request with a bearer token, and
     * `EdgeService.extractAccessToken` refuses a token carrying `cnf.jkt` over the `Bearer`
     * scheme regardless of what either side was configured to prefer.
     */
    public val isDpopBound: Boolean,
) {
    /** Credential material. */
    override fun toString(): String = "AccessToken(redacted)"

    internal companion object {
        fun of(response: TokenResponse): AccessToken =
            AccessToken(response.accessToken, response.isDpopBound)
    }
}

/**
 * The two questions the authenticated client asks of a session: give me a token to send, and
 * give me a new one because the last was refused.
 *
 * An interface rather than [SessionCoordinator] itself so that the HTTP layer depends on the
 * two calls it makes instead of on the class that also owns the rotation slot, the idempotency
 * key and the state machine.
 */
public interface AccessTokenSource {

    /**
     * A token fit to send now: the cached one while it is outside its refresh skew, otherwise
     * the result of a refresh.
     */
    public suspend fun accessToken(): AccessToken

    /**
     * A token issued by the server during this call, whatever the age of the cached one.
     *
     * Single-flight like every other refresh: concurrent callers coalesce onto one token
     * request rather than each spending the grant.
     */
    public suspend fun renewAccessToken(): AccessToken
}
