package versola.oauth.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * What the token endpoint issued: RFC 6749 §5.1 plus OpenID Connect's `id_token`.
 *
 * The refresh token is [ByteArray] rather than `String` because that is what
 * [CredentialStore.save] takes, and the conversion has to happen somewhere. Doing it here
 * rather than at the call site means one place holds it, and the caller hands it straight on.
 *
 * Honest about what this cannot fix: parsing JSON materialises every value as a `String`
 * first, and a `String` cannot be zeroed. The response body therefore leaves one copy of the
 * refresh token on the heap until it is collected, on any platform with an ordinary JSON
 * parser. What the SDK controls is everything after that — the copy this class holds is bytes,
 * the request body that spends it is bytes, and both are zeroed.
 */
public class TokenResponse internal constructor(
    public val accessToken: String,
    public val tokenType: String,
    public val expiresInSeconds: Long,
    internal val refreshToken: ByteArray?,
    public val idToken: String?,
    public val scopes: Set<String>,
) {

    /**
     * RFC 9449 §5: `DPoP` means the access token is bound to the key that proved possession,
     * and must be presented with the `DPoP` scheme rather than `Bearer`. Compared
     * case-insensitively — RFC 6749 §5.1 makes the value case-insensitive.
     */
    public val isDpopBound: Boolean
        get() = tokenType.equals("DPoP", ignoreCase = true)

    /** Credential material on three counts. */
    override fun toString(): String = "TokenResponse(redacted)"

    internal companion object {
        fun from(payload: TokenResponsePayload): TokenResponse {
            if (payload.accessToken.isBlank()) {
                throw VersolaError.Configuration(
                    VersolaError.Configuration.Detail.TokenResponseMalformed("access_token is missing"),
                )
            }
            // RFC 6749 §5.1 makes `token_type` REQUIRED, and it is what decides whether the
            // token is presented as `Bearer` or `DPoP`. Assuming `Bearer` for a response that
            // omits it would guess the one field that says whether the grant is key-bound.
            if (payload.tokenType.isNullOrBlank()) {
                throw VersolaError.Configuration(
                    VersolaError.Configuration.Detail.TokenResponseMalformed("token_type is missing"),
                )
            }
            return TokenResponse(
                accessToken = payload.accessToken,
                tokenType = payload.tokenType,
                expiresInSeconds = payload.expiresIn,
                refreshToken = payload.refreshToken?.toByteArray(Charsets.UTF_8),
                idToken = payload.idToken,
                // RFC 6749 §5.1: space-delimited, and present only when it differs from what
                // was requested. An absent scope is not an empty grant.
                scopes = payload.scope?.split(' ')?.filter { it.isNotEmpty() }?.toSet() ?: emptySet(),
            )
        }
    }
}

/**
 * The wire shape, kept separate from [TokenResponse] so the public type is not a
 * `@Serializable` data class whose `toString` would print the tokens.
 */
@Serializable
internal class TokenResponsePayload(
    @SerialName("access_token") val accessToken: String = "",
    @SerialName("token_type") val tokenType: String? = null,
    @SerialName("expires_in") val expiresIn: Long = 0,
    @SerialName("refresh_token") val refreshToken: String? = null,
    @SerialName("id_token") val idToken: String? = null,
    @SerialName("scope") val scope: String? = null,
)

/** RFC 6749 §5.2, plus the two RFC 9449 codes the token endpoint adds. */
@Serializable
@VersolaInternalApi
public class TokenErrorPayload(
    @SerialName("error") public val error: String = "",
    @SerialName("error_description") public val errorDescription: String? = null,
)
