package kz.versola.sdk.core

import java.net.URLEncoder
import java.security.SecureRandom

/**
 * An authorization request, built once and then split in two: the URI the browser opens, and
 * the [PendingAuthorizationRequest] persisted before it opens.
 *
 * PKCE, `state` and `nonce` are not parameters — they are generated here, always. There is no
 * way for an integrator to supply, disable or weaken them.
 */
public class AuthorizationRequest internal constructor(
    internal val configuration: VersolaConfiguration,
    public val scopes: Set<String>,
    public val state: String,
    public val nonce: String,
    internal val codeVerifier: CodeVerifier,
    public val acrValues: List<String>,
    public val maxAge: Long?,
    /**
     * RFC 9449 §10, and null whenever the session is not key-bound. Committing to the key
     * here, before a code exists, is what stops a stolen code being redeemed against a
     * different key: `AuthorizeRequestParser` stores it and the token endpoint compares it
     * against the redeeming proof's thumbprint.
     */
    internal val dpopJkt: String? = null,
) {

    /**
     * The authorization URI. `response_type=code` and `code_challenge_method=S256` are the
     * only values the server accepts (`AuthorizeRequestParser`), so neither is configurable.
     */
    public fun toUri(authorizationEndpoint: String): String {
        val parameters = buildList {
            add("response_type" to "code")
            add("client_id" to configuration.clientId)
            add("redirect_uri" to configuration.redirectUri.value)
            if (scopes.isNotEmpty()) add("scope" to scopes.joinToString(" "))
            add("state" to state)
            add("nonce" to nonce)
            add("code_challenge" to codeVerifier.challengeS256())
            add("code_challenge_method" to "S256")
            if (acrValues.isNotEmpty()) add("acr_values" to acrValues.joinToString(" "))
            maxAge?.let { add("max_age" to it.toString()) }
            dpopJkt?.let { add("dpop_jkt" to it) }
        }
        val query = parameters.joinToString("&") { (name, value) -> "${encode(name)}=${encode(value)}" }
        val separator = if (authorizationEndpoint.contains('?')) "&" else "?"
        return authorizationEndpoint + separator + query
    }

    internal fun toPending(createdAtEpochMillis: Long): PendingAuthorizationRequest =
        PendingAuthorizationRequest(
            state = state,
            nonce = nonce,
            codeVerifier = codeVerifier.value,
            scopes = scopes.toList(),
            redirectUri = configuration.redirectUri.value,
            acrValues = acrValues,
            maxAge = maxAge,
            createdAtEpochMillis = createdAtEpochMillis,
        )

    // URLEncoder is form encoding, which differs from percent-encoding in exactly one place:
    // a space becomes '+'. Legal in a query string but not in every server's parser, and
    // `scope` and `acr_values` are space-delimited, so it is corrected here.
    private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8").replace("+", "%20")

    internal companion object {
        fun create(
            configuration: VersolaConfiguration,
            scopes: Set<String>,
            acrValues: List<String> = emptyList(),
            maxAge: Long? = null,
            dpopJkt: String? = null,
            random: SecureRandom = SecureRandom(),
        ): AuthorizationRequest = AuthorizationRequest(
            configuration = configuration,
            scopes = scopes,
            state = SecureTokens.generate(random),
            nonce = SecureTokens.generate(random),
            codeVerifier = CodeVerifier.generate(random),
            acrValues = acrValues,
            maxAge = maxAge,
            dpopJkt = dpopJkt,
        )
    }
}
