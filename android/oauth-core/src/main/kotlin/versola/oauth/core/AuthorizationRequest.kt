package versola.oauth.core

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
    /** What `login()` added beyond scopes, `acr_values` and `max_age`; sent after `dpop_jkt`. */
    public val parameters: AuthorizationParameters = AuthorizationParameters(),
) {

    /**
     * Every parameter of the request, in wire order, as (name, value) pairs. The one list both
     * [toUri] (the query) and a pushed request (the form body, RFC 9126 §2.1) are built from,
     * so the two cannot drift: a parameter pushed is a parameter that would have been in the
     * query, and the reverse.
     *
     * `response_type=code` and `code_challenge_method=S256` are the only values the server
     * accepts (`AuthorizeRequestParser`), so neither is configurable. The [parameters] follow
     * `dpop_jkt`, `extra` last, each as given: `resource` repeats once per value (RFC 8707
     * §2.1) and `ui_locales` is one space-delimited value (OpenID Connect Core §3.1.2.1).
     * A public client has no credential, so there is nothing here to authenticate with.
     */
    internal fun formParameters(): List<Pair<String, String>> = buildList {
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
        parameters.prompt?.let { add("prompt" to it.value) }
        parameters.loginHint?.let { add("login_hint" to it) }
        if (parameters.uiLocales.isNotEmpty()) add("ui_locales" to parameters.uiLocales.joinToString(" "))
        parameters.resources.forEach { add("resource" to it) }
        parameters.extra.forEach { (name, value) -> add(name to value) }
    }

    /** The authorization URI: the endpoint with every [formParameters] pair as its query. */
    public fun toUri(authorizationEndpoint: String): String {
        return withQuery(authorizationEndpoint, formParameters())
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
            // Kept so the exchange can repeat them (RFC 8707 §2.2); nothing else of the
            // parameters is needed once the browser has them.
            resources = parameters.resources,
        )

    /** Wiring: a facade's starter builds the request it pushes from here (the edge back channel). */
    @VersolaInternalApi
    public companion object {
        public fun create(
            configuration: VersolaConfiguration,
            scopes: Set<String>,
            acrValues: List<String> = emptyList(),
            maxAge: Long? = null,
            dpopJkt: String? = null,
            parameters: AuthorizationParameters = AuthorizationParameters(),
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
            parameters = parameters,
        )
    }
}

/**
 * [endpoint] with [parameters] as its query, appended to one it already has. Shared by the
 * plain authorization URI and the short one a pushed request opens (`client_id` and
 * `request_uri`), so both encode alike.
 */
internal fun withQuery(endpoint: String, parameters: List<Pair<String, String>>): String {
    val query = parameters.joinToString("&") { (name, value) -> "${encode(name)}=${encode(value)}" }
    val separator = if (endpoint.contains('?')) "&" else "?"
    return endpoint + separator + query
}

// URLEncoder is form encoding, which differs from percent-encoding in exactly one place:
// a space becomes '+'. Legal in a query string but not in every server's parser, and
// `scope`, `acr_values` and `ui_locales` are space-delimited, so it is corrected here.
private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8").replace("+", "%20")
