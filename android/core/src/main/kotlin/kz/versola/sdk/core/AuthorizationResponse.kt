package kz.versola.sdk.core

import java.net.URI
import java.net.URLDecoder

/**
 * A validated authorization code, with everything the token exchange (#8) needs to redeem it.
 * There is no way to construct one except by passing [AuthorizationResponseValidator], which
 * is the point: a code that reached the token endpoint was checked first.
 */
public class AuthorizationGrant internal constructor(
    internal val code: String,
    internal val codeVerifier: CodeVerifier,
    public val redirectUri: String,
    public val nonce: String,
    public val scopes: Set<String>,
) {
    /** Credential material on both counts. */
    override fun toString(): String = "AuthorizationGrant(redacted)"
}

/**
 * Validates a redirect against the pending request that produced it.
 *
 * The order is normative (`spec/state-machine.md`, `Authorizing → Authenticated`) and every
 * step happens **before any network call**: `state`, then `iss`, then the response's own
 * error, then the presence of `code`. A failure at any step means no request reaches the
 * token endpoint at all — scenarios 15 and 16.
 */
public object AuthorizationResponseValidator {

    public fun validate(
        redirect: String,
        pending: PendingAuthorizationRequest,
        issuer: String,
        issParameterSupported: Boolean,
    ): AuthorizationGrant {
        val parameters = parseQuery(redirect)

        // 1. state, compared in constant time. An absent state is a mismatch, not a separate
        //    case: the SDK always sends one.
        val state = parameters["state"]
        if (state == null || !SecureTokens.constantTimeEquals(pending.state, state)) {
            throw VersolaError.Configuration(VersolaError.Configuration.Detail.StateMismatch)
        }

        // 2. iss (RFC 9207). Present ⇒ must match. Absent ⇒ only a failure when the provider
        //    advertises authorization_response_iss_parameter_supported; a deployment that
        //    does not advertise it may legitimately omit iss.
        val iss = parameters["iss"]
        if (iss != null) {
            if (iss.trimEnd('/') != issuer.trimEnd('/')) {
                throw VersolaError.Configuration(
                    VersolaError.Configuration.Detail.IssuerMismatch(issuer, iss),
                )
            }
        } else if (issParameterSupported) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.IssuerMismatch(issuer, null),
            )
        }

        // 3. An error the authorization endpoint redirected back. Checked after state and iss
        //    so an injected error response cannot short-circuit those.
        parameters["error"]?.let { code ->
            throw authorizationError(code, parameters["error_description"])
        }

        // 4. code.
        val code = parameters["code"]
        if (code.isNullOrEmpty()) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.MalformedAuthorizationResponse,
            )
        }

        return AuthorizationGrant(
            code = code,
            codeVerifier = CodeVerifier(pending.codeVerifier),
            redirectUri = pending.redirectUri,
            nonce = pending.nonce,
            scopes = pending.scopes.toSet(),
        )
    }

    /**
     * `spec/errors.md`, authorization endpoint table. Everything reachable without
     * `prompt=none` is a `Configuration` fault; the four that mean "the user has to sign in
     * again" are `Reauthenticate`. An unrecognised code is `Configuration` rather than a
     * silent success — a provider that invents codes is a deployment the SDK cannot reason
     * about.
     */
    private fun authorizationError(code: String, description: String?): VersolaError = when (code) {
        "access_denied" ->
            VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.AuthorizationDenied)

        "login_required", "consent_required", "interaction_required" ->
            VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.InteractionRequired(code))

        else -> VersolaError.Configuration(
            VersolaError.Configuration.Detail.AuthorizationRejected(code, description),
        )
    }

    /**
     * Query only: the SDK requests `response_type=code`, whose default response mode is
     * `query`. A fragment response would be an `id_token` flow the SDK never asks for.
     *
     * A repeated parameter is malformed rather than last-wins — the server refuses duplicates
     * for the same reason (`AuthorizeRequestParser.getParam`), and last-wins is how a
     * smuggled parameter gets read.
     */
    private fun parseQuery(redirect: String): Map<String, String> {
        val query = URI(redirect).rawQuery ?: return emptyMap()
        val parameters = mutableMapOf<String, String>()
        for (pair in query.split('&')) {
            if (pair.isEmpty()) continue
            val separator = pair.indexOf('=')
            val name = if (separator < 0) pair else pair.substring(0, separator)
            val value = if (separator < 0) "" else pair.substring(separator + 1)
            val decodedName = URLDecoder.decode(name, "UTF-8")
            if (parameters.containsKey(decodedName)) {
                throw VersolaError.Configuration(
                    VersolaError.Configuration.Detail.MalformedAuthorizationResponse,
                )
            }
            parameters[decodedName] = URLDecoder.decode(value, "UTF-8")
        }
        return parameters
    }
}
