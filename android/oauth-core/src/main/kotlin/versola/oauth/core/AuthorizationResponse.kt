package versola.oauth.core

import java.net.URI
import java.net.URISyntaxException
import java.net.URLDecoder

/**
 * A validated authorization code, with everything the token exchange (#8) needs to redeem it.
 * There is no way to construct one except by passing [AuthorizationResponseValidator], which
 * is the point: a code that reached the token endpoint was checked first.
 */
public class AuthorizationGrant @VersolaInternalApi public constructor(
    /** The authorization code. Readable only by a [TokenClient], which spends it once. */
    @VersolaInternalApi public val code: String,
    internal val codeVerifier: CodeVerifier,
    public val redirectUri: String,
    public val nonce: String,
    public val scopes: Set<String>,
    /** The `state` the redirect carried, already matched; a back channel may want it back. */
    @VersolaInternalApi public val state: String = "",
    /** RFC 9207 `iss` off the redirect, already matched; a back channel may require it. */
    @VersolaInternalApi public val iss: String? = null,
    /** [PendingAuthorizationRequest.extension], unchanged: what the starter left for the exchange. */
    @VersolaInternalApi public val extension: Map<String, String> = emptyMap(),
    /**
     * RFC 8707 `resource` values the authorization request carried; the exchange repeats them
     * (§2.2). Not a credential, so readable by the app. A refresh does not repeat them: the
     * grant's audience is already fixed.
     */
    public val resources: List<String> = emptyList(),
    /**
     * The `max_age` the request carried, restored from the pending request. A login finished in
     * another process than the one that asked has no caller to remember it, and the ID token's
     * `auth_time` check (OpenID Connect Core 3.1.3.7 step 11) must not depend on there being one.
     */
    @VersolaInternalApi public val maxAge: Long? = null,
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

    /**
     * @param issuer the `issuer` of the provider's metadata, as announced: the redirect's `iss` must
     *   equal it byte for byte (RFC 9207 section 2.4), which is not the configured issuer when the
     *   provider announces a trailing slash.
     */
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

        // 2. iss (RFC 9207). Present ⇒ must match, by simple string comparison (section 2.4): no
        //    trailing-slash or case folding, because two issuers that differ only that way are two
        //    issuers, and a tolerance here is room for the mix-up attack this parameter exists to
        //    close. The comparand is the issuer the provider's own metadata announces. Absent ⇒ only a failure when the provider
        //    advertises authorization_response_iss_parameter_supported; a deployment that
        //    does not advertise it may legitimately omit iss.
        //    A starter whose exchange requires `iss` (the edge back channel: a required field
        //    of `/native/complete`) says so on the pending request, whatever discovery says.
        val iss = parameters["iss"]
        if (iss != null) {
            if (iss != issuer) {
                throw VersolaError.Configuration(
                    VersolaError.Configuration.Detail.IssuerMismatch(issuer, iss),
                )
            }
        } else if (issParameterSupported || pending.issRequired) {
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
            state = pending.state,
            iss = iss,
            extension = pending.extension,
            resources = pending.resources,
            maxAge = pending.maxAge,
        )
    }

    /**
     * The `state` a redirect carries, or null when it carries none or cannot be parsed.
     *
     * Only for telling *which* of this process's own authorizations a redirect answers. It
     * decides nothing: a redirect that reaches [validate] is still compared against the
     * pending request in constant time, absent `state` included.
     */
    internal fun stateOf(redirect: String): String? = try {
        parseQueryOrThrowRaw(redirect)["state"]
    } catch (e: Exception) {
        null
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
    private fun parseQuery(redirect: String): Map<String, String> = try {
        parseQueryOrThrowRaw(redirect)
    } catch (e: URISyntaxException) {
        // The redirect activity hands over whatever URI string the OS delivered; a
        // malformed one is untrusted external input, not a place to let a raw exception
        // escape past the `VersolaError` contract `complete()` cleans up after. No cause is
        // attached: `URISyntaxException.message` is the whole redirect, `code` and `state`
        // included, and a cause travels with the error into crash reports and logs.
        throw VersolaError.Configuration(VersolaError.Configuration.Detail.MalformedAuthorizationResponse)
    } catch (e: IllegalArgumentException) {
        // Thrown by `URLDecoder.decode` on an invalid percent-escape (e.g. a bare "%"); its
        // message quotes the offending part of the query, so it is dropped for the same reason.
        throw VersolaError.Configuration(VersolaError.Configuration.Detail.MalformedAuthorizationResponse)
    }

    private fun parseQueryOrThrowRaw(redirect: String): Map<String, String> {
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
