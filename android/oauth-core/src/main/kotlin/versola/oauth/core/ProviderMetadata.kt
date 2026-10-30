package versola.oauth.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
public data class MtlsEndpointAliases(
    @SerialName("token_endpoint")
    public val tokenEndpoint: String? = null,
    @SerialName("revocation_endpoint")
    public val revocationEndpoint: String? = null,
)

/**
 * The authorization server metadata document (RFC 8414 / OpenID Connect Discovery), as far as
 * the SDK reads it. Unknown fields are ignored rather than rejected — a provider is free to
 * advertise more than this, and `auth` does (`ServedMetadata` derives several fields the SDK
 * has no use for).
 *
 * The issuer is the only URL the integrator supplies. Everything else is read from here, which
 * is what keeps the core usable against any conforming provider. Edge's base URL is *not* in
 * this document and is separate configuration (#1 §2.1).
 */
@Serializable
public data class ProviderMetadata(
    // The three required fields default to empty rather than being non-optional, so a
    // document that omits one fails as DiscoveryFieldMissing naming the field, rather than
    // as an opaque deserialization error.
    @SerialName("issuer")
    public val issuer: String = "",
    @SerialName("authorization_endpoint")
    public val authorizationEndpoint: String = "",
    @SerialName("token_endpoint")
    public val tokenEndpoint: String = "",
    @SerialName("userinfo_endpoint")
    public val userinfoEndpoint: String? = null,
    @SerialName("revocation_endpoint")
    public val revocationEndpoint: String? = null,
    @SerialName("end_session_endpoint")
    public val endSessionEndpoint: String? = null,
    @SerialName("jwks_uri")
    public val jwksUri: String? = null,
    @SerialName("scopes_supported")
    public val scopesSupported: List<String> = emptyList(),
    @SerialName("response_types_supported")
    public val responseTypesSupported: List<String> = emptyList(),
    @SerialName("grant_types_supported")
    public val grantTypesSupported: List<String> = emptyList(),
    @SerialName("code_challenge_methods_supported")
    public val codeChallengeMethodsSupported: List<String> = emptyList(),
    /**
     * RFC 9449 §5.1. Its **absence** is the bearer-fallback signal (#1 §4, scenario 07):
     * a log line, not a failure. Its presence is what turns DPoP on, invisibly.
     */
    @SerialName("dpop_signing_alg_values_supported")
    public val dpopSigningAlgValuesSupported: List<String> = emptyList(),
    /**
     * RFC 9207. When a deployment advertises this, an `iss` missing from the redirect is a
     * hard failure; when it does not, a missing `iss` is legitimate. Defaulting to `false`
     * is therefore the safe reading of a document that omits the field.
     */
    @SerialName("authorization_response_iss_parameter_supported")
    public val authorizationResponseIssParameterSupported: Boolean = false,
    /**
     * RFC 8705 §5: the same endpoints on the provider's mutual-TLS listener. A back channel
     * that forwards the device's proof to that listener signs its proofs for these URLs (the
     * Versola facade's edge flow learns them from `/native/start` too, and that answer wins
     * because it is edge's own configuration rather than a deployment-wide guess).
     */
    @SerialName("mtls_endpoint_aliases")
    public val mtlsEndpointAliases: MtlsEndpointAliases? = null,
    /** RFC 9126: where a request is pushed before the browser opens. Absent means no PAR. */
    @SerialName("pushed_authorization_request_endpoint")
    public val pushedAuthorizationRequestEndpoint: String? = null,
    /** RFC 9126 §5: the provider refuses an authorization request that was not pushed. */
    @SerialName("require_pushed_authorization_requests")
    public val requirePushedAuthorizationRequests: Boolean = false,
    /** OpenID Connect Discovery 3: the ID-token signing algorithms the provider uses. */
    @SerialName("id_token_signing_alg_values_supported")
    public val idTokenSigningAlgValuesSupported: List<String> = emptyList(),
) {

    /**
     * DPoP is on whenever the provider advertises any signing algorithm for it. The SDK does
     * not let the integrator choose: #1 §4 fixes the behaviour to "on and invisible", with
     * bearer reached only through this absence or an explicit `TokenBinding.Bearer`.
     */
    public val supportsDpop: Boolean
        get() = dpopSigningAlgValuesSupported.isNotEmpty()

    internal fun validate(configuredIssuer: String) {
        if (issuer.isBlank()) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.DiscoveryFieldMissing("issuer"),
            )
        }
        if (issuer.trimEnd('/') != configuredIssuer.trimEnd('/')) {
            // OpenID Connect Discovery §4.3. A document that names a different issuer than
            // the one it was fetched from is the classic mix-up precondition.
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.DiscoveryIssuerMismatch(configuredIssuer, issuer),
            )
        }
        if (authorizationEndpoint.isBlank()) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.DiscoveryFieldMissing("authorization_endpoint"),
            )
        }
        if (tokenEndpoint.isBlank()) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.DiscoveryFieldMissing("token_endpoint"),
            )
        }
        // Every URL the SDK will send a code, a refresh token, a proof or the user to. Held to the
        // issuer's own rule (https, or cleartext on loopback for a staged stack) but not to the
        // issuer's origin: Cognito's OAuth endpoints live on the user-pool domain and Entra's
        // UserInfo on Microsoft Graph, so a cross-origin endpoint is legitimate (`providers.md`).
        // Without this a document announcing `http://…/token` has refresh tokens POSTed to it in
        // the clear.
        requireSecure("authorization_endpoint", authorizationEndpoint)
        requireSecure("token_endpoint", tokenEndpoint)
        requireSecure("userinfo_endpoint", userinfoEndpoint)
        requireSecure("revocation_endpoint", revocationEndpoint)
        requireSecure("end_session_endpoint", endSessionEndpoint)
        requireSecure("jwks_uri", jwksUri)
        requireSecure("pushed_authorization_request_endpoint", pushedAuthorizationRequestEndpoint)
        requireSecure("mtls_endpoint_aliases.token_endpoint", mtlsEndpointAliases?.tokenEndpoint)
        requireSecure("mtls_endpoint_aliases.revocation_endpoint", mtlsEndpointAliases?.revocationEndpoint)
    }

    /** Absent or blank is "not advertised", which the callers already read as such; anything else must be secure. */
    private fun requireSecure(member: String, url: String?) {
        if (url.isNullOrBlank()) return
        val parsed = try {
            java.net.URI(url)
        } catch (e: java.net.URISyntaxException) {
            null
        }
        val scheme = parsed?.scheme?.lowercase()
        val acceptable = !parsed?.host.isNullOrEmpty() &&
            (scheme == "https" || (scheme == "http" && isLoopbackHost(parsed?.host)))
        if (!acceptable) {
            // The member's name and nothing of its value: the document is the provider's, but the
            // value could carry a credential in its query, and the name is what a developer needs.
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.DiscoveryMalformed("$member must be an https URL (http only on loopback)"),
            )
        }
    }
}
