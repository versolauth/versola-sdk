package versola.sdk.core

import java.net.URLEncoder
import versola.oauth.core.AuthorizationRequest
import versola.oauth.core.AuthorizationStarter
import versola.oauth.core.PendingAuthorizationRequest
import versola.oauth.core.ProviderMetadata
import versola.oauth.core.RedirectUriKind
import versola.oauth.core.StartedAuthorization
import versola.oauth.core.TokenBinding
import versola.oauth.core.VersolaConfiguration
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaInternalApi

/**
 * [BackChannel.Edge]'s version of building the request: edge builds it, pushes it to `/par`
 * with `dpop_jkt` set from the proof on this very call, and hands back the `request_uri` to
 * open, the `state` to expect and the blob that stands in for the verifier. What is persisted
 * before the browser opens is therefore edge's `state` and blob rather than a verifier of the
 * flow's own — the same moment, the same reason.
 *
 * The authorization endpoint comes from discovery, not from edge's answer: the issuer is the
 * one URL the integrator vouched for, and `request_uri` is bound to the client at auth either
 * way. Edge's `authorization_endpoint` is informational for this SDK.
 *
 * Every native endpoint demands a proof, so there is no bearer variant of this flow to fall
 * back to; and the server registers an edge-fronted native client with https redirect URIs
 * only, so anything else fails at `/par` rather than here. Both are refused at construction.
 */
@VersolaInternalApi
public class EdgeAuthorizationStarter(
    private val configuration: VersolaConfiguration,
    tokenBinding: TokenBinding,
    private val native: NativeAuthorizationStarter,
) : AuthorizationStarter {

    init {
        if (tokenBinding !is TokenBinding.Dpop) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.InvalidConfiguration(
                    "BackChannel.Edge needs TokenBinding.Dpop: edge's native endpoints accept no bearer presentation",
                ),
            )
        }
        if (configuration.redirectUri.kind != RedirectUriKind.AppLink) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.InvalidConfiguration(
                    "BackChannel.Edge needs an https App Link redirectUri: " +
                        "an edge-fronted native client is registered with https redirect URIs only",
                ),
            )
        }
    }

    override suspend fun start(
        request: AuthorizationRequest,
        metadata: ProviderMetadata,
        nowEpochMillis: Long,
    ): StartedAuthorization {
        val started = native.start(
            NativeStartRequest(
                redirectUri = configuration.redirectUri.value,
                scopes = request.scopes,
                nonce = request.nonce,
                acrValues = request.acrValues,
                maxAge = request.maxAge,
            ),
        )
        val pending = PendingAuthorizationRequest(
            state = started.state,
            nonce = request.nonce,
            codeVerifier = "",
            scopes = request.scopes.toList(),
            redirectUri = configuration.redirectUri.value,
            acrValues = request.acrValues,
            maxAge = request.maxAge,
            createdAtEpochMillis = nowEpochMillis,
            extension = mapOf(
                BLOB to started.blob,
                TOKEN_ENDPOINT to started.tokenEndpoint,
                REVOCATION_ENDPOINT to started.revocationEndpoint,
            ),
            // `/native/complete` requires `iss`, and auth always emits it.
            issRequired = true,
        )
        val query = "client_id=${encode(configuration.clientId)}&request_uri=${encode(started.requestUri)}"
        val separator = if (metadata.authorizationEndpoint.contains('?')) "&" else "?"
        return StartedAuthorization(pending, metadata.authorizationEndpoint + separator + query)
    }

    private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8").replace("+", "%20")

    public companion object {
        /** Keys of [PendingAuthorizationRequest.extension] the edge flow writes and [EdgeNativeTokenClient] reads. */
        public const val BLOB: String = "blob"
        public const val TOKEN_ENDPOINT: String = "token_endpoint"
        public const val REVOCATION_ENDPOINT: String = "revocation_endpoint"

        /**
         * The names the same artefacts had as fields of the pending record before the
         * extension map existed. A record written by that version can still be on disk,
         * unexpired, after an update; [PendingAuthorizationCodec] keeps its members under
         * these names and the exchange reads either.
         */
        public const val LEGACY_TOKEN_ENDPOINT: String = "tokenEndpoint"
        public const val LEGACY_REVOCATION_ENDPOINT: String = "revocationEndpoint"

        /** The endpoints a grant's extension names, under the current or the pre-extension keys. */
        public fun tokenEndpointOf(extension: Map<String, String>): String? =
            extension[TOKEN_ENDPOINT] ?: extension[LEGACY_TOKEN_ENDPOINT]

        public fun revocationEndpointOf(extension: Map<String, String>): String? =
            extension[REVOCATION_ENDPOINT] ?: extension[LEGACY_REVOCATION_ENDPOINT]
    }
}
