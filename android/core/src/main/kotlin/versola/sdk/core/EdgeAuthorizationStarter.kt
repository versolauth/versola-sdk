package versola.sdk.core

import java.net.URLEncoder
import versola.oauth.core.AuthorizationRequest
import versola.oauth.core.AuthorizationStarter
import versola.oauth.core.PendingAuthorizationRequest
import versola.oauth.core.ProviderMetadata
import versola.oauth.core.RedirectUriKind
import versola.oauth.core.StartedAuthorization
import versola.oauth.core.VersolaConfiguration
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaInternalApi

/**
 * The Versola facade's way of building the request: edge builds it, pushes it to `/par` with
 * `dpop_jkt` set from the proof on this very call, and hands back the `request_uri` to open, the
 * `state` to expect and the blob that stands in for the verifier. What is persisted before the
 * browser opens is therefore edge's `state` and blob rather than a verifier of the flow's own:
 * the same moment, the same reason.
 *
 * The browser opens the `authorization_endpoint` **edge answered**, not one read from a discovery
 * document: with cells the issuer's address is an edge's, which serves the sign-in pages and no
 * discovery, so there is no document to read (`spec/versola-sdk-api.md` sections 1 and 5). The
 * answer is refused unless that endpoint is `https` ([NativeStart.validate]).
 *
 * The request lives as long as edge said, `expires_in` seconds: edge seals that moment into the
 * blob and refuses `/native/complete` after it, so a redirect that arrives later is not redeemed
 * (`spec/state-machine.md`).
 *
 * An edge-fronted native client is registered with https redirect URIs only, in every tenant, so
 * anything else is refused here, at construction, rather than at `/par`.
 */
@VersolaInternalApi
public class EdgeAuthorizationStarter(
    private val configuration: VersolaConfiguration,
    private val native: NativeAuthorizationStarter,
) : AuthorizationStarter {

    /** Edge sets `dpop_jkt` at `/par` from the proof on `/native/start`; see [AuthorizationStarter.bindsDpopKeyItself]. */
    override val bindsDpopKeyItself: Boolean get() = true

    init {
        if (configuration.redirectUri.kind != RedirectUriKind.AppLink) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.InvalidConfiguration(
                    "redirectUri must be an https App Link: " +
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
                prompt = request.parameters.prompt?.value,
                loginHint = request.parameters.loginHint,
                uiLocales = request.parameters.uiLocales,
                resources = request.parameters.resources,
                // The two that have no field of their own in the core's parameters travel in its
                // `extra` map under their wire names; nothing else of that map is forwarded,
                // because edge forwards nothing else.
                claims = request.parameters.extra[CLAIMS],
                authorizationDetails = request.parameters.extra[AUTHORIZATION_DETAILS],
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
            resources = request.parameters.resources,
        ).withLifetime(
            // Seconds to milliseconds without overflow for an absurd value; the request caps it
            // at ten minutes whatever edge says.
            started.expiresIn.coerceAtMost(PendingAuthorizationRequest.MAX_AGE_MILLIS / 1000) * 1000,
        )
        // The `request_uri` is percent-encoded as a query value and not otherwise touched: with
        // cells it names the cell that holds the request, and edge routes by it.
        val query = "client_id=${encode(configuration.clientId)}&request_uri=${encode(started.requestUri)}"
        val separator = if (started.authorizationEndpoint.contains('?')) "&" else "?"
        return StartedAuthorization(pending, started.authorizationEndpoint + separator + query)
    }

    private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8").replace("+", "%20")

    public companion object {
        /** Keys of [PendingAuthorizationRequest.extension] the edge flow writes and [EdgeNativeTokenClient] reads. */
        public const val BLOB: String = "blob"
        public const val TOKEN_ENDPOINT: String = "token_endpoint"
        public const val REVOCATION_ENDPOINT: String = "revocation_endpoint"

        /** Keys of `AuthorizationParameters.extra` this starter forwards, by their wire names. */
        public const val CLAIMS: String = "claims"
        public const val AUTHORIZATION_DETAILS: String = "authorization_details"

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
