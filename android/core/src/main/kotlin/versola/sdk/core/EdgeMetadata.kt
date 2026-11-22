package versola.sdk.core

import versola.oauth.core.DiscoveryClient
import versola.oauth.core.ProviderMetadata
import versola.oauth.core.ProviderMetadataCache
import versola.oauth.core.VersolaInternalApi

/**
 * What the protocol core reads from a provider's metadata, stated instead of fetched.
 *
 * The Versola facade has no discovery document to read: with cells the issuer's address is an
 * edge's, which serves the pages of a sign-in and no well-known document
 * (`spec/versola-sdk-api.md` section 1). The core still asks its metadata for four things, and
 * each has one answer here that needs no network:
 *
 * - `issuer`: the configured value, byte for byte, which the redirect's `iss` is compared with;
 * - `end_session_endpoint`: the issuer's `/logout`, the page edge serves there;
 * - `token_endpoint` and `revocation_endpoint`: **edge's** native URLs. Not for calling (the
 *   token client has its own) but because the retry budget and the `Retry-After` cooldown are
 *   keyed by the token endpoint's origin, and the server that answers 429 to this facade is edge
 *   (`spec/retry-policy.md`, "Cooldown");
 * - `authorization_endpoint`: the issuer's `/authorize`, required of any metadata and never
 *   opened: the browser opens the one `/native/start` answered ([EdgeAuthorizationStarter]).
 *
 * `iss` is always on a Versola redirect and `/native/complete` requires it, and every native
 * grant is DPoP-bound with ES256, so both are stated too.
 */
@VersolaInternalApi
public class EdgeMetadata(
    issuer: String,
    edgeUrl: String,
    clientId: String,
) : DiscoveryClient {

    private val metadata = ProviderMetadata(
        issuer = issuer,
        authorizationEndpoint = issuer.trimEnd('/') + "/authorize",
        tokenEndpoint = nativeEndpointUrl(edgeUrl, "token", clientId),
        revocationEndpoint = nativeEndpointUrl(edgeUrl, "revoke", clientId),
        endSessionEndpoint = issuer.trimEnd('/') + "/logout",
        dpopSigningAlgValuesSupported = listOf("ES256"),
        authorizationResponseIssParameterSupported = true,
    )

    override suspend fun fetch(issuer: String): ProviderMetadata = metadata

    /** Nothing to keep: the document is a function of the configuration. */
    public object NoCache : ProviderMetadataCache {
        override suspend fun load(): ProviderMetadata? = null
        override suspend fun save(metadata: ProviderMetadata) {}
        override suspend fun clear() {}
    }
}
