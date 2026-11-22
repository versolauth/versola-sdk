import Foundation
import OAuthCore

/// What the protocol core reads from a provider's metadata, stated instead of fetched.
///
/// The Versola facade has no discovery document to read: with cells the issuer's address is an
/// edge's, which serves the pages of a sign-in and no well-known document
/// (`spec/versola-sdk-api.md` section 1). The core still asks its metadata for a few things, and each
/// has one answer here that needs no network:
///
/// - `issuer`: the configured value, byte for byte (a trailing slash included), which the redirect's
///   `iss` is compared with;
/// - `end_session_endpoint`: the issuer's `/logout`, the page edge serves there;
/// - `token_endpoint` and `revocation_endpoint`: **edge's** native URLs. Not for calling (the token
///   client has its own) but because the retry budget and the `Retry-After` cooldown are keyed by the
///   token endpoint's origin, and the server that answers 429 to this facade is edge
///   (`spec/retry-policy.md`, "Cooldown");
/// - `authorization_endpoint`: the issuer's `/authorize`, required of any metadata and never opened:
///   the browser opens the one `/native/start` answered (`EdgeAuthorizationStarter`).
///
/// `iss` is always on a Versola redirect and `/native/complete` requires it, and every native grant is
/// DPoP-bound with ES256, so both are stated too.
package struct EdgeMetadata: DiscoveryClient {
    package let metadata: ProviderMetadata

    package init(issuer: String, edgeUrl: URL, clientId: String) throws {
        var root = issuer
        while root.hasSuffix("/") { root.removeLast() }
        metadata = ProviderMetadata(
            issuer: issuer,
            authorizationEndpoint: root + "/authorize",
            tokenEndpoint: try edgeNativeUrl(edgeUrl, endpoint: "token", clientId: clientId).absoluteString,
            revocationEndpoint: try edgeNativeUrl(edgeUrl, endpoint: "revoke", clientId: clientId).absoluteString,
            endSessionEndpoint: root + "/logout",
            dpopSigningAlgValuesSupported: ["ES256"],
            authorizationResponseIssParameterSupported: true
        )
    }

    package func fetch(issuer: String) async throws -> ProviderMetadata { metadata }
}
