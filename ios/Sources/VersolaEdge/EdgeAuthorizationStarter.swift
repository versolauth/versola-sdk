import Foundation
import OAuthCore

/// The Versola facade's way of building the request: edge builds it, pushes it to `/par` with
/// `dpop_jkt` set from the proof on this very call, and hands back the `request_uri` to open, the
/// `state` to expect and the blob that stands in for the verifier. What is persisted before the
/// browser opens is therefore edge's `state` and blob rather than a verifier of the flow's own: the
/// same moment, the same reason.
///
/// The browser opens the `authorization_endpoint` **edge answered**, not one read from a discovery
/// document: with cells the issuer's address is an edge's, which serves the sign-in pages and no
/// discovery, so there is no document to read (`spec/versola-sdk-api.md` sections 1 and 5). The
/// answer is refused unless that endpoint is `https` (`NativeStart.parse`).
///
/// The request lives as long as edge said, `expires_in` seconds: edge seals that moment into the
/// blob and refuses `/native/complete` after it, so a redirect that arrives later is not redeemed
/// (`spec/state-machine.md`).
///
/// An edge-fronted native client is registered with https redirect URIs only, in every tenant, so
/// anything else is refused here, at construction, rather than at `/par`.
package struct EdgeAuthorizationStarter: AuthorizationStarter {
    private let configuration: CoreConfiguration
    private let native: NativeAuthorizationStarter

    /// Edge sets `dpop_jkt` at `/par` from the proof on `/native/start`; see
    /// `AuthorizationStarter.bindsDpopKeyItself`.
    package var bindsDpopKeyItself: Bool { true }

    package init(configuration: CoreConfiguration, native: NativeAuthorizationStarter) throws {
        guard configuration.redirectUri.scheme?.lowercased() == "https", configuration.redirectUri.host?.isEmpty == false else {
            throw OAuthError.configuration(.invalidConfiguration(
                detail: "redirectUri must be an https App Link: an edge-fronted native client is registered with https redirect URIs only"
            ))
        }
        self.configuration = configuration
        self.native = native
    }

    package func start(request: AuthorizationRequest, metadata: ProviderMetadata, now: Date) async throws
        -> StartedAuthorization {
        let started = try await native.start(NativeStartRequest(
            redirectUri: configuration.redirectUri.absoluteString,
            scopes: request.scopes,
            nonce: request.nonce,
            acrValues: request.acrValues,
            maxAge: request.maxAge,
            prompt: request.parameters.prompt?.rawValue,
            loginHint: request.parameters.loginHint,
            uiLocales: request.parameters.uiLocales,
            resources: request.parameters.resources,
            // The two that have no field of their own in the core's parameters travel in its `extra`
            // map under their wire names; nothing else of that map is forwarded, because edge
            // forwards nothing else.
            claims: request.parameters.extra[EdgeParameter.claims],
            authorizationDetails: request.parameters.extra[EdgeParameter.authorizationDetails]
        ))
        // Capped at ten minutes whatever edge says (the request type does it as well, so that a
        // record read back from disk is held to the same bound).
        let lifetime = min(TimeInterval(started.expiresIn), PendingAuthorizationRequest.maxAge)
        let pending = PendingAuthorizationRequest(
            state: started.state, nonce: request.nonce, codeVerifier: "", scopes: request.scopes,
            redirectUri: configuration.redirectUri.absoluteString, acrValues: request.acrValues,
            maxAge: request.maxAge, createdAt: now, resources: request.parameters.resources,
            // `/native/complete` requires `iss`, and auth always emits it.
            issRequired: true,
            extensions: [
                EdgeExtension.blob: started.blob,
                EdgeExtension.tokenEndpoint: started.tokenEndpoint,
                EdgeExtension.revocationEndpoint: started.revocationEndpoint,
            ],
            lifetime: lifetime
        )
        // The `request_uri` is percent-encoded as a query value and not otherwise touched: with
        // cells it names the cell that holds the request, and edge routes by it.
        let browserUri = try FormEncoding.withQuery(
            started.authorizationEndpoint,
            [("client_id", configuration.clientId), ("request_uri", started.requestUri)]
        )
        return StartedAuthorization(pending: pending, browserUri: browserUri, expiresAt: now.addingTimeInterval(lifetime))
    }
}
