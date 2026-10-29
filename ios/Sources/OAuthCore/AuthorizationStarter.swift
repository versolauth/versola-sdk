import Foundation

/// What `AuthorizationStarter.start` hands back: persist `pending`, then open `browserUri`.
public struct StartedAuthorization: Sendable {
    public let pending: PendingAuthorizationRequest
    public let browserUri: URL

    public init(pending: PendingAuthorizationRequest, browserUri: URL) {
        self.pending = pending
        self.browserUri = browserUri
    }
}

/// Builds what the browser opens and what must be persisted before it does, for a facade whose
/// authorization request is not the plain one `AuthorizationRequest` builds: a pushed request
/// (RFC 9126), or the Versola facade's back channel that pushes it itself and keeps the verifier.
///
/// `AuthorizationFlow` persists `pending` and then opens `browserUri`, in that order; the
/// starter decides what the pending request carries, and whatever it needs at the exchange goes
/// into `PendingAuthorizationRequest.extensions`, which the validator copies onto the grant.
public protocol AuthorizationStarter: Sendable {
    func start(request: AuthorizationRequest, metadata: ProviderMetadata, now: Date) async throws
        -> StartedAuthorization

    /// Whether the starter binds the request to the DPoP key itself, so the flow must not put
    /// `dpop_jkt` on the request it builds. The edge back channel does: the thumbprint reaches
    /// `/par` from the proof on `/native/start`, the one place edge can verify it. A starter
    /// that pushes the request as built does not, and keeps the flow's `dpop_jkt`.
    var bindsDpopKeyItself: Bool { get }
}

extension AuthorizationStarter {
    public var bindsDpopKeyItself: Bool { false }
}
