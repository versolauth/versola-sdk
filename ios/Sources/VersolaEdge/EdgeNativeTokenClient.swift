import Foundation
import OAuthCore

/// The token endpoint through edge: `/native/complete` for the code, `/native/token` for refreshes,
/// `/native/revoke` for logout.
///
/// Edge authenticates to auth over mutual TLS and relays auth's answer as it stands (status, body,
/// `DPoP-Nonce`, `WWW-Authenticate`), so the responses read here are the ones `HTTPTokenClient`
/// reads, and the same `TokenRequestExecutor` reads them. What differs is what the proof is signed
/// for: every proof carries auth's mutual-TLS endpoint as `htu`, because edge forwards it byte for
/// byte and auth verifies it against its own URL. A proof signed for edge's URL would be refused at
/// auth as `invalid_dpop_proof`, and a `use_dpop_nonce` in the relayed answer is auth's nonce, cached
/// under auth's origin, not edge's (`spec/versola-sdk-api.md` section 7).
///
/// The `Idempotency-Key` is forwarded too. A native grant is DPoP-bound and auth renews it in place,
/// so the key changes nothing today; it is still sent, and holds if a bound grant is ever rotated.
///
/// Every value is sent as it was received: a code, a refresh token and a blob may name the cell that
/// issued them, edge routes by that, and nothing here reads one (section 8).
package struct EdgeNativeTokenClient: TokenClient {
    private let clientId: String
    private let issuer: String
    private let completeUrl: URL
    private let tokenUrl: URL
    private let revokeUrl: URL
    private let executor: TokenRequestExecutor
    private let endpoints: any EdgeEndpointsStore

    package init(
        clientId: String, issuer: String, edgeUrl: URL, httpClient: HTTPClient, dpop: DpopProofSource,
        endpoints: any EdgeEndpointsStore, clock: Clock = .system
    ) throws {
        self.clientId = clientId
        self.issuer = issuer
        self.completeUrl = try edgeNativeUrl(edgeUrl, endpoint: "complete", clientId: clientId)
        self.tokenUrl = try edgeNativeUrl(edgeUrl, endpoint: "token", clientId: clientId)
        self.revokeUrl = try edgeNativeUrl(edgeUrl, endpoint: "revoke", clientId: clientId)
        self.executor = TokenRequestExecutor(httpClient: httpClient, dpop: dpop, clock: clock)
        self.endpoints = endpoints
    }

    /// Edge's 404: it fronts no such client. Named rather than left as "no OAuth error in a 404".
    private var unknownClient: @Sendable (Int) -> OAuthError? {
        let clientId = self.clientId
        return { $0 == 404 ? .configuration(.facade(name: "edge_client_unknown", detail: clientId)) : nil }
    }

    package func exchange(_ grant: AuthorizationGrant) async throws -> TokenResponse {
        // A grant started directly against auth carries a verifier and no blob; redeeming it here would
        // hand edge a code it did not push the request for. Wiring, not the user's problem, and it fails
        // before the code is spent on anything.
        guard let blob = grant.extensions[EdgeExtension.blob],
              let tokenEndpoint = grant.extensions[EdgeExtension.tokenEndpoint]
        else {
            throw OAuthError.configuration(.invalidConfiguration(detail: "the authorization was not started through edge's /native/start"))
        }
        guard let iss = grant.iss else {
            // Unreachable through AuthorizationResponseValidator, which requires `iss` for a request
            // started through edge; kept as a check because /native/complete does.
            throw OAuthError.configuration(.issuerMismatch(expected: issuer, received: nil))
        }
        // Both endpoints, and both `https`: they come from a record `NativeStart.parse` already held to
        // that, so anything else here is a record this flow did not write. Nothing is inferred from one
        // about the other, and the code is not spent on a proof addressed in the clear.
        guard let revocationEndpoint = grant.extensions[EdgeExtension.revocationEndpoint],
              isSecureEdgeEndpoint(tokenEndpoint), isSecureEdgeEndpoint(revocationEndpoint),
              let htu = URL(string: tokenEndpoint)
        else {
            throw OAuthError.configuration(.invalidConfiguration(detail: "the pending authorization names no usable token and revocation endpoint"))
        }
        let body = FormEncoding.body([("code", grant.code), ("state", grant.state), ("iss", iss), ("blob", blob)])
        let url = completeUrl
        let executor = self.executor
        let onStatus = unknownClient
        // One attempt: an authorization code is single use (`spec/retry-policy.md`).
        let issued = try await OperationBudget.runOnce(origin: DpopOrigin.of(url)) {
            try await executor.execute(url: url, body: body, idempotencyKey: nil, proofFor: htu, onStatus: onStatus)
        }
        try Self.requireDpopBound(issued)
        // Remembered for the refreshes and the revocation that follow, in this process and the next: a
        // refresh does not go through /native/start and has no other way to learn what to sign for.
        // Written here, before the coordinator stores the refresh token, so a grant on disk always has
        // them beside it, and in a task of its own for the reason the token is persisted that way: the
        // code is spent, and a cancelled caller must not leave the grant without them.
        let store = endpoints
        let saved = EdgeNativeEndpoints(tokenEndpoint: tokenEndpoint, revocationEndpoint: revocationEndpoint)
        let revocation = revokeUrl
        let tokenExecutor = executor
        let onUnknown = unknownClient
        try await Task {
            do {
                try await store.save(saved)
            } catch {
                // The code is spent and the refresh token it bought is a live credential at the server that
                // no device will hold: the coordinator never sees it, because this call throws instead of
                // returning it, so it is revoked here, best effort, for the revocation endpoint in hand (the
                // store that failed is the one a later revoke would read it from). Failing to revoke changes
                // nothing about what the caller is told: the sign-in is over, with the store's own failure.
                if let refreshToken = issued.refreshToken {
                    let revokeBody = FormEncoding.body([("token_type_hint", "refresh_token"), ("token", refreshToken)])
                    try? await tokenExecutor.revoke(url: revocation, body: revokeBody, proofFor: URL(string: revocationEndpoint), onStatus: onUnknown)
                }
                throw edgeStoreFailure(error)
            }
        }.value
        return issued
    }

    package func refresh(refreshToken: String, idempotencyKey: String) async throws -> TokenResponse {
        let htu = try await resolveEndpoints().tokenEndpoint
        guard let proofFor = URL(string: htu) else { throw Self.noEndpoints() }
        let body = FormEncoding.body([("grant_type", "refresh_token"), ("refresh_token", refreshToken)])
        let issued = try await executor.execute(
            url: tokenUrl, body: body, idempotencyKey: idempotencyKey, proofFor: proofFor, onStatus: unknownClient
        )
        try Self.requireDpopBound(issued)
        return issued
    }

    /// `/native/revoke`: edge checks the proof is signed for auth's revocation endpoint and relays;
    /// auth's `/revoke` itself reads no proof. `token_type_hint` goes along as RFC 7009 section 2.1
    /// suggests. A repeat is safe (section 2.2), so the operation's budget repeats it.
    package func revoke(refreshToken: String) async throws {
        let htu = try await resolveEndpoints().revocationEndpoint
        guard let proofFor = URL(string: htu) else { throw Self.noEndpoints() }
        let body = FormEncoding.body([("token_type_hint", "refresh_token"), ("token", refreshToken)])
        try await executor.revoke(url: revokeUrl, body: body, proofFor: proofFor, onStatus: unknownClient)
    }

    /// What `/native/start` said at the login this grant came from. There is nothing to infer them from
    /// when they are gone: the facade reads no discovery document. They are written before the refresh
    /// token is, so a grant without them is a damaged store, and the proof a refresh needs cannot be
    /// addressed: the same verdict as a DPoP key that is gone (`spec/errors.md`).
    private func resolveEndpoints() async throws -> EdgeNativeEndpoints {
        // A load that fails is the store's failure, typed, and not "no endpoints": only an absent or an
        // undecodable record is that, and it is the store that tells the two apart (`FileEdgeEndpointsStore`).
        let loaded: EdgeNativeEndpoints?
        do { loaded = try await endpoints.load() } catch { throw edgeStoreFailure(error) }
        guard let stored = loaded,
              isSecureEdgeEndpoint(stored.tokenEndpoint), isSecureEdgeEndpoint(stored.revocationEndpoint)
        else { throw Self.noEndpoints() }
        return stored
    }

    private static func noEndpoints() -> OAuthError { .reauthenticate(.credentialsInvalidated) }

    /// Every native endpoint demands a proof, so a token that is not DPoP-bound is not what was asked for.
    private static func requireDpopBound(_ response: TokenResponse) throws {
        if response.tokenType.caseInsensitiveCompare("DPoP") != .orderedSame {
            throw OAuthError.configuration(.hardwareBindingUnavailable(detail: "the token endpoint issued a \(response.tokenType) token for a DPoP-bound request"))
        }
    }
}
