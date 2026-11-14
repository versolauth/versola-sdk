import Foundation
import OAuthCore

/// The token endpoint through edge: `/native/complete` for the code, `/native/token` for refreshes,
/// `/native/revoke` for logout.
///
/// Edge authenticates to auth over mutual TLS and relays auth's answer as it stands -- status, body,
/// `DPoP-Nonce`, `WWW-Authenticate` -- so the responses read here are the ones `HTTPTokenClient` reads, and
/// the same `TokenRequestExecutor` reads them. What differs is what the proof is signed for: every proof
/// carries auth's mutual-TLS endpoint as `htu`, because edge forwards it byte for byte and auth verifies it
/// against its own URL. A `use_dpop_nonce` in a relayed answer is auth's nonce, cached under auth's origin.
/// The `Idempotency-Key` is forwarded too, so a refresh keeps the retry safety it has against auth directly.
package struct EdgeNativeTokenClient: TokenClient {
    private let configuration: CoreConfiguration
    private let completeUrl: URL
    private let tokenUrl: URL
    private let revokeUrl: URL
    private let httpClient: HTTPClient
    private let dpop: DpopProofSource
    private let executor: TokenRequestExecutor
    private let metadata: @Sendable () async throws -> ProviderMetadata
    private let endpoints: any EdgeEndpointsStore

    package init(
        configuration: CoreConfiguration, edgeBaseUrl: URL, httpClient: HTTPClient, dpop: DpopProofSource,
        metadata: @escaping @Sendable () async throws -> ProviderMetadata, endpoints: any EdgeEndpointsStore,
        clock: Clock = .system
    ) throws {
        self.configuration = configuration
        self.completeUrl = try edgeNativeUrl(edgeBaseUrl, endpoint: "complete", clientId: configuration.clientId)
        self.tokenUrl = try edgeNativeUrl(edgeBaseUrl, endpoint: "token", clientId: configuration.clientId)
        self.revokeUrl = try edgeNativeUrl(edgeBaseUrl, endpoint: "revoke", clientId: configuration.clientId)
        self.httpClient = httpClient
        self.dpop = dpop
        self.executor = TokenRequestExecutor(httpClient: httpClient, dpop: dpop, clock: clock)
        self.metadata = metadata
        self.endpoints = endpoints
    }

    private var unknownClient: @Sendable (Int) -> OAuthError? {
        let clientId = configuration.clientId
        return { $0 == 404 ? edgeClientUnknown(clientId) : nil }
    }

    package func exchange(_ grant: AuthorizationGrant) async throws -> TokenResponse {
        // A grant started directly against auth carries a verifier and no blob; redeeming it here would hand
        // edge a code it did not push the request for. Wiring, and it fails before the code is spent.
        guard let blob = grant.extensions[EdgeExtension.blob],
              let tokenEndpoint = grant.extensions[EdgeExtension.tokenEndpoint],
              let htu = URL(string: tokenEndpoint)
        else {
            throw OAuthError.configuration(.invalidConfiguration(detail: "the authorization was not started through edge; redeem it with HTTPTokenClient"))
        }
        guard let iss = grant.iss else {
            // Unreachable through AuthorizationResponseValidator, which requires `iss` for a request started
            // through edge; kept as a check because /native/complete does.
            throw OAuthError.configuration(.issuerMismatch(expected: configuration.issuer, received: nil))
        }
        let body = FormEncoding.body([("code", grant.code), ("state", grant.state), ("iss", iss), ("blob", blob)])
        let url = completeUrl
        let executor = self.executor
        let onStatus = unknownClient
        let issued = try await OperationBudget.runOnce(origin: DpopOrigin.of(url)) {
            try await executor.execute(url: url, body: body, idempotencyKey: nil, proofFor: htu, onStatus: onStatus)
        }
        try Self.requireDpopBound(issued)
        // Remembered for the refreshes and the revocation that follow, in this process and the next: a
        // refresh does not go through /native/start and has no other way to learn what to sign for.
        let revocation = grant.extensions[EdgeExtension.revocationEndpoint] ?? Self.siblingRevoke(of: tokenEndpoint)
        try await endpoints.save(EdgeNativeEndpoints(tokenEndpoint: tokenEndpoint, revocationEndpoint: revocation))
        return issued
    }

    package func refresh(refreshToken: String, idempotencyKey: String) async throws -> TokenResponse {
        let htu = try await resolveEndpoints().tokenEndpoint
        guard let proofFor = URL(string: htu) else {
            throw OAuthError.configuration(.invalidConfiguration(detail: "token_endpoint is not a URL"))
        }
        let body = FormEncoding.body([("grant_type", "refresh_token"), ("refresh_token", refreshToken)])
        let issued = try await executor.execute(
            url: tokenUrl, body: body, idempotencyKey: idempotencyKey, proofFor: proofFor, onStatus: unknownClient
        )
        try Self.requireDpopBound(issued)
        return issued
    }

    /// `/native/revoke`: edge checks the proof is signed for auth's revocation endpoint and relays; auth's
    /// `/revoke` itself reads no proof. A repeat is safe (RFC 7009 section 2.2), so the budget repeats it.
    package func revoke(refreshToken: String) async throws {
        let htu = try await resolveEndpoints().revocationEndpoint
        guard let proofFor = URL(string: htu) else {
            throw OAuthError.configuration(.invalidConfiguration(detail: "revocation_endpoint is not a URL"))
        }
        let body = FormEncoding.body([("token_type_hint", "refresh_token"), ("token", refreshToken)])
        let url = revokeUrl
        let httpClient = self.httpClient
        let dpop = self.dpop
        let onStatus = unknownClient
        try await OperationBudget.run(origin: DpopOrigin.of(url)) {
            var nonceAnswered = false
            while true {
                let origin = DpopOrigin.of(proofFor)
                let proof = try await dpop.proof(method: "POST", url: proofFor, nonce: await dpop.nonce(for: origin), accessToken: nil)
                var headers = TokenRequestExecutor.formHeaders
                headers["DPoP"] = proof
                let response: HTTPResponse
                do {
                    response = try await httpClient.send(HTTPRequest(method: .post, url: url, headers: headers, body: body))
                } catch let error as OAuthError {
                    throw error
                } catch is CancellationError {
                    throw CancellationError()
                } catch {
                    throw OAuthError.recoverable(.network(detail: "revocation request failed", attempts: 1, elapsedMillis: 0))
                }
                await dpop.observe(serverDate: response.header("Date"), age: response.header("Age"), origin: DpopOrigin.of(url))
                let nonce = response.header("DPoP-Nonce")
                if let nonce, !nonce.isEmpty { await dpop.observe(nonce: nonce, origin: origin) }
                if (200..<300).contains(response.statusCode) { return }
                let challenged = response.statusCode == 401 && response.header("WWW-Authenticate").flatMap(wwwAuthenticateError) == "use_dpop_nonce"
                if challenged || TokenErrorPayload.parse(response.body).error == "use_dpop_nonce" {
                    if nonceAnswered || nonce == nil || nonce!.isEmpty { throw OAuthError.recoverable(.nonceLoop(origin: origin)) }
                    nonceAnswered = true
                    continue
                }
                if let named = onStatus(response.statusCode) { throw named }
                if let failure = ServerFailure.error(for: response) { throw failure }
                let error = TokenErrorPayload.parse(response.body)
                throw OAuthError.configuration(.tokenRequestRejected(
                    code: error.error.isEmpty ? "(no error code in a HTTP \(response.statusCode) response)" : error.error,
                    description: error.errorDescription
                ))
            }
        }
    }

    /// What `/native/start` said, when this installation has completed a login through edge; otherwise
    /// discovery's endpoints, which are right wherever edge and auth agree on the URL auth names itself by.
    /// The first is edge's own configuration and the other an inference, so the order is not negotiable. Unlike
    /// Android there is no `mtls_endpoint_aliases` step: iOS's `ProviderMetadata` does not carry them.
    private func resolveEndpoints() async throws -> EdgeNativeEndpoints {
        if let stored = try await endpoints.load() { return stored }
        let document = try await metadata()
        try ProviderMetadata.requireSecure("token_endpoint", document.tokenEndpoint)
        return EdgeNativeEndpoints(
            tokenEndpoint: document.tokenEndpoint,
            revocationEndpoint: document.revocationEndpoint ?? Self.siblingRevoke(of: document.tokenEndpoint)
        )
    }

    private static func siblingRevoke(of tokenEndpoint: String) -> String {
        guard let slash = tokenEndpoint.lastIndex(of: "/") else { return tokenEndpoint }
        return String(tokenEndpoint[...slash]) + "revoke"
    }

    /// Every native endpoint demands a proof, so a token that is not DPoP-bound is not what was asked for.
    private static func requireDpopBound(_ response: TokenResponse) throws {
        if response.tokenType.caseInsensitiveCompare("DPoP") != .orderedSame {
            throw OAuthError.configuration(.hardwareBindingUnavailable(detail: "the token endpoint issued a \(response.tokenType) token for a DPoP-bound request"))
        }
    }
}
