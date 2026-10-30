import Foundation

/// Pushes the authorization request (RFC 9126) when the policy and the provider's metadata say
/// to, and opens the browser on the short `client_id` + `request_uri` URI it gets back; the
/// decision table is `spec/oauth-sdk-api.md` section 7.
///
/// Decided at `start` from the metadata it is handed, not at construction: discovery is lazy
/// and cached, so the endpoint is not known any earlier, and a provider that starts requiring
/// PAR is noticed at the next login.
///
/// Pushing changes only what crosses the browser. The verifier stays on the pending request and
/// the grant carries no extension, so the code is redeemed at the token endpoint as it would be
/// for the plain request. A package client has no credential, so the push carries none: the form
/// is exactly what the query would have been, `client_id` included. Nothing here retries itself; the
/// operation's budget decides that (a push is repeated: a second one creates a second `request_uri`
/// and the first expires unused, so nothing is spent), and the `HTTPClient` contract is that
/// redirects are not followed.
package struct PushedAuthorizationStarter: AuthorizationStarter {
    private let configuration: CoreConfiguration
    private let httpClient: HTTPClient
    private let policy: PushedAuthorization

    package init(configuration: CoreConfiguration, httpClient: HTTPClient, policy: PushedAuthorization) {
        self.configuration = configuration
        self.httpClient = httpClient
        self.policy = policy
    }

    package func start(request: AuthorizationRequest, metadata: ProviderMetadata, now: Date) async throws
        -> StartedAuthorization {
        let advertised = metadata.pushedAuthorizationRequestEndpoint.flatMap { $0.isEmpty ? nil : $0 }
        // The endpoint to push to, or nil for the plain request.
        let endpoint: String?
        switch policy {
        case .never: endpoint = nil
        case .whenAdvertised: endpoint = advertised
        case .required:
            guard let advertised else { throw Self.unsupported() }
            endpoint = advertised
        }
        let pending = request.toPending(
            createdAt: now, issRequired: metadata.authorizationResponseIssParameterSupported
        )
        guard let endpoint else {
            // Honoured whatever the option says: a plain request the provider will refuse is
            // worse than naming the capability that is missing. This also catches a provider
            // that requires PAR yet advertises nowhere to push to.
            if metadata.requirePushedAuthorizationRequests { throw Self.unsupported() }
            return StartedAuthorization(
                pending: pending, browserUri: try request.toUri(authorizationEndpoint: metadata.authorizationEndpoint)
            )
        }
        let requestUri = try await push(to: endpoint, request: request)
        return StartedAuthorization(
            pending: pending,
            browserUri: try FormEncoding.withQuery(
                metadata.authorizationEndpoint,
                [("client_id", configuration.clientId), ("request_uri", requestUri)]
            )
        )
    }

    private static func unsupported() -> OAuthError {
        .configuration(.providerUnsupported(capability: "par"))
    }

    /// One POST; returns the `request_uri`, or throws before anything is persisted or opened.
    private func push(to endpoint: String, request: AuthorizationRequest) async throws -> String {
        try ProviderMetadata.requireSecure("pushed_authorization_request_endpoint", endpoint)
        guard let url = URL(string: endpoint), url.scheme != nil else {
            throw OAuthError.configuration(.invalidConfiguration(
                detail: "pushed_authorization_request_endpoint is not a URL"
            ))
        }
        let httpRequest = HTTPRequest(
            method: .post, url: url,
            headers: ["Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded"],
            body: FormEncoding.body(request.formParameters())
        )
        let httpClient = self.httpClient
        let response: HTTPResponse = try await OperationBudget.run(origin: DpopOrigin.of(url)) {
            let response: HTTPResponse
            do {
                response = try await httpClient.send(httpRequest)
            } catch is CancellationError {
                throw CancellationError()
            } catch let error as OAuthError {
                throw error
            } catch {
                throw OAuthError.recoverable(.network(
                    detail: "pushed authorization request failed: \(type(of: error))", attempts: 1, elapsedMillis: 0
                ))
            }
            if let failure = ServerFailure.error(for: response) { throw failure }
            return response
        }
        return try interpret(status: response.statusCode, body: response.body)
    }

    /// RFC 9126 section 2.2: 201 with `request_uri` and `expires_in`; section 2.3: an error
    /// response, 400 for a request the provider refuses. 200 is accepted as well, which some
    /// providers send. RFC 9126 points at RFC 6749 section 5.2, which uses 401 for
    /// `invalid_client`, and some providers answer 403 for a client not allowed to push: each
    /// carries the error code the app is promised in `authorizationRejected`.
    private func interpret(status: Int, body: Data) throws -> String {
        if status == 200 || status == 201 { return try requestUri(body) }
        if [400, 401, 403].contains(status),
           let error = try? JSONDecoder().decode(ErrorPayload.self, from: body),
           let code = error.error, !code.isEmpty {
            throw OAuthError.configuration(.authorizationRejected(code: code, description: error.errorDescription))
        }
        throw OAuthError.configuration(.invalidConfiguration(detail: "PAR endpoint answered \(status)"))
    }

    private func requestUri(_ body: Data) throws -> String {
        let parsed: ResponsePayload
        do {
            parsed = try JSONDecoder().decode(ResponsePayload.self, from: body)
        } catch {
            throw OAuthError.configuration(.invalidConfiguration(detail: "PAR response is not valid JSON"))
        }
        guard let requestUri = parsed.requestUri, !requestUri.isEmpty,
              let expiresIn = parsed.expiresIn, expiresIn > 0 else {
            throw OAuthError.configuration(.invalidConfiguration(
                detail: "PAR response lacks a request_uri or a positive expires_in"
            ))
        }
        return requestUri
    }

    private struct ResponsePayload: Decodable {
        let requestUri: String?
        let expiresIn: Int64?
        enum CodingKeys: String, CodingKey {
            case requestUri = "request_uri"
            case expiresIn = "expires_in"
        }
    }

    private struct ErrorPayload: Decodable {
        let error: String?
        let errorDescription: String?
        enum CodingKeys: String, CodingKey {
            case error
            case errorDescription = "error_description"
        }
    }
}
