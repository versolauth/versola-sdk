import Foundation

/// Redeems grants at the token endpoint: `authorization_code` once per login, `refresh_token`
/// for as long as the session lives; RFC 7009 revocation at sign-out.
///
/// Deliberately no client secret anywhere in this interface or its implementation. A mobile
/// client is package (#1 §2), and a parameter that cannot be expressed cannot be shipped by an
/// integrator who was sure it would be fine.
///
/// Single-flight coordination, the rotation slot and the retry budget are **not** here. This
/// type performs one exchange per call; what decides how many calls there are, and in what
/// order they touch storage, is the session coordinator above it.
package protocol TokenClient: Sendable {
    /// Redeems a validated authorization code. The PKCE verifier goes with it.
    func exchange(_ grant: AuthorizationGrant) async throws -> TokenResponse

    /// Spends a refresh token. `idempotencyKey` is derived from the generation being spent and
    /// persisted beside it, so a retry after a dropped response resolves to the same rotation;
    /// whether it is sent is the implementation's policy (a standard does not define it).
    func refresh(refreshToken: String, idempotencyKey: String) async throws -> TokenResponse

    /// RFC 7009: ends the grant at the server rather than at expiry. Best effort by contract:
    /// `logout()` wipes local state whether or not this succeeded. A provider that advertises
    /// no `revocation_endpoint` is not a failure; the grant dies at expiry as it would have.
    func revoke(refreshToken: String) async throws
}

/// The token endpoint over the injected `HTTPClient`, as a package client of the provider.
///
/// Two protocol-shaped retries live here rather than in the caller's budget, because both are
/// answers to a challenge rather than to a failure, and `spec/retry-policy.md` fixes each at
/// exactly one: `use_dpop_nonce` (the nonce arrives in the response, so the second attempt is
/// the first that could have carried it; a second demand is `nonceLoop`, scenario 05) and
/// `invalid_dpop_proof` (a second failure means the key does not match the grant).
/// Everything else this type raises is final: it has no budget of its own and does not sleep.
///
/// The `HTTPClient` never follows redirects: a 307 or 308 repeats the method and the body, and
/// one `Location` from anything able to answer as the token endpoint would repost a code or a
/// refresh token to another origin, with the proof minted for this one.
package struct HTTPTokenClient: TokenClient {
    private let configuration: CoreConfiguration
    private let metadata: @Sendable () async throws -> ProviderMetadata
    private let httpClient: HTTPClient
    private let dpop: DpopProofSource?
    private let tokenBinding: TokenBinding
    private let sendIdempotencyKey: Bool

    /// - Parameters:
    ///   - dpop: nil for a session that is not key-bound.
    ///   - sendIdempotencyKey: whether a refresh carries `Idempotency-Key`. Versola honours it;
    ///     no standard asks a provider to, so the generic facade passes false (ADR 0001).
    package init(
        configuration: CoreConfiguration,
        metadata: @escaping @Sendable () async throws -> ProviderMetadata,
        httpClient: HTTPClient,
        dpop: DpopProofSource? = nil,
        tokenBinding: TokenBinding = .bearer,
        sendIdempotencyKey: Bool = false
    ) throws {
        // The same pairing the flow refuses: with no proof source a key-bound request goes out
        // unbound. Wiring, not deployment, so it fails here rather than at the first exchange.
        if case .dpop = tokenBinding, dpop == nil {
            throw OAuthError.configuration(.invalidConfiguration(detail: "TokenBinding.dpop needs a DpopProofSource; pass one or select .bearer"))
        }
        self.configuration = configuration
        self.metadata = metadata
        self.httpClient = httpClient
        self.dpop = dpop
        self.tokenBinding = tokenBinding
        self.sendIdempotencyKey = sendIdempotencyKey
    }

    package func exchange(_ grant: AuthorizationGrant) async throws -> TokenResponse {
        if !grant.extensions.isEmpty {
            // A code a back channel pushed the request for is redeemable only there, with its
            // artefacts; presenting it here would spend it for an `invalid_grant`.
            throw OAuthError.configuration(.invalidConfiguration(detail: "the authorization was started through a back channel that kept the verifier; redeem it with that channel's TokenClient"))
        }
        var form: [(String, String)] = [
            ("grant_type", "authorization_code"),
            ("code", grant.code),
            ("redirect_uri", grant.redirectUri),
            ("code_verifier", grant.codeVerifier),
            ("client_id", configuration.clientId),
        ]
        // RFC 8707 §2.2: repeated on the code exchange, so the token is issued for the
        // audience the user consented to. Not on refresh: the grant's audience is fixed.
        for resource in grant.resources { form.append(("resource", resource)) }
        return try await post(form, idempotencyKey: nil, once: true)
    }

    package func refresh(refreshToken: String, idempotencyKey: String) async throws -> TokenResponse {
        let form: [(String, String)] = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refreshToken),
            ("client_id", configuration.clientId),
        ]
        return try await post(form, idempotencyKey: sendIdempotencyKey ? idempotencyKey : nil, once: false)
    }

    /// `POST` to `revocation_endpoint` as a package client: `token`, `token_type_hint` and
    /// `client_id`, nothing else, and no `DPoP` header (RFC 9449 binds the token endpoint and
    /// resource access, not revocation). RFC 7009 §2.2 answers 200 for an unknown token too,
    /// so a 2xx says only that the server took the request.
    package func revoke(refreshToken: String) async throws {
        guard let endpoint = try await metadata().revocationEndpoint, !endpoint.isEmpty, let url = URL(string: endpoint) else { return }
        let body = FormEncoding.body([
            ("token_type_hint", "refresh_token"),
            ("token", refreshToken),
            ("client_id", configuration.clientId),
        ])
        let request = HTTPRequest(method: .post, url: url, headers: Self.formHeaders, body: body)
        let httpClient = self.httpClient
        // Revoking a token that is already revoked succeeds (RFC 7009 section 2.2), so a repeat
        // is safe, and under the operation's budget it is made (`spec/retry-policy.md`).
        try await OperationBudget.run(origin: DpopOrigin.of(url)) {
            let response: HTTPResponse
            do {
                response = try await httpClient.send(request)
            } catch let error as OAuthError {
                throw error
            } catch {
                throw OAuthError.recoverable(.network(detail: "revocation request failed", attempts: 1, elapsedMillis: 0))
            }
            if (200..<300).contains(response.statusCode) { return }
            // The same split `rejected` draws: 5xx, 408 and 429 are the provider having a bad
            // moment; anything else is a request it understood and refused.
            if let failure = ServerFailure.error(for: response) { throw failure }
            let error = TokenErrorPayload.parse(response.body)
            throw OAuthError.configuration(.tokenRequestRejected(
                code: error.error.isEmpty ? "(no error code in a HTTP \(response.statusCode) response)" : error.error,
                description: error.errorDescription
            ))
        }
    }

    /// - Parameter once: the `authorization_code` exchange, which is never repeated: under the
    ///   operation's cooldown and answering a `Retry-After` with one, but no more than one request.
    private func post(_ form: [(String, String)], idempotencyKey: String?, once: Bool) async throws -> TokenResponse {
        let metadata = try await metadata()
        // Before the request, not after one succeeds: for an authorization code "useless"
        // means spent, and discovery already said whether the deployment can bind the grant.
        if case .dpop(let required) = tokenBinding, required, !metadata.supportsDpop {
            throw OAuthError.configuration(.hardwareBindingUnavailable(detail: "the provider does not advertise dpop_signing_alg_values_supported"))
        }
        guard let url = URL(string: metadata.tokenEndpoint) else {
            throw OAuthError.configuration(.discoveryMalformed(detail: "token_endpoint is not a URL"))
        }
        // A proof goes on the request exactly when the pairing can produce one the deployment
        // will honour (#1 §4: bearer where DPoP is not advertised, unless `required`).
        let proofFor: URL?
        if case .dpop = tokenBinding, metadata.supportsDpop { proofFor = url } else { proofFor = nil }
        let body = FormEncoding.body(form)
        let response: TokenResponse
        if once {
            response = try await OperationBudget.runOnce(origin: DpopOrigin.of(url)) {
                try await self.execute(url: url, body: body, idempotencyKey: idempotencyKey, proofFor: proofFor)
            }
        } else {
            response = try await execute(url: url, body: body, idempotencyKey: idempotencyKey, proofFor: proofFor)
        }
        try accept(response)
        return response
    }

    /// `required` DPoP: a token the endpoint issued as `Bearer` for a DPoP-bound request is refused.
    private func accept(_ response: TokenResponse) throws {
        if case .dpop(let required) = tokenBinding, required, response.tokenType.caseInsensitiveCompare("DPoP") != .orderedSame {
            throw OAuthError.configuration(.hardwareBindingUnavailable(detail: "the token endpoint issued a \(response.tokenType) token for a DPoP-bound request"))
        }
    }

    private enum Attempt {
        case issued(TokenResponse)
        case useDpopNonce(String?)
        case invalidProof
    }

    private func execute(url: URL, body: Data, idempotencyKey: String?, proofFor: URL?) async throws -> TokenResponse {
        var nonceRetried = false
        var proofRetried = false
        while true {
            switch try await attempt(url: url, body: body, idempotencyKey: idempotencyKey, proofFor: proofFor) {
            case .issued(let response):
                return response
            case .useDpopNonce(let nonce):
                // The nonce is in the proof source by now, so the retry's proof picks it up.
                // A challenge without one cannot be answered, and a second demand is a server
                // that will never be satisfied: `nonceLoop` rather than a third attempt.
                if nonceRetried || nonce == nil || nonce!.isEmpty {
                    throw OAuthError.recoverable(.nonceLoop(origin: DpopOrigin.of(proofFor ?? url)))
                }
                nonceRetried = true
            case .invalidProof:
                if proofRetried { throw OAuthError.reauthenticate(.credentialsInvalidated) }
                proofRetried = true
            }
        }
    }

    private func attempt(url: URL, body: Data, idempotencyKey: String?, proofFor: URL?) async throws -> Attempt {
        var headers = Self.formHeaders
        if let idempotencyKey { headers["Idempotency-Key"] = idempotencyKey }
        if let proofFor, let dpop {
            let origin = DpopOrigin.of(proofFor)
            headers["DPoP"] = try await dpop.proof(method: "POST", url: proofFor, nonce: await dpop.nonce(for: origin), accessToken: nil)
        }
        let response: HTTPResponse
        do {
            response = try await httpClient.send(HTTPRequest(method: .post, url: url, headers: headers, body: body))
        } catch let error as OAuthError {
            throw error
        } catch {
            throw OAuthError.recoverable(.network(detail: "token request failed", attempts: 1, elapsedMillis: 0))
        }
        // Before the answer is read, so an `invalid_dpop_proof` retry mints from the server's clock.
        if let dpop { await dpop.observe(serverDate: response.header("Date"), age: response.header("Age")) }
        // Under the origin the proof was for: that server issued the nonce and will check it.
        if let nonce = response.header("DPoP-Nonce"), !nonce.isEmpty, let dpop {
            await dpop.observe(nonce: nonce, origin: DpopOrigin.of(proofFor ?? url))
        }
        if (200..<300).contains(response.statusCode) {
            return .issued(try Self.issued(response.body, dateHeader: response.header("Date")))
        }
        return try Self.rejected(response)
    }

    private static func issued(_ body: Data, dateHeader: String?) throws -> TokenResponse {
        guard let object = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] else {
            throw OAuthError.configuration(.tokenResponseMalformed(detail: "the token response is not a JSON object"))
        }
        guard let accessToken = object["access_token"] as? String, !accessToken.isEmpty else {
            throw OAuthError.configuration(.tokenResponseMalformed(detail: "access_token missing"))
        }
        guard let tokenType = object["token_type"] as? String, !tokenType.isEmpty else {
            throw OAuthError.configuration(.tokenResponseMalformed(detail: "token_type missing"))
        }
        // `expires_in` is a number; a string of digits is tolerated, anything else is unknown.
        let expiresIn: Int
        switch object["expires_in"] {
        case let number as NSNumber: expiresIn = max(0, number.intValue)
        case let text as String: expiresIn = max(0, Int(text) ?? 0)
        default: expiresIn = 0
        }
        return TokenResponse(
            accessToken: accessToken,
            tokenType: tokenType,
            expiresIn: expiresIn,
            refreshToken: (object["refresh_token"] as? String).flatMap { $0.isEmpty ? nil : $0 },
            idToken: (object["id_token"] as? String).flatMap { $0.isEmpty ? nil : $0 },
            scope: object["scope"] as? String,
            serverDate: dateHeader.flatMap(HTTPDate.parse)
        )
    }

    private static func rejected(_ response: HTTPResponse) throws -> Attempt {
        let status = response.statusCode
        let body = response.body
        let nonce = response.header("DPoP-Nonce")
        let wwwAuthenticate = response.header("WWW-Authenticate")
        // A redirect that was not followed. The Location is deliberately not reported: the
        // token endpoint is whatever discovery said it was.
        if (300..<400).contains(status) {
            throw OAuthError.configuration(.tokenRequestRejected(code: "(the token endpoint answered HTTP \(status); redirects are not followed)", description: nil))
        }
        if status == 401, let challenge = wwwAuthenticate.flatMap(wwwAuthenticateError) {
            switch challenge {
            case "use_dpop_nonce": return .useDpopNonce(nonce)
            case "invalid_dpop_proof": return .invalidProof
            default: break
            }
        }
        // 5xx is the provider having a bad moment, and its body is as likely to be an HTML
        // page as JSON. A 408, a 429 and a 5xx are `server`, with the `Retry-After` of a 429
        // or a 503; whether it is repeated is the caller's budget's decision (a refresh is, the
        // authorization_code exchange is not).
        if let failure = ServerFailure.error(for: response) { throw failure }
        guard let error = TokenErrorPayload.parseStrict(body) else {
            // A 4xx that is not an OAuth error response is something other than a token
            // endpoint answering at this URL.
            throw OAuthError.configuration(.tokenRequestRejected(code: "(no OAuth error in a HTTP \(status) response)", description: nil))
        }
        switch error.error {
        case "use_dpop_nonce": return .useDpopNonce(nonce)
        case "invalid_dpop_proof": return .invalidProof
        case "invalid_grant": throw OAuthError.reauthenticate(.grantRejected)
        default:
            throw OAuthError.configuration(.tokenRequestRejected(
                code: error.error.isEmpty ? "(no error code in a HTTP \(status) response)" : error.error,
                description: error.errorDescription
            ))
        }
    }

    static let formHeaders: [String: String] = [
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
    ]

}

/// An RFC 6749 §5.2 error body. Lenient: the fields are read when present.
struct TokenErrorPayload: Sendable {
    var error: String = ""
    var errorDescription: String?

    static func parse(_ body: Data) -> TokenErrorPayload { parseStrict(body) ?? TokenErrorPayload() }

    /// nil when the body is not a JSON object at all.
    static func parseStrict(_ body: Data) -> TokenErrorPayload? {
        guard let object = (try? JSONSerialization.jsonObject(with: body)) as? [String: Any] else { return nil }
        return TokenErrorPayload(error: object["error"] as? String ?? "", errorDescription: object["error_description"] as? String)
    }
}

/// The `error` parameter of a `WWW-Authenticate` header, quoted or bare, across challenges.
package func wwwAuthenticateError(_ header: String) -> String? {
    let pattern = try! NSRegularExpression(pattern: #"(?:^|[\s,])error\s*=\s*(?:"([^"]*)"|([^\s,]+))"#)
    let range = NSRange(header.startIndex..., in: header)
    guard let match = pattern.firstMatch(in: header, range: range) else { return nil }
    for group in 1...2 {
        if let r = Range(match.range(at: group), in: header) { return String(header[r]) }
    }
    return nil
}

/// RFC 9110 §5.6.7 dates (`Sun, 06 Nov 1994 08:49:37 GMT`); an unreadable one is only an absent clock.
enum HTTPDate {
    static func parse(_ text: String) -> Date? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
        return formatter.date(from: text)
    }

    static func format(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        return formatter.string(from: date)
    }
}
