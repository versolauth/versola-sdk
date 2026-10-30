import Foundation

/// The session as the UserInfo client sees it: a token to present, and a way to get another one
/// when the provider says the first is no good. The facade backs it with the coordinator.
package protocol AccessTokenSource: Sendable {
    /// A token not within its refresh skew, refreshing once if needed.
    func accessToken() async throws -> AccessToken
    /// Forces a refresh: the provider just rejected the token this source handed out.
    func renewAccessToken() async throws -> AccessToken
}

/// Asks the provider who the access token's user is.
package protocol UserInfoClient: Sendable {
    /// - Parameters:
    ///   - tokens: the session: its token is sent as `Bearer`, or as `DPoP` with a proof when it
    ///     is key-bound; a bare 401 spends one renewal and one replay, then is
    ///     `reauthenticate(.sessionRejected)` (`spec/errors.md`, a resource server's 401).
    ///   - expectedSubject: the `sub` of the validated ID token. Core 5.3.2: a UserInfo response
    ///     about anyone else must not be used, so a different `sub` is refused.
    /// - Throws: `configuration(.providerUnsupported("userinfo"))` without an endpoint,
    ///   `configuration(.userInfoRejected)` for a `sub` mismatch, a signed response that does not
    ///   verify or an unexpected status, `reauthenticate(.sessionRejected)` on a repeated 401,
    ///   `recoverable(.network)` on a transport failure and `recoverable(.server)` on a transient
    ///   status, both after the operation's retry budget.
    func fetch(tokens: AccessTokenSource, expectedSubject: String) async throws -> UserInfo
}

/// `UserInfoClient` over the SDK's `HTTPClient`.
///
/// Redirects are never followed (the `HTTPClient` contract), for the reason that applies to the
/// token endpoint: the request carries the access token and, when bound, a proof, and neither
/// may follow a `Location` the endpoint named in discovery did not have a right to.
///
/// No retries here. The caller's budget decides whether a transport failure is tried again
/// (`spec/retry-policy.md`); the one exception is the DPoP nonce challenge, answered once,
/// because it is a protocol step and not a retry (RFC 9449 section 9).
package struct HTTPUserInfoClient: UserInfoClient {
    private let userinfoEndpoint: @Sendable () async throws -> String?
    private let httpClient: HTTPClient
    private let dpop: DpopProofSource?
    private let verifier: JwsVerifier

    /// - Parameters:
    ///   - userinfoEndpoint: from discovery, nil when the provider has none.
    ///   - dpop: the proof source of a key-bound session; nil for a bearer one. A bound token
    ///     without a source cannot be presented and is refused as a misconfiguration.
    ///   - verifier: checks a signed (`application/jwt`) response against the provider's JWK
    ///     Set, the same one that verifies ID tokens (`spec/oauth-sdk-api.md` section 11).
    package init(
        userinfoEndpoint: @escaping @Sendable () async throws -> String?,
        httpClient: HTTPClient,
        dpop: DpopProofSource?,
        verifier: JwsVerifier
    ) {
        self.userinfoEndpoint = userinfoEndpoint
        self.httpClient = httpClient
        self.dpop = dpop
        self.verifier = verifier
    }

    private enum Outcome {
        case body(Data, signed: Bool)
        case useDpopNonce(nonce: String?)
        case rejected
    }

    package func fetch(tokens: AccessTokenSource, expectedSubject: String) async throws -> UserInfo {
        guard let endpoint = try await userinfoEndpoint() else {
            throw OAuthError.configuration(.providerUnsupported(capability: "userinfo"))
        }
        guard let url = URL(string: endpoint), url.scheme != nil, url.host != nil else {
            throw OAuthError.configuration(.invalidConfiguration(detail: "userinfo_endpoint is not an absolute URL"))
        }
        var accessToken = try await tokens.accessToken()
        if Self.isDpopBound(accessToken) && dpop == nil {
            throw OAuthError.configuration(.invalidConfiguration(
                detail: "a DPoP-bound access token needs a DpopProofSource to call the UserInfo endpoint"
            ))
        }
        var nonceRetried = false
        var renewed = false
        while true {
            // One repeatable request under the operation's budget (a read-only `GET`); the
            // nonce and renewal replays below are protocol answers, not retries of a failure.
            let token = accessToken
            switch try await OperationBudget.run(origin: DpopOrigin.of(url), { try await self.attempt(url, token) }) {
            case .body(let body, let signed):
                return try await parse(body, signed: signed, expectedSubject: expectedSubject)
            // A bare 401 is read as an expired token: one renewal, one replay, then the session
            // is what the provider says it is (`spec/errors.md`).
            case .rejected:
                if renewed { throw OAuthError.reauthenticate(.sessionRejected) }
                renewed = true
                accessToken = try await tokens.renewAccessToken()
            case .useDpopNonce(let nonce):
                // `attempt` already remembered the nonce off this response, so the next proof
                // carries it. A challenge without one, or a second challenge, cannot be answered
                // by asking again.
                if nonceRetried || (nonce ?? "").isEmpty {
                    throw OAuthError.recoverable(.nonceLoop(origin: DpopOrigin.of(url)))
                }
                nonceRetried = true
            }
        }
    }

    private static func isDpopBound(_ token: AccessToken) -> Bool {
        token.tokenType.lowercased() == "dpop"
    }

    private func attempt(_ url: URL, _ accessToken: AccessToken) async throws -> Outcome {
        let bound = Self.isDpopBound(accessToken)
        var headers = [
            "Accept": "application/json, application/jwt",
            "Authorization": (bound ? "DPoP " : "Bearer ") + accessToken.value,
        ]
        let origin = DpopOrigin.of(url)
        if bound, let dpop {
            let nonce = await dpop.nonce(for: origin)
            headers["DPoP"] = try await dpop.proof(method: "GET", url: url, nonce: nonce, accessToken: accessToken.value)
        }

        let response: HTTPResponse
        do {
            response = try await httpClient.send(HTTPRequest(method: .get, url: url, headers: headers))
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as OAuthError {
            throw error
        } catch {
            throw OAuthError.recoverable(.network(detail: "userinfo request failed", attempts: 1, elapsedMillis: 0))
        }

        // Every response may carry a nonce, not only a challenge: the next proof to this origin
        // should have it.
        let nonce = response.header("DPoP-Nonce")
        if let nonce, !nonce.isEmpty, let dpop { await dpop.observe(nonce: nonce, origin: origin) }

        switch response.statusCode {
        case 200..<300:
            return .body(response.body, signed: Self.isSigned(response))
        case 401:
            if bound, WwwAuthenticate.error(response.header("WWW-Authenticate")) == "use_dpop_nonce" {
                return .useDpopNonce(nonce: nonce)
            }
            return .rejected
        // A transient condition is the operation's retry budget (`server`, with the `Retry-After`
        // of a 429 or a 503); anything else is the provider refusing this request, which
        // retrying does not change.
        case 408, 429, 500..<600:
            throw ServerFailure.error(for: response)!
        default:
            throw OAuthError.configuration(.userInfoRejected(detail: "userinfo answered \(response.statusCode)"))
        }
    }

    /// `application/jwt`, or a body that is itself a compact JWS under another content type.
    private static func isSigned(_ response: HTTPResponse) -> Bool {
        let mediaType = response.header("Content-Type")?
            .split(separator: ";", maxSplits: 1).first
            .map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
        if mediaType == "application/jwt" { return true }
        let text = String(decoding: response.body, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        let segments = text.split(separator: ".", omittingEmptySubsequences: false)
        return segments.count == 3 && !text.contains("{") && !text.contains(where: \.isWhitespace)
    }

    private func parse(_ body: Data, signed: Bool, expectedSubject: String) async throws -> UserInfo {
        let claims: [String: JoseJSON]
        if signed {
            let compact = String(decoding: body, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            do {
                claims = try await verifier.verify(compact).claims
            } catch let rejection as JwsRejection {
                throw Self.rejected("the signed response does not verify (\(rejection.reason.rawValue))")
            }
        } else {
            guard case .object(let members)? = JoseJSON.parse(body) else {
                throw Self.rejected("the response is not a JSON object")
            }
            claims = members
        }
        guard case .string(let subject)? = claims["sub"] else { throw Self.rejected("sub is missing or not a string") }
        // Constant time is not the point here (a `sub` is not a secret that authenticates
        // anything); the value is left out of the message because it identifies a user.
        if subject != expectedSubject { throw Self.rejected("sub does not match the ID token's") }
        return UserInfo(subject: subject, claims: claims.mapValues { $0.claimText })
    }

    private static func rejected(_ detail: String) -> OAuthError {
        .configuration(.userInfoRejected(detail: detail))
    }
}

/// The auth-params of a `WWW-Authenticate` challenge (RFC 9110 11.6.1), read far enough to find
/// `error`. Scanned rather than searched for `error=`, so that the text of an
/// `error_description="... error=..."` cannot be mistaken for the parameter.
enum WwwAuthenticate {
    /// The first `error` parameter of any challenge in `header`, nil when there is none.
    static func error(_ header: String?) -> String? {
        guard let header else { return nil }
        let chars = Array(header)
        var i = 0
        func skipSeparators() { while i < chars.count, chars[i] == " " || chars[i] == "\t" || chars[i] == "," { i += 1 } }
        func token() -> String {
            let start = i
            while i < chars.count, !(chars[i] == " " || chars[i] == "\t" || chars[i] == "," || chars[i] == "=") { i += 1 }
            return String(chars[start..<i])
        }
        while i < chars.count {
            skipSeparators()
            let name = token()
            while i < chars.count, chars[i] == " " || chars[i] == "\t" { i += 1 }
            guard i < chars.count, chars[i] == "=" else { continue }   // a scheme name, not a parameter
            i += 1
            while i < chars.count, chars[i] == " " || chars[i] == "\t" { i += 1 }
            var value = ""
            if i < chars.count, chars[i] == "\"" {
                i += 1
                while i < chars.count, chars[i] != "\"" {
                    if chars[i] == "\\", i + 1 < chars.count { i += 1 }
                    value.append(chars[i])
                    i += 1
                }
                i += 1
            } else {
                value = token()
            }
            if name.lowercased() == "error" { return value }
        }
        return nil
    }
}
