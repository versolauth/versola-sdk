import Foundation

/// Validates a redirect against the pending request that produced it.
///
/// The order is normative (`spec/state-machine.md`, `Authorizing -> Authenticated`) and every
/// step happens before any network call: `state`, then `iss`, then the response's own error,
/// then the presence of `code`. A failure at any step means nothing reaches the token endpoint.
package enum AuthorizationResponseValidator {

    /// The `state` a redirect carries, or nil when it carries none.
    ///
    /// Only for telling which of this process's own authorizations a redirect answers. It
    /// decides nothing: a redirect that reaches `validate` is still compared against the
    /// pending request in constant time, an absent `state` included.
    package static func stateOf(_ redirect: URL) -> String? {
        parseQuery(redirect)["state"]
    }

    /// The query of `url` as a dictionary, tolerant of whatever the OS delivered: a malformed
    /// percent escape stays as typed instead of trapping or failing, a repeated name keeps its
    /// first value, a name without `=` has an empty value. Query only: the SDK requests
    /// `response_type=code`, whose default response mode is `query`.
    package static func parseQuery(_ url: URL) -> [String: String] {
        var result: [String: String] = [:]
        for (name, value) in queryPairs(url) where result[name] == nil {
            result[name] = value
        }
        return result
    }

    /// - Throws: `configuration(.stateMismatch)`, `.issuerMismatch`, `.malformedAuthorizationResponse`,
    ///   `.authorizationRejected`, or `reauthenticate(...)` for the provider's own refusals.
    package static func validate(
        redirect: URL,
        pending: PendingAuthorizationRequest,
        issuer: String,
        issParameterSupported: Bool
    ) throws -> AuthorizationGrant {
        let pairs = queryPairs(redirect)
        let parameters = parseQuery(redirect)

        // A repeated security parameter is malformed, not first-wins: the server refuses
        // duplicates for the same reason, and ambiguity is how a smuggled parameter gets read.
        // `parseQuery` keeps the first for callers that only route on `state`.
        for name in ["state", "iss", "error", "code"] where pairs.filter({ $0.0 == name }).count > 1 {
            throw OAuthError.configuration(.malformedAuthorizationResponse)
        }

        // 1. state, in constant time. An absent state is a mismatch, not a separate case: the
        //    SDK always sends one.
        guard let state = parameters["state"],
              SecureTokens.constantTimeEquals(pending.state, state) else {
            throw OAuthError.configuration(.stateMismatch)
        }

        // The redirect must be to the URI the request named. Not part of the specified order:
        // it only runs once `state` has shown that the redirect answers this request, and it
        // keeps a code delivered to another URL from being exchanged.
        guard redirectMatches(redirect, pending.redirectUri) else {
            throw OAuthError.configuration(.malformedAuthorizationResponse)
        }

        // 2. iss (RFC 9207). Present means it must match, a trailing slash tolerated. Absent
        //    fails only when the provider advertises support, or the request recorded that
        //    its exchange requires it; a deployment that does not may legitimately omit it.
        let iss = parameters["iss"]
        if let iss {
            if trimSlash(iss) != trimSlash(issuer) {
                throw OAuthError.configuration(.issuerMismatch(expected: issuer, received: iss))
            }
        } else if issParameterSupported || pending.issRequired {
            throw OAuthError.configuration(.issuerMismatch(expected: issuer, received: nil))
        }

        // 3. An error the authorization endpoint redirected back. After state and iss, so an
        //    injected error response cannot short-circuit those.
        if let code = parameters["error"] {
            throw authorizationError(code, description: parameters["error_description"])
        }

        // 4. code.
        guard let code = parameters["code"], !code.isEmpty else {
            throw OAuthError.configuration(.malformedAuthorizationResponse)
        }

        return AuthorizationGrant(
            code: code,
            codeVerifier: pending.codeVerifier,
            redirectUri: pending.redirectUri,
            resources: pending.resources,
            extensions: pending.extensions,
            nonce: pending.nonce,
            scopes: pending.scopes,
            state: pending.state,
            iss: iss,
            maxAge: pending.maxAge
        )
    }

    /// `spec/errors.md`, authorization endpoint table. The four that mean "the user has to sign
    /// in again" are `reauthenticate`; everything else is a `configuration` fault, so a provider
    /// that invents codes is reported rather than silently succeeding.
    private static func authorizationError(_ code: String, description: String?) -> OAuthError {
        switch code {
        case "access_denied":
            return .reauthenticate(.authorizationDenied)
        case "login_required", "consent_required", "interaction_required", "account_selection_required":
            return .reauthenticate(.interactionRequired(code: code))
        default:
            return .configuration(.authorizationRejected(code: code, description: description))
        }
    }

    private static func queryPairs(_ url: URL) -> [(String, String)] {
        guard let query = URLComponents(url: url, resolvingAgainstBaseURL: false)?.percentEncodedQuery else {
            return []
        }
        var pairs: [(String, String)] = []
        for part in query.split(separator: "&", omittingEmptySubsequences: true) {
            let separator = part.firstIndex(of: "=")
            let rawName = separator.map { String(part[..<$0]) } ?? String(part)
            let rawValue = separator.map { String(part[part.index(after: $0)...]) } ?? ""
            let name = decode(rawName)
            if name.isEmpty { continue }
            pairs.append((name, decode(rawValue)))
        }
        return pairs
    }

    /// Form decoding: `+` is a space, `%XX` a byte. A sequence that is not valid UTF-8
    /// percent-encoding is returned as typed, so it can fail a comparison but not the parser.
    private static func decode(_ raw: String) -> String {
        let spaced = raw.replacingOccurrences(of: "+", with: " ")
        return spaced.removingPercentEncoding ?? spaced
    }

    /// Scheme and host are case-insensitive, the path is not; a query on either side is ignored.
    private static func redirectMatches(_ redirect: URL, _ expected: String) -> Bool {
        guard let left = URLComponents(url: redirect, resolvingAgainstBaseURL: false),
              let right = URLComponents(string: expected) else { return false }
        func path(_ components: URLComponents) -> String { components.path.isEmpty ? "/" : components.path }
        return left.scheme?.lowercased() == right.scheme?.lowercased()
            && left.host?.lowercased() == right.host?.lowercased()
            && path(left) == path(right)
    }

    private static func trimSlash(_ s: String) -> String { s.hasSuffix("/") ? String(s.dropLast()) : s }
}
