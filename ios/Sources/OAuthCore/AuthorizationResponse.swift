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

    /// The `error` code a redirect carries, only when it is a plain token (RFC 6749 section 5.2
    /// codes are), at most 64 characters: for the one log line about an ignored redirect, where a
    /// code from untrusted input must not be a way to put arbitrary text in a log. Nil otherwise.
    package static func errorCode(of redirect: URL) -> String? {
        guard let code = parseQuery(redirect)["error"], (1...64).contains(code.utf8.count),
              code.utf8.allSatisfy({ ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x41 && $0 <= 0x5A) || ($0 >= 0x61 && $0 <= 0x7A) || $0 == 0x5F || $0 == 0x2E || $0 == 0x2D })
        else { return nil }
        return code
    }

    /// Whether `redirect` carries exactly `state`, compared in constant time; a redirect with no
    /// `state` does not. How the flow tells the response to its request from any other redirect
    /// for the same URI (scenario 15), and how a browser session tells that its own page ended
    /// with something else.
    package static func carries(_ redirect: URL, state: String) -> Bool {
        guard let received = stateOf(redirect) else { return false }
        return SecureTokens.constantTimeEquals(state, received)
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

        // 2. iss (RFC 9207 section 2.4). Present means an exact string match to the discovered
        //    issuer: a trailing slash or case difference identifies a different issuer. Absent
        //    fails only when the provider advertises support, or the request recorded that
        //    its exchange requires it; a deployment that does not may legitimately omit it.
        let iss = parameters["iss"]
        if let iss {
            if iss != issuer {
                throw OAuthError.configuration(.issuerMismatch(expected: issuer, received: boundedText(iss, limit: 256)))
            }
        } else if issParameterSupported || pending.issRequired {
            throw OAuthError.configuration(.issuerMismatch(expected: issuer, received: nil))
        }

        // The redirect must be to the URI the request named (scheme, host, port and path): `state`
        // proves which request a redirect answers, not where it was sent, and a code delivered to
        // another URL must not be exchanged. After `iss`, before the provider's own `error`
        // (`spec/state-machine.md`).
        guard redirectMatches(redirect, pending.redirectUri) else {
            throw OAuthError.configuration(.malformedAuthorizationResponse)
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
    private static func authorizationError(_ received: String, description receivedDescription: String?) -> OAuthError {
        // What a redirect carries is whoever delivered the URL's, and it ends up in logs and in the
        // error an app prints: the code is cut to the token alphabet of RFC 6749 section 5.2 and
        // to a bounded length, the description to printable text of a bounded length.
        let code = String(received.unicodeScalars.filter {
            $0.isASCII && (CharacterSet.alphanumerics.contains($0) || "_-.".unicodeScalars.contains($0))
        }.prefix(64))
        let description = receivedDescription.map { boundedText($0, limit: 256) }
        switch code.isEmpty ? "invalid_response" : code {
        case "access_denied":
            return .reauthenticate(.authorizationDenied)
        case "login_required", "consent_required", "interaction_required", "account_selection_required":
            return .reauthenticate(.interactionRequired(code: code))
        // RFC 6749 4.1.2.1: the server could not handle the request now. Surfaced once, never retried
        // by the SDK: the browser leg cannot be replayed without the user.
        case "server_error":
            return .recoverable(.server(status: 500, retryAfterMillis: nil, attempts: 1, elapsedMillis: 0))
        case "temporarily_unavailable":
            return .recoverable(.server(status: 503, retryAfterMillis: nil, attempts: 1, elapsedMillis: 0))
        default:
            return .configuration(.authorizationRejected(code: code.isEmpty ? "invalid_response" : code, description: description))
        }
    }

    /// Printable text of at most `limit` characters: control characters (a newline that forges a log
    /// line, an escape sequence for a terminal) are dropped.
    private static func boundedText(_ text: String, limit: Int) -> String {
        String(String.UnicodeScalarView(text.unicodeScalars.filter { !CharacterSet.controlCharacters.contains($0) }.prefix(limit)))
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

    /// Scheme and host are case-insensitive, ports include their HTTP(S) defaults, and the path
    /// is case-sensitive; a query on either side is ignored.
    private static func redirectMatches(_ redirect: URL, _ expected: String) -> Bool {
        guard let left = URLComponents(url: redirect, resolvingAgainstBaseURL: false),
              let right = URLComponents(string: expected) else { return false }
        func path(_ components: URLComponents) -> String { components.path.isEmpty ? "/" : components.path }
        func port(_ components: URLComponents) -> Int? {
            if let port = components.port { return port }
            switch components.scheme?.lowercased() {
            case "https": return 443
            case "http": return 80
            default: return nil
            }
        }
        return left.scheme?.lowercased() == right.scheme?.lowercased()
            && left.host?.lowercased() == right.host?.lowercased()
            && port(left) == port(right)
            && path(left) == path(right)
    }
}
