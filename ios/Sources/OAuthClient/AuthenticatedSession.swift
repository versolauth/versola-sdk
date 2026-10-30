import Foundation
import os


/// Which requests get a token. A token sent to a host the app did not name is a leak, so the
/// scope is explicit: exactly these origins (`scheme://host[:port]`, the default port applied),
/// any path. Another port, another scheme or another host is another origin.
package struct RequestScope: Sendable {
    private let origins: Set<String>

    /// - Throws: `invalidConfiguration` for an empty set (a scope that matches nothing is a
    ///   mistake, not a safe default), for an origin that is not `https` (`http` only on a
    ///   loopback host), or one with a path, query or fragment.
    package init(origins: Set<String>) throws {
        if origins.isEmpty { throw URLRules.invalid("at least one protected origin is required") }
        self.origins = Set(try origins.map { try URLRules.parseOrigin($0, name: "origins") })
    }

    package func includes(_ url: URL) -> Bool {
        guard let scheme = url.scheme, URLRules.normalizedHost(url.host) != nil else { return false }
        return origins.contains(URLRules.originString(scheme: scheme, host: url.host, port: url.port))
    }
}

/// The authenticated leg: a token on every request to a protected origin, a DPoP proof over it
/// under DPoP, and the four things a 401 can mean. A `URLSession` wrapper rather than a
/// subclass, which keeps the surface to the one method apps need.
///
/// No retry budget of its own: every repeat is one of the fixed protocol ceilings (one nonce
/// retry, one proof retry, one replay after a refresh), and the refresh spends the
/// coordinator's budget rather than opening a second one beside it.
public final class AuthenticatedSession: Sendable {
    private let tokens: any AccessTokenSource
    private let scope: RequestScope
    private let dpop: (any DpopProofSource)?
    private let session: URLSession

    /// - Parameters:
    ///   - dpop: nil under bearer, and then no proof goes on any request.
    ///   - session: the app's session; redirects are switched off on every request through it.
    /// Told when a step-up challenge arrives, before it is thrown: the coordinator publishes
    /// `stepUpRequired` so the state machine shows the pause (`spec/state-machine.md`).
    private let onStepUp: (@Sendable () async -> Void)?

    package init(tokens: any AccessTokenSource, scope: RequestScope, dpop: (any DpopProofSource)?, session: URLSession, onStepUp: (@Sendable () async -> Void)? = nil) {
        self.tokens = tokens
        self.scope = scope
        self.dpop = dpop
        self.onStepUp = onStepUp
        self.session = session
    }

    /// Performs `request`, attaching the session when its URL is inside the scope.
    ///
    /// - A request outside the scope goes through untouched, 401 included: it is not ours to
    ///   handle, and attaching a token to the request that obtains one is a recursion.
    /// - A redirect is never followed: the 3xx is returned as it is. A `Location` on another
    ///   origin must not get the token, and the app decides whether to follow it.
    /// - Throws `OAuthError.stepUp` on an RFC 9470 challenge, `.reauthenticate(.sessionRejected)`
    ///   when a refreshed token is refused too, and the coordinator's own errors from the token.
    public func data(for request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        guard let url = request.url, scope.includes(url) else {
            let (data, response, _) = try await send(request)
            return (data, response)
        }
        let origin = DpopOrigin.of(url)
        var token = try await tokens.accessToken()
        var nonceRetried = false
        var proofRetried = false
        var refreshed = false

        while true {
            let (data, response, fromCache) = try await send(try await sign(request, url: url, token: token, origin: origin))
            // The server's clock, off every answer the network gave: a response the URL cache
            // served carries the `Date` of when it was stored, which is not now.
            if let dpop {
                await dpop.observe(serverDate: fromCache ? nil : response.value(forHTTPHeaderField: "Date"), age: response.value(forHTTPHeaderField: "Age"))
            }
            if let dpop, let nonce = response.value(forHTTPHeaderField: "DPoP-Nonce"), !nonce.isEmpty {
                await dpop.observe(nonce: nonce, origin: origin)
            }
            guard response.statusCode == 401 else { return (data, response) }

            // By parameter name, never by scheme: a server may put `insufficient_user_authentication`
            // under `Bearer` while using `DPoP` for the nonce and proof errors, and a client keyed
            // on the scheme misses every step-up.
            let challenge = AuthenticateChallenge.merged(
                AuthenticateChallenge.parse(response.value(forHTTPHeaderField: "WWW-Authenticate") ?? "")
            )
            switch challenge["error"] {
            case "use_dpop_nonce":
                // The nonce is already cached off this response, so the next proof carries it.
                // A challenge with none cannot be answered, and a second one means the origin
                // keeps changing its mind: the unbounded loop scenario 05 rules out.
                if nonceRetried || (response.value(forHTTPHeaderField: "DPoP-Nonce") ?? "").isEmpty {
                    throw OAuthError.recoverable(.nonceLoop(origin: origin))
                }
                nonceRetried = true

            case "invalid_dpop_proof":
                // The one recoverable cause is clock skew, learned off this response's `Date`
                // (above), so the retry's proof is minted from the server's clock. A second
                // refusal means the key does not match the grant, and a refresh reuses the
                // same key, so no refresh repairs it.
                if proofRetried { throw OAuthError.reauthenticate(.credentialsInvalidated) }
                proofRetried = true

            case "insufficient_user_authentication":
                // RFC 9470, and deliberately the one branch that does not refresh: the token is
                // valid, its authentication context is not, and a refresh yields another token
                // with the same `acr`, which is how one 401 becomes an unbounded rotation loop.
                let acrValues = (challenge["acr_values"] ?? "").split(separator: " ").map(String.init)
                // An unparseable `max_age` is dropped rather than failing the step-up: the ACR
                // is what the re-authorization cannot proceed without.
                await onStepUp?()
                throw OAuthError.stepUp(acrValues: acrValues, maxAge: challenge["max_age"].flatMap { Int($0) })

            default:
                // A bare 401, or a code this SDK does not know, read as an expiry: one refresh,
                // one replay; a second 401 is the session being refused, not the token being old.
                if refreshed { throw OAuthError.reauthenticate(.sessionRejected) }
                refreshed = true
                // A concurrent call may already have refreshed while this response was in
                // flight; rotating again would spend a second rotation on a usable token.
                let cached = try await tokens.accessToken()
                token = cached.value != token.value ? cached : try await tokens.renewAccessToken()
                // A streamed body cannot be sent twice. The renewed token is in the cache, so
                // the app's own retry (which rebuilds the body) succeeds; replaying a consumed
                // stream would fail for a reason that looks nothing like its cause.
                if request.httpBodyStream != nil { return (data, response) }
            }
        }
    }

    /// `Authorization`, and the proof that goes with it. The scheme follows the token, not the
    /// configuration: RFC 9449 section 5 makes `DPoP` the scheme a key-bound token must be
    /// presented under, and a resource server refuses it over `Bearer`.
    private func sign(_ request: URLRequest, url: URL, token: AccessToken, origin: String) async throws -> URLRequest {
        var signed = request
        if token.tokenType.caseInsensitiveCompare("DPoP") == .orderedSame {
            // A DPoP-bound token with no proof source would go out as a bare credential the
            // server cannot accept, and would look like a server fault. Fail closed instead.
            guard let dpop else {
                throw URLRules.invalid("a DPoP-bound access token needs a DPoP proof source")
            }
            signed.setValue("DPoP \(token.value)", forHTTPHeaderField: "Authorization")
            // `htu` is the URL without query and fragment (RFC 9449 section 4.2); `ath` is
            // derived from the token actually being sent; the nonce is the origin's own.
            let proof = try await dpop.proof(
                method: request.httpMethod ?? "GET", url: Self.htu(url), nonce: await dpop.nonce(for: origin),
                accessToken: token.value
            )
            signed.setValue(proof, forHTTPHeaderField: "DPoP")
        } else {
            signed.setValue("Bearer \(token.value)", forHTTPHeaderField: "Authorization")
            // A proof from the caller would be a second credential nobody asked for.
            signed.setValue(nil, forHTTPHeaderField: "DPoP")
        }
        return signed
    }

    /// The answer, and whether the URL cache rather than the network produced it. Redirects are
    /// refused as everywhere in the SDK; the fetch type comes from the task's metrics.
    private func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse, fromCache: Bool) {
        let delegate = CacheAwareNoRedirectDelegate()
        let (data, response) = try await session.data(for: request, delegate: delegate)
        guard let http = response as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        return (data, http, delegate.servedFromCache)
    }


    private static func htu(_ url: URL) -> URL {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return url }
        components.query = nil
        components.fragment = nil
        return components.url ?? url
    }
}

/// `NoRedirectDelegate`, plus whether the response came out of the URL cache
/// (`URLSessionTaskMetrics.resourceFetchType`), which `AuthenticatedSession` needs so that a
/// stored response's `Date` is not taken for the server's clock.
private final class CacheAwareNoRedirectDelegate: NSObject, URLSessionTaskDelegate, Sendable {
    private let cached = OSAllocatedUnfairLock(initialState: false)

    var servedFromCache: Bool { cached.withLock { $0 } }

    func urlSession(
        _ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest
    ) async -> URLRequest? {
        nil
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didFinishCollecting metrics: URLSessionTaskMetrics) {
        cached.withLock { $0 = metrics.transactionMetrics.last?.resourceFetchType == .localCache }
    }
}

/// The `WWW-Authenticate` challenges of a 401 (RFC 9110 section 11.6.1), read leniently: input
/// comes from the network, so nothing here may crash, hang or throw, and a malformed header
/// yields what could be read of it.
enum AuthenticateChallenge {
    struct Challenge: Equatable, Sendable {
        /// "" for parameters that appear with no scheme before them.
        var scheme: String
        /// Names lower-cased; the first occurrence of a name wins.
        var parameters: [String: String] = [:]
        var token68: String?
    }

    /// `1#challenge`: a scheme, then a token68 or a comma-separated list of `name=value`
    /// parameters, values bare or quoted (with `\` escapes).
    static func parse(_ header: String) -> [Challenge] {
        let chars = Array(header)
        var index = 0
        var challenges: [Challenge] = []

        func isSpace(_ c: Character) -> Bool { c == " " || c == "\t" || c == "\r" || c == "\n" }
        func isTokenChar(_ c: Character) -> Bool {
            c.isASCII && (c.isLetter || c.isNumber || "!#$%&'*+-.^_`|~".contains(c))
        }
        func skipSeparators() { while index < chars.count, isSpace(chars[index]) || chars[index] == "," { index += 1 } }
        func skipSpaces(_ at: inout Int) { while at < chars.count, isSpace(chars[at]) { at += 1 } }
        func addParameter(_ name: String, _ value: String) {
            if challenges.isEmpty { challenges.append(Challenge(scheme: "")) }
            let key = name.lowercased()
            if challenges[challenges.count - 1].parameters[key] == nil {
                challenges[challenges.count - 1].parameters[key] = value
            }
        }

        while true {
            skipSeparators()
            guard index < chars.count else { break }
            let start = index
            while index < chars.count, isTokenChar(chars[index]) { index += 1 }
            if index == start {
                // Not a token (a stray quote, equals sign, control character): skip it, which
                // also guarantees the loop advances.
                index += 1
                continue
            }
            let name = String(chars[start..<index])
            var lookahead = index
            skipSpaces(&lookahead)

            guard lookahead < chars.count, chars[lookahead] == "=" else {
                // A token not followed by "=" opens a new challenge.
                challenges.append(Challenge(scheme: name))
                continue
            }
            var valueStart = lookahead + 1
            skipSpaces(&valueStart)
            // "name=" at the end, or "name==": a token68 (base64 padding), not a parameter.
            if valueStart >= chars.count || chars[valueStart] == "," || chars[valueStart] == "=" {
                var end = lookahead
                while end < chars.count, chars[end] == "=" { end += 1 }
                if !challenges.isEmpty, challenges[challenges.count - 1].token68 == nil,
                   challenges[challenges.count - 1].parameters.isEmpty {
                    challenges[challenges.count - 1].token68 = name + String(repeating: "=", count: end - lookahead)
                }
                index = end
                continue
            }
            if chars[valueStart] == "\"" {
                var value = ""
                var cursor = valueStart + 1
                while cursor < chars.count, chars[cursor] != "\"" {
                    if chars[cursor] == "\\" {
                        // A quoted-pair; a lone backslash at the very end has nothing to escape.
                        cursor += 1
                        if cursor >= chars.count { break }
                    }
                    value.append(chars[cursor])
                    cursor += 1
                }
                addParameter(name, value)
                index = min(cursor + 1, chars.count)  // past the closing quote; unterminated runs to the end
            } else {
                var cursor = valueStart
                while cursor < chars.count, !isSpace(chars[cursor]), chars[cursor] != "," { cursor += 1 }
                addParameter(name, String(chars[valueStart..<cursor]))
                index = cursor
            }
        }
        return challenges
    }

    /// Every parameter of every challenge as one set, the first occurrence of a name winning:
    /// the read-by-name-never-by-scheme view the 401 handling uses.
    static func merged(_ challenges: [Challenge]) -> [String: String] {
        var result: [String: String] = [:]
        for challenge in challenges {
            for (name, value) in challenge.parameters where result[name] == nil { result[name] = value }
        }
        return result
    }
}
