import Foundation

/// Refuses every redirect, so the 3xx is the response the caller sees. A per-request delegate,
/// not a session setting, because the session is the app's (`OAuthConfiguration.urlSession`)
/// and the SDK's own requests must not follow a `Location` whatever it is configured to do:
/// a token endpoint redirecting a form body (or an `Authorization` header) to another origin
/// is a leak, not a convenience. No state, so `Sendable` without ceremony.
final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(
        _ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest
    ) async -> URLRequest? {
        nil
    }
}

/// The SDK's own HTTP: discovery, JWKS, token, revocation, PAR, UserInfo. Wraps a `URLSession`
/// (the app's, from the configuration) and never follows a redirect.
package struct URLSessionHTTPClient: HTTPClient {
    private let session: URLSession

    /// - Parameter session: the session the requests go through; its timeouts, proxies and
    ///   protocol classes are honoured, its redirect handling is not.
    package init(session: URLSession = .shared) {
        self.session = session
    }

    package func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        var urlRequest = URLRequest(url: request.url)
        urlRequest.httpMethod = request.method.rawValue
        for (name, value) in request.headers { urlRequest.setValue(value, forHTTPHeaderField: name) }
        urlRequest.httpBody = request.body
        // Cookies are the browser's business: a Set-Cookie from the token endpoint must not
        // land in the app's shared jar, nor a jar cookie ride along on a token request.
        urlRequest.httpShouldHandleCookies = false

        let clock = ContinuousClock()
        let start = clock.now
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: urlRequest, delegate: NoRedirectDelegate())
        } catch {
            // A cancelled caller is a cancellation, not a network failure to retry.
            if Task.isCancelled || (error as? URLError)?.code == .cancelled { throw CancellationError() }
            throw Self.networkError(error, elapsed: clock.now - start)
        }
        guard let http = response as? HTTPURLResponse else {
            throw Self.networkError(nil, detail: "the response was not an HTTP response", elapsed: clock.now - start)
        }
        var headers: [String: String] = [:]
        for (key, value) in http.allHeaderFields {
            if let key = key as? String, let value = value as? String { headers[key.lowercased()] = value }
        }
        return HTTPResponse(statusCode: http.statusCode, headers: headers, body: data)
    }

    /// The detail never carries a URL: they can hold a code or a state in the query, and a
    /// transport error's text sometimes quotes one.
    static func networkError(_ error: (any Error)?, detail: String? = nil, elapsed: Duration) -> OAuthError {
        let text: String
        if let detail {
            text = detail
        } else if let error {
            let code = (error as? URLError).map { NetworkFailure.suffix(forURLErrorCode: $0.code.rawValue) } ?? ""
            text = Self.stripURLs(error.localizedDescription) + code
        } else {
            text = "transport failure"
        }
        let parts = elapsed.components
        let millis = parts.seconds * 1000 + parts.attoseconds / 1_000_000_000_000_000
        return .recoverable(.network(detail: text, attempts: 1, elapsedMillis: millis))
    }

    static func stripURLs(_ text: String) -> String {
        guard let expression = try? NSRegularExpression(pattern: "[A-Za-z][A-Za-z0-9+.\\-]*://\\S+") else { return text }
        return expression.stringByReplacingMatches(
            in: text, range: NSRange(text.startIndex..., in: text), withTemplate: "<url>"
        )
    }
}
