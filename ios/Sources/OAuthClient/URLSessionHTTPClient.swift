import Foundation
import OAuthCore

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
///
/// Three things the session's own settings do not give these requests, because they are
/// security-relevant fetches and not the app's traffic:
/// - **No cache.** A key set or discovery document fetched again on purpose (a `kid` the cached
///   set lacks, a rotated endpoint) must come from the provider; the app session's `URLCache`
///   would answer a forced refetch with the very document being doubted.
/// - **A size limit** (`HTTPRequest.maxResponseBytes`), enforced while the body streams in.
/// - **A deadline bounded by the operation's retry budget** (`spec/retry-policy.md`): the session's
///   default request timeout is 60 s, which a 20 s `totalBudget` cannot honour.
package struct URLSessionHTTPClient: HTTPClient {
    private let session: URLSession
    private let minimumAttemptTimeout: TimeInterval

    /// - Parameters:
    ///   - session: the session the requests go through; its timeouts, proxies and protocol
    ///     classes are honoured, its redirect handling and cache are not.
    ///   - minimumAttemptTimeout: the least a request is given when its operation's budget is
    ///     nearly spent. A request that has not been tried yet (the code exchange, which cannot
    ///     be repeated, after the user's time in the browser) must not be set up to fail at once.
    package init(session: URLSession = .shared, minimumAttemptTimeout: TimeInterval = 5) {
        self.session = session
        self.minimumAttemptTimeout = minimumAttemptTimeout
    }

    package func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        var urlRequest = URLRequest(url: request.url)
        urlRequest.httpMethod = request.method.rawValue
        for (name, value) in request.headers { urlRequest.setValue(value, forHTTPHeaderField: name) }
        urlRequest.httpBody = request.body
        // Cookies are the browser's business: a Set-Cookie from the token endpoint must not
        // land in the app's shared jar, nor a jar cookie ride along on a token request.
        urlRequest.httpShouldHandleCookies = false
        urlRequest.cachePolicy = .reloadIgnoringLocalCacheData
        let deadline = await attemptTimeout()
        urlRequest.timeoutInterval = deadline

        let clock = ContinuousClock()
        let start = clock.now
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await Self.fetch(session, urlRequest, deadline: deadline, limit: request.maxResponseBytes)
        } catch let error as OAuthError {
            throw error
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

    /// The session's own request timeout, cut to what is left of the operation's budget (but not
    /// below the floor): the same number is the idle timeout handed to `URLSession` and the
    /// deadline for the whole exchange, since an idle timeout alone is restarted by every byte a
    /// slow provider drips.
    private func attemptTimeout() async -> TimeInterval {
        let own = session.configuration.timeoutIntervalForRequest
        guard let budget = OperationBudget.current else { return own }
        return min(own, max(await budget.remaining(), minimumAttemptTimeout))
    }

    private static func fetch(_ session: URLSession, _ request: URLRequest, deadline: TimeInterval, limit: Int) async throws -> (Data, URLResponse) {
        try await withThrowingTaskGroup(of: (Data, URLResponse)?.self) { group in
            group.addTask {
                let (bytes, response) = try await session.bytes(for: request, delegate: NoRedirectDelegate())
                // Refused on the declared length before a byte of the body is read, and again on
                // what arrives: a server may lie about, or omit, the length.
                if response.expectedContentLength > Int64(limit) { throw Self.tooLarge(limit) }
                // `AsyncBytes` has no chunked read, so the cost per byte is kept to an append to a
                // pre-sized array and a comparison; one `Data` is made at the end. A document
                // is a few KiB in practice; the limit bounds the worst case, not the usual one.
                var buffer = [UInt8]()
                let declared = response.expectedContentLength
                buffer.reserveCapacity(declared > 0 ? min(Int(declared), limit) : 4096)
                for try await byte in bytes {
                    buffer.append(byte)
                    if buffer.count > limit { throw Self.tooLarge(limit) }
                }
                return (Data(buffer), response)
            }
            group.addTask {
                try await Task.sleep(for: .seconds(deadline))
                throw URLError(.timedOut)
            }
            defer { group.cancelAll() }
            guard let first = try await group.next(), let answer = first else { throw URLError(.timedOut) }
            return answer
        }
    }

    /// The origin only: a URL can hold a code or a state in its query.
    private static func tooLarge(_ limit: Int) -> OAuthError {
        .configuration(.invalidConfiguration(detail: "a response from the provider is larger than \(limit) bytes and was refused"))
    }

    /// The detail never carries a URL: they can hold a code or a state in the query, and a
    /// transport error's text sometimes quotes one.
    static func networkError(_ error: (any Error)?, detail: String? = nil, elapsed: Duration) -> OAuthError {
        let text: String
        if let detail {
            text = detail
        } else if let error {
            let code = (error as? URLError).map { NetworkFailure.suffix(forURLErrorCode: $0.code.rawValue) } ?? ""
            // The one place the platform's error is in hand: say, as a typed fact, whether the
            // request ever connected (`RefreshReplay`). The text above is for people.
            text = Self.stripURLs(error.localizedDescription) + code
        } else {
            text = "transport failure"
        }
        if let urlError = error as? URLError, NetworkFailure.isNeverConnected(urlErrorCode: urlError.code.rawValue) {
            ConnectionFlag.current?.markNeverConnected()
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
