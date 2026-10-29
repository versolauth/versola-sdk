import Foundation

/// Process-local key cache, for tests and for an integrator who wants nothing on disk.
package actor MemoryJwksCache: JwksCache {
    private var stored: JsonWebKeySet?

    package init() {}

    package func load() async throws -> JsonWebKeySet? { stored }
    package func save(_ set: JsonWebKeySet) async throws { stored = set }
}

/// Fetches and caches the provider's JWK Set (`jwks_uri`).
///
/// The HTTP client is the facade's and never follows redirects for the SDK's own requests: the
/// URL came from discovery and is the only place keys may be read from. A key set fetched from
/// wherever a `Location` header pointed would let anything able to answer there choose which
/// keys verify.
///
/// What it does not do is decide when a refetch is warranted. That is the verifier's call, one
/// per validation, so that a flood of tokens naming unknown `kid`s costs the provider at most
/// one request each and never a loop.
package actor JwksClient {
    /// A key set and whether this very call fetched it, which tells the caller that a refetch
    /// would be a repeat.
    package struct Loaded: Sendable {
        package let keys: JsonWebKeySet
        package let fetched: Bool
        package init(keys: JsonWebKeySet, fetched: Bool) {
            self.keys = keys
            self.fetched = fetched
        }
    }

    private let httpClient: HTTPClient
    private let cache: JwksCache
    private var inMemory: JsonWebKeySet?
    /// The fetch in progress, if any. An actor is reentrant at every `await`, so without this
    /// a burst of validations would each fetch; with it they share one request.
    private var inFlight: Task<JsonWebKeySet, Error>?

    package init(httpClient: HTTPClient, cache: JwksCache = MemoryJwksCache()) {
        self.httpClient = httpClient
        self.cache = cache
    }

    /// - Parameter forceRefresh: skip memory and the cache and fetch. Without it the key set
    ///   comes from memory, then the cache, then the network.
    /// - Throws: `OAuthError.recoverable(.network)` when the provider cannot be reached or
    ///   answers an error; `OAuthError.configuration(.discoveryMalformed)` when the answer is
    ///   not a JWK Set.
    package func keys(uri: String, forceRefresh: Bool) async throws -> Loaded {
        if !forceRefresh {
            if let inMemory { return Loaded(keys: inMemory, fetched: false) }
            // A cache that cannot be read is a miss, never a failure: the document is one
            // request away.
            if inFlight == nil, let stored = try? await cache.load() {
                // The await above let another caller in; keep what it may have stored.
                if inMemory == nil { inMemory = stored }
                if let inMemory { return Loaded(keys: inMemory, fetched: false) }
            }
        }
        let task: Task<JsonWebKeySet, Error>
        if let existing = inFlight {
            task = existing
        } else {
            task = Task { try await self.fetchAndStore(uri) }
            inFlight = task
        }
        return Loaded(keys: try await task.value, fetched: true)
    }

    private func fetchAndStore(_ uri: String) async throws -> JsonWebKeySet {
        defer { inFlight = nil }
        let set = try await fetch(uri)
        inMemory = set
        // Saved only once it parsed: a bad answer must not replace keys that worked. A failed
        // save costs a request next start, not this validation.
        try? await cache.save(set)
        return set
    }

    private func fetch(_ uri: String) async throws -> JsonWebKeySet {
        guard let url = URL(string: uri), url.scheme != nil else {
            throw OAuthError.configuration(.discoveryMalformed(detail: "jwks_uri is not a URL"))
        }
        let response: HTTPResponse
        do {
            response = try await httpClient.send(HTTPRequest(method: .get, url: url, headers: ["Accept": "application/json"]))
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw OAuthError.recoverable(.network(detail: "jwks request failed", attempts: 1, elapsedMillis: 0))
        }
        switch response.statusCode {
        case 200:
            guard let set = JwksClient.parse(response.body) else {
                throw OAuthError.configuration(.discoveryMalformed(detail: "jwks_uri did not serve a JWK Set"))
            }
            return set
        // A redirect that was not followed is a deployment fault no retry fixes.
        case 300...399:
            throw OAuthError.configuration(.discoveryMalformed(detail: "jwks_uri answered HTTP \(response.statusCode); redirects are not followed"))
        default:
            throw OAuthError.recoverable(.network(detail: "jwks_uri returned HTTP \(response.statusCode)", attempts: 1, elapsedMillis: 0))
        }
    }

    /// Strict about the document and forgiving about its members: RFC 7517 5 says a key the
    /// application cannot use (an unknown `kty`, a key that does not decode) is ignored rather
    /// than failing the set, because a provider rotating in an algorithm this SDK lacks must not
    /// break verification with the keys it does have. A document that is not JSON or has no
    /// `keys` array is not a JWK Set at all (nil).
    static func parse(_ document: Data) -> JsonWebKeySet? {
        struct Document: Decodable {
            let keys: [Lenient]
        }
        struct Lenient: Decodable {
            let key: JsonWebKey?
            init(from decoder: Decoder) throws { key = try? JsonWebKey(from: decoder) }
        }
        guard let parsed = try? JSONDecoder().decode(Document.self, from: document) else { return nil }
        let usable = parsed.keys.compactMap(\.key).filter { key in
            switch key.kty {
            case "RSA": return key.n != nil && key.e != nil
            case "EC": return key.crv != nil && key.x != nil && key.y != nil
            default: return false
            }
        }
        return JsonWebKeySet(keys: usable)
    }
}
