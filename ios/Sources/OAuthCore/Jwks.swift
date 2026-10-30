import Foundation

/// Process-local key cache, for tests and for an integrator who wants nothing on disk.
package actor MemoryJwksCache: JwksCache {
    private var stored: JsonWebKeySet?
    private var storedAt: Date?
    private var storedLifetime: TimeInterval?

    package init() {}

    package func load() async throws -> JsonWebKeySet? { stored }
    package func save(_ set: JsonWebKeySet) async throws {
        try await save(set, lifetime: nil)
    }
    package func save(_ set: JsonWebKeySet, lifetime: TimeInterval?) async throws {
        stored = set
        storedAt = Date()
        storedLifetime = lifetime
    }
    package func savedAt() async throws -> Date? { storedAt }
    package func lifetime() async throws -> TimeInterval? { storedLifetime }
}

/// Whether a key set past its lifetime may be used when the provider cannot be reached for a
/// fresh one. Off everywhere except the check of the ID token on a **refresh**, where the
/// provider has already rotated the refresh token and a key-set outage would otherwise cost the
/// session its access token on every attempt for as long as the outage lasts. A task-local, so
/// the rule is the caller's and the key client has no flag to forget to clear.
package enum JwksStaleness {
    @TaskLocal package static var allowed = false
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
        /// Past its lifetime, served because the provider could not be reached
        /// (`JwksStaleness`). `fetched` is true then: a refetch has just failed, and another for an
        /// unknown `kid` would only fail again.
        package let stale: Bool
        package init(keys: JsonWebKeySet, fetched: Bool, stale: Bool = false) {
            self.keys = keys
            self.fetched = fetched
            self.stale = stale
        }
    }

    private let httpClient: HTTPClient
    private let cache: JwksCache
    private let clock: Clock
    private var inMemory: JsonWebKeySet?
    /// When `inMemory` stops being fresh, in `Clock.uptime` seconds (`CacheLifetime`).
    private var inMemoryExpiresAt: TimeInterval = 0
    /// The fetch in progress, if any. An actor is reentrant at every `await`, so without this
    /// a burst of validations would each fetch; with it they share one request.
    private var inFlight: Task<JsonWebKeySet, Error>?

    package init(httpClient: HTTPClient, cache: JwksCache = MemoryJwksCache(), clock: Clock = .system) {
        self.httpClient = httpClient
        self.cache = cache
        self.clock = clock
    }

    /// - Parameter forceRefresh: skip memory and the cache and fetch. Without it the key set
    ///   comes from memory, then the cache, then the network.
    /// - Throws: `OAuthError.recoverable(.network)` when the provider cannot be reached and
    ///   `.recoverable(.server)` when it answers a status that is not the key set (repeated under
    ///   the operation's budget when transient, never otherwise); `OAuthError.configuration(.discoveryMalformed)` when the answer is
    ///   not a JWK Set.
    package func keys(uri: String, forceRefresh: Bool) async throws -> Loaded {
        if !forceRefresh {
            if let held = fresh() { return Loaded(keys: held, fetched: false) }
            // A cache that cannot be read is a miss, never a failure: the document is one
            // request away. One older than its lifetime is a miss too: a key the provider has
            // withdrawn is not trusted for as long as a file on disk survives.
            if inFlight == nil, let stored = try? await cache.load(), let remaining = await cachedFreshness() {
                // The await above let another caller in; keep what it may have stored.
                if let held = fresh() { return Loaded(keys: held, fetched: false) }
                inMemory = stored
                inMemoryExpiresAt = clock.uptime() + remaining
                return Loaded(keys: stored, fetched: false)
            }
        }
        let task: Task<JsonWebKeySet, Error>
        if let existing = inFlight {
            task = existing
        } else {
            task = Task { try await self.fetchAndStore(uri) }
            inFlight = task
        }
        do {
            return Loaded(keys: try await task.value, fetched: true)
        } catch let error as OAuthError {
            // Only for a provider that could not be reached or answered badly for now, and only
            // where the caller said an outage must not cost it more than the check: a document
            // that is not a key set is a deployment fault and is never papered over.
            if !forceRefresh, JwksStaleness.allowed, case .recoverable = error, let stale = await staleKeys() {
                return Loaded(keys: stale, fetched: true, stale: true)
            }
            throw error
        }
    }

    /// The expired set, while it is within `CacheLifetime.maximumStale` of its expiry.
    private func staleKeys() async -> JsonWebKeySet? {
        if let inMemory, clock.uptime() < inMemoryExpiresAt + CacheLifetime.maximumStale { return inMemory }
        guard let stored = try? await cache.load(), let savedAt = (try? await cache.savedAt()).flatMap({ $0 }) else { return nil }
        let lifetime = (try? await cache.lifetime()).flatMap { $0 } ?? CacheLifetime.defaultLifetime
        let age = clock.now().timeIntervalSince(savedAt)
        return age >= 0 && age < lifetime + CacheLifetime.maximumStale ? stored : nil
    }

    /// The key set held in memory, while it is within its lifetime.
    private func fresh() -> JsonWebKeySet? {
        guard let inMemory, clock.uptime() < inMemoryExpiresAt else { return nil }
        return inMemory
    }

    /// How much of its lifetime the cached set has left (wall clock: it has to survive a restart),
    /// nil when it is expired, of unknown age, or from the future.
    private func cachedFreshness() async -> TimeInterval? {
        guard let savedAt = (try? await cache.savedAt()).flatMap({ $0 }) else { return nil }
        let lifetime = (try? await cache.lifetime()).flatMap { $0 } ?? CacheLifetime.defaultLifetime
        let age = clock.now().timeIntervalSince(savedAt)
        return age >= 0 && age < lifetime ? lifetime - age : nil
    }

    private func fetchAndStore(_ uri: String) async throws -> JsonWebKeySet {
        defer { inFlight = nil }
        let (set, lifetime) = try await fetch(uri)
        inMemory = set
        inMemoryExpiresAt = clock.uptime() + lifetime
        // Saved only once it parsed: a bad answer must not replace keys that worked. A failed
        // save costs a request next start, not this validation.
        try? await cache.save(set, lifetime: lifetime)
        return set
    }

    private func fetch(_ uri: String) async throws -> (JsonWebKeySet, TimeInterval) {
        guard let url = URL(string: uri), url.scheme != nil else {
            throw OAuthError.configuration(.discoveryMalformed(detail: "jwks_uri is not a URL"))
        }
        let httpClient = self.httpClient
        // A read-only request, repeated under the operation's budget (`spec/retry-policy.md`).
        let response: HTTPResponse = try await OperationBudget.run(origin: DpopOrigin.of(url)) {
            let response: HTTPResponse
            do {
                response = try await httpClient.send(HTTPRequest(method: .get, url: url, headers: ["Accept": "application/json"]))
            } catch is CancellationError {
                throw CancellationError()
            } catch let error as OAuthError {
                // Typed by the client (a transport failure, a body over the size limit): kept.
                throw error
            } catch {
                throw OAuthError.recoverable(.network(detail: "jwks request failed", attempts: 1, elapsedMillis: 0))
            }
            if let failure = ServerFailure.error(for: response) { throw failure }
            return response
        }
        switch response.statusCode {
        case 200:
            guard let set = JwksClient.parse(response.body) else {
                throw OAuthError.configuration(.discoveryMalformed(detail: "jwks_uri did not serve a JWK Set"))
            }
            return (set, CacheLifetime.of(response.header("Cache-Control")))
        // A redirect that was not followed is a deployment fault no retry fixes.
        case 300...399:
            throw OAuthError.configuration(.discoveryMalformed(detail: "jwks_uri answered HTTP \(response.statusCode); redirects are not followed"))
        default:
            // A 408, 429 or 5xx never gets here (it is `server`, above). What does is a status the
            // key set has no use for (a 404, a 204): reported with its status, never repeated.
            throw ServerFailure.unexpected(response.statusCode)
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
