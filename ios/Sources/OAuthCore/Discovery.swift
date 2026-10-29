import Foundation

/// Fetches the provider's metadata document.
public protocol DiscoveryClient: Sendable {
    func fetch(issuer: String) async throws -> ProviderMetadata
}

/// OpenID Connect Discovery section 4.1: the well-known path is appended to the issuer, keeping
/// any path component the issuer already has.
func wellKnownURL(issuer: String) -> String {
    (issuer.hasSuffix("/") ? String(issuer.dropLast()) : issuer) + "/.well-known/openid-configuration"
}

/// Discovery over HTTP: one GET of `<issuer>/.well-known/openid-configuration`.
public struct HTTPDiscoveryClient: DiscoveryClient {
    private let httpClient: HTTPClient

    public init(httpClient: HTTPClient) {
        self.httpClient = httpClient
    }

    public func fetch(issuer: String) async throws -> ProviderMetadata {
        let location = wellKnownURL(issuer: issuer)
        guard let url = URL(string: location), url.scheme != nil else {
            throw OAuthError.configuration(.invalidConfiguration(detail: "issuer is not a URL: \(issuer)"))
        }
        let response: HTTPResponse
        do {
            response = try await httpClient.send(
                HTTPRequest(method: .get, url: url, headers: ["Accept": "application/json"])
            )
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as OAuthError {
            throw error
        } catch {
            throw OAuthError.recoverable(.network(
                detail: "discovery request failed: \(type(of: error))", attempts: 1, elapsedMillis: 0
            ))
        }
        switch response.statusCode {
        case 200..<300:
            break
        // A 4xx means this issuer serves no discovery document at all, which no retry fixes:
        // an integrator typo or the wrong environment.
        case 400..<500:
            throw OAuthError.configuration(.invalidConfiguration(
                detail: "no discovery document at \(location) (HTTP \(response.statusCode))"
            ))
        // Anything else is the provider having a bad moment: transport-shaped, retried under
        // the caller's budget rather than surfaced as a deployment fault.
        default:
            throw OAuthError.recoverable(.network(
                detail: "discovery returned HTTP \(response.statusCode)", attempts: 1, elapsedMillis: 0
            ))
        }
        do {
            return try JSONDecoder().decode(ProviderMetadata.self, from: response.body)
        } catch {
            throw OAuthError.configuration(.discoveryMalformed(detail: "the document is not valid metadata JSON"))
        }
    }
}

/// Serves a document handed in at construction: for a provider whose discovery endpoint is
/// missing or wrong, and for tests.
public struct StaticDiscoveryClient: DiscoveryClient {
    private let metadata: ProviderMetadata

    public init(metadata: ProviderMetadata) {
        self.metadata = metadata
    }

    public func fetch(issuer: String) async throws -> ProviderMetadata { metadata }
}

/// A cache that lives as long as the process; the facade supplies a file-backed one.
public actor MemoryMetadataCache: ProviderMetadataCache {
    private var stored: ProviderMetadata?

    public init(_ initial: ProviderMetadata? = nil) {
        stored = initial
    }

    public func load() async throws -> ProviderMetadata? { stored }

    public func save(_ metadata: ProviderMetadata) async throws { stored = metadata }
}

/// Discovery with its cache in front: at most one fetch per process, however many callers ask at
/// once, and none at all when the cache already holds a document for this issuer.
public actor DiscoveryService {
    private let issuer: String
    private let client: DiscoveryClient
    private let cache: ProviderMetadataCache
    private var inMemory: ProviderMetadata?
    /// The fetch in flight, so concurrent callers share it rather than each hitting the network.
    /// A caller that is cancelled stops waiting; it does not cancel the fetch the others need.
    private var inFlight: Task<ProviderMetadata, Error>?

    public init(issuer: String, client: DiscoveryClient, cache: ProviderMetadataCache) {
        self.issuer = issuer
        self.client = client
        self.cache = cache
    }

    public func metadata() async throws -> ProviderMetadata {
        if let inMemory { return inMemory }
        if let inFlight { return try await inFlight.value }
        // Created and stored in the same actor turn: the body cannot start before `inFlight` is
        // set, and it clears it itself, so a late waiter cannot clear a newer task.
        let task = Task { try await self.resolve() }
        inFlight = task
        return try await task.value
    }

    private func resolve() async throws -> ProviderMetadata {
        defer { inFlight = nil }
        // A cache that cannot be read or written is a cache miss, never a failure: the document
        // is one round trip away, and the alternative is bricking login on a corrupt file.
        if let cached = try? await cache.load() {
            // A document cached for another issuer belongs to a previous configuration of this
            // app; it is treated as absent rather than trusted.
            if (try? cached.validate(configuredIssuer: issuer)) != nil {
                inMemory = cached
                return cached
            }
        }
        let fetched = try await client.fetch(issuer: issuer)
        try fetched.validate(configuredIssuer: issuer)
        try? await cache.save(fetched)
        inMemory = fetched
        return fetched
    }
}
