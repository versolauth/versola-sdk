import Foundation

// The seams the core is assembled through (ADR 0001). A facade supplies a browser, stores,
// an HTTP client, a proof source and a logger; the core supplies the protocol. Every seam
// takes and returns values, never views, so an embedded web view stays unrepresentable.

/// Where the SDK's warnings go. An app routes them into whatever it already uses; the default
/// facade logger emits warnings only (`spec/oauth-sdk-api.md` section 15).
public protocol OAuthLogger: Sendable {
    func info(_ message: String)
    func warn(_ message: String)
}

/// One HTTP exchange, as the core sees it: the facade hands in a `URLSession`-backed
/// implementation, tests a stub. Redirects are never followed for the SDK's own requests.
public struct HTTPRequest: Sendable, Equatable {
    public enum Method: String, Sendable { case get = "GET", post = "POST" }
    public var method: Method
    public var url: URL
    public var headers: [String: String]
    /// `application/x-www-form-urlencoded` when set together with the matching header.
    public var body: Data?

    public init(method: Method, url: URL, headers: [String: String] = [:], body: Data? = nil) {
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
    }
}

public struct HTTPResponse: Sendable {
    public var statusCode: Int
    /// Header names lower-cased, so lookups are case-insensitive as HTTP is.
    public var headers: [String: String]
    public var body: Data

    public init(statusCode: Int, headers: [String: String] = [:], body: Data = Data()) {
        self.statusCode = statusCode
        self.headers = Dictionary(uniqueKeysWithValues: headers.map { ($0.key.lowercased(), $0.value) })
        self.body = body
    }

    public func header(_ name: String) -> String? { headers[name.lowercased()] }
}

public protocol HTTPClient: Sendable {
    /// Throws only on a transport failure (no connection, timeout, TLS); a non-2xx answer is
    /// a returned response, which the caller interprets.
    func send(_ request: HTTPRequest) async throws -> HTTPResponse
}

/// How the browser leg ended.
public enum BrowserOutcome: Sendable, Equatable {
    /// The redirect URI was delivered back to the app. Not yet validated.
    case redirect(URL)
    /// The user dismissed the browser while the app was in the foreground: the pending request
    /// is wiped and the login is `recoverable(.userCancelled)`.
    case userCancelled
    /// The system tore the session down while the app was not in the foreground: the pending
    /// request is kept so the flow can resume (`spec/state-machine.md`, the cancel table).
    case systemCancelled
}

/// What one browser leg may ask beyond the URI (`spec/oauth-sdk-api.md` section 6).
public struct BrowserSessionOptions: Sendable, Equatable {
    /// `prefersEphemeralWebBrowserSession`. Off by default: it breaks passkeys and SSO.
    public var ephemeral: Bool
    /// The URI the provider will redirect to; what `ASWebAuthenticationSession` matches on.
    public var redirectURI: URL?

    public init(ephemeral: Bool = false, redirectURI: URL? = nil) {
        self.ephemeral = ephemeral
        self.redirectURI = redirectURI
    }
}

/// The system browser leg. Takes and returns URIs and nothing else: no implementation can
/// accept a web view, which is what keeps one unrepresentable (RFC 8252, #1 §4).
public protocol BrowserAuthorizationSession: Sendable {
    func authorize(_ uri: URL, options: BrowserSessionOptions) async throws -> BrowserOutcome
    /// A redirect for an authorization this process did not start (the app was killed with the
    /// browser open). Opens nothing; the facade's `handleRedirect` feeds it.
    func awaitPendingRedirect() async throws -> BrowserOutcome
}

/// The durable half of a session (`spec/state-machine.md`, persistence summary): the refresh
/// token, the raw ID token and the rotation slot, wrapped by the platform's secure store.
public protocol CredentialStore: Sendable {
    /// Whether a refresh grant is stored, answered without unlocking anything.
    func hasGrant() async throws -> Bool
    func refreshToken() async throws -> String?
    func rawIdToken() async throws -> String?
    /// Writes the new grant over the old one atomically: a crash between the two cannot lose it.
    func save(refreshToken: String, rawIdToken: String?) async throws
    func clear() async throws
}

/// The pending authorization request, persisted before the browser opens so a process death
/// mid-browser can resume (scenario 12).
public protocol PendingAuthorizationStore: Sendable {
    func save(_ request: PendingAuthorizationRequest) async throws
    func load() async throws -> PendingAuthorizationRequest?
    func clear() async throws
}

/// The discovered metadata, cached across restarts and logout.
public protocol ProviderMetadataCache: Sendable {
    func load() async throws -> ProviderMetadata?
    func save(_ metadata: ProviderMetadata) async throws
}

/// The provider's key set, cached unencrypted (public keys).
public protocol JwksCache: Sendable {
    func load() async throws -> JsonWebKeySet?
    func save(_ set: JsonWebKeySet) async throws
}

/// Mints DPoP proofs (RFC 9449) for a key the facade owns; the core never sees the key.
public protocol DpopProofSource: Sendable {
    /// The key's JWK thumbprint, for `dpop_jkt`.
    func thumbprint() async throws -> String
    /// A proof for `method` on `url`, carrying `nonce` and the hash of `accessToken` when given.
    func proof(method: String, url: URL, nonce: String?, accessToken: String?) async throws -> String
    /// A nonce the origin demanded (`use_dpop_nonce`), remembered per origin.
    func observe(nonce: String, origin: String) async
    func nonce(for origin: String) async -> String?
    func clearNonces() async
}

/// Validates an ID token before anything is persisted (`spec/oauth-sdk-api.md` section 11).
public protocol IdTokenValidator: Sendable {
    /// - Parameters:
    ///   - expectedNonce: the nonce the request carried; nil on a refresh.
    ///   - previous: the claims of the session being refreshed, whose `sub` must not change.
    ///   - serverTime: the token response's `Date`, the server's clock, when present.
    func validate(
        idToken: String,
        expectedNonce: String?,
        accessToken: String?,
        maxAge: Int?,
        previous: IdTokenClaims?,
        serverTime: Date?
    ) async throws -> IdTokenClaims
}

/// Time and randomness are injected so tests need no sleeps and no luck (`testing.md`).
public struct Clock: Sendable {
    public var now: @Sendable () -> Date
    public init(now: @escaping @Sendable () -> Date) { self.now = now }
    public static let system = Clock(now: { Date() })
}

public protocol RandomSource: Sendable {
    /// `count` cryptographically random bytes.
    func bytes(_ count: Int) -> [UInt8]
}

/// The platform CSPRNG (`SystemRandomNumberGenerator`): `state`, `nonce`, verifiers and `jti`.
public struct SystemRandomSource: RandomSource {
    public init() {}
    public func bytes(_ count: Int) -> [UInt8] {
        var generator = SystemRandomNumberGenerator()
        return (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
    }
}
