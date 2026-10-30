import AuthenticationServices
import Foundation
import OAuthCore

/// The generic facade of `spec/oauth-sdk-api.md`: a public client for any conforming OpenID
/// Provider, owning sign-in, ID-token validation, storage, refresh, authenticated HTTP and
/// sign-out. The integrator sees a session, observable through `sessionStates()`, not tokens.
///
/// The protocol is the same core the Versola facade uses; what differs are the defaults
/// (bearer tokens, no `offline_access` added, PAR when advertised, nothing sent that a
/// standard does not define) and the surface. Provider differences are capabilities read from
/// discovery, never a branch on an issuer (`spec/providers.md`).
public final class OAuthClient: Sendable {
    public let configuration: OAuthConfiguration
    private let flow: AuthorizationFlow
    private let coordinator: SessionCoordinator
    private let userInfoClient: UserInfoClient
    private let proofs: DpopProofSource?
    private let dpopKey: SecureEnclaveDpopKey?
    private let browser: WebAuthenticationBrowser?
    private let httpSession: URLSession

    /// One client per configuration per process: a second `create` with the same issuer and
    /// client id returns the first instance (two coordinators over one Keychain item would race
    /// each other's refresh), and a *different* configuration for the same pair is refused.
    private static let registry = Registry()

    private actor Registry {
        var clients: [String: OAuthClient] = [:]
        func resolve(_ configuration: OAuthConfiguration, build: () throws -> OAuthClient) throws -> OAuthClient {
            if let existing = clients[configuration.storageKey] {
                if existing.configuration.fingerprint != configuration.fingerprint {
                    throw OAuthError.configuration(.invalidConfiguration(detail: "a client for \(configuration.issuerIdentifier) / \(configuration.clientId) already exists in this process with a different configuration"))
                }
                return existing
            }
            let client = try build()
            clients[configuration.storageKey] = client
            return client
        }
        func forgetAll() { clients.removeAll() }
    }

    /// Validates nothing further (the configuration did) and wires the default implementations.
    /// No network I/O and no key generation happen here: discovery runs on the first operation
    /// that needs it, the DPoP key is generated on first use.
    ///
    /// - Parameter presentationAnchor: the window the browser sheet is presented from, supplied
    ///   by the app; the SDK never finds a window by itself.
    public static func create(
        configuration: OAuthConfiguration,
        presentationAnchor: @escaping @MainActor @Sendable () -> ASPresentationAnchor
    ) async throws -> OAuthClient {
        try await registry.resolve(configuration) {
            try build(configuration: configuration, presentationAnchor: presentationAnchor, browser: nil, credentialStore: nil, pendingStore: nil, metadataCache: nil, jwksCache: nil, makeDpopKey: nil)
        }
    }

    /// Wiring for a driver: the browser leg and the stores replaced (an HTTP login conversation
    /// and in-memory stores). Package access, not public: the contract stays URI-only.
    package static func create(
        configuration: OAuthConfiguration,
        browser: BrowserAuthorizationSession,
        credentialStore: CredentialStore,
        pendingStore: PendingAuthorizationStore,
        /// In-memory caches for a driver whose every test stages the provider anew; the file
        /// caches would otherwise serve one test's discovery and keys to the next.
        metadataCache: ProviderMetadataCache? = nil,
        jwksCache: JwksCache? = nil,
        /// The DPoP key, built from the configuration's hardware requirement and the logger. A driver
        /// on a host whose Keychain refuses an unsigned process (-34018) hands the key a store of its
        /// own; what the key does with `requireHardware` is still the SDK's, only where it persists
        /// and whether the Secure Enclave counts as present are the driver's.
        dpopKey makeDpopKey: (@Sendable (_ requireHardware: Bool, _ logger: any OAuthLogger) -> SecureEnclaveDpopKey)? = nil
    ) async throws -> OAuthClient {
        try await registry.resolve(configuration) {
            try build(configuration: configuration, presentationAnchor: nil, browser: browser, credentialStore: credentialStore, pendingStore: pendingStore, metadataCache: metadataCache, jwksCache: jwksCache, makeDpopKey: makeDpopKey)
        }
    }

    /// Forgets every client this process created, for a driver whose tests each stage a
    /// provider at the same address. The instances are not closed.
    package static func forgetAll() async {
        await registry.forgetAll()
    }

    private init(configuration: OAuthConfiguration, flow: AuthorizationFlow, coordinator: SessionCoordinator, userInfoClient: UserInfoClient, proofs: DpopProofSource?, dpopKey: SecureEnclaveDpopKey?, browser: WebAuthenticationBrowser?, httpSession: URLSession) {
        self.configuration = configuration
        self.flow = flow
        self.coordinator = coordinator
        self.userInfoClient = userInfoClient
        self.proofs = proofs
        self.dpopKey = dpopKey
        self.browser = browser
        self.httpSession = httpSession
    }

    // MARK: - Surface

    /// The state machine of `spec/state-machine.md`, one stream per observer. The first value
    /// is the restored state: an app killed mid-browser observes `authorizing` on cold start.
    public func sessionStates() async -> AsyncStream<SessionState> {
        try? await flow.ensureRestored()
        return await flow.states.stream()
    }

    /// The current state, restored first.
    public var sessionState: SessionState {
        get async {
            try? await flow.ensureRestored()
            return await flow.states.current
        }
    }

    /// The claims of the validated ID token of this session, or nil when there is no session.
    /// Memory only; the raw token and the `nonce` are not exposed.
    public var claims: IdTokenClaims? {
        get async { await coordinator.claims }
    }

    /// The provider's metadata, discovered once and cached on disk across restarts and logout.
    public func metadata() async throws -> ProviderMetadata {
        let flow = self.flow
        return try await coordinator.operation { try await flow.metadata() }
    }

    /// Opens the system browser, validates the redirect, exchanges the code, validates the ID
    /// token and persists the grant, in that order; `authenticated` is published only after the
    /// grant is durably stored. While `authorizing` it is refused: observe the state first.
    public func login(_ options: LoginOptions = .default) async throws {
        try await refuseWhileAuthorizing()
        let coordinator = self.coordinator
        let scopes = Array((options.scopes ?? configuration.scopes).union(["openid"])).sorted()
        try await coordinator.operation {
            try await coordinator.login(
                scopes: scopes,
                acrValues: options.acrValues,
                maxAge: options.maxAge,
                parameters: options.parameters,
                ephemeralBrowser: options.ephemeralBrowser
            )
        }
    }

    /// Answers `OAuthError.stepUp` by re-authorizing at the authentication context the resource
    /// server asked for; the app then re-issues the refused call.
    public func stepUp(acrValues: [String], maxAge: Int?, options: LoginOptions = .default) async throws {
        try await refuseWhileAuthorizing()
        let coordinator = self.coordinator
        let scopes = Array((options.scopes ?? configuration.scopes).union(["openid"])).sorted()
        try await coordinator.operation {
            try await coordinator.login(
                scopes: scopes,
                acrValues: acrValues,
                maxAge: maxAge,
                parameters: options.parameters,
                ephemeralBrowser: options.ephemeralBrowser
            )
        }
    }

    /// Finishes an authorization that outlived the process that started it (scenario 12): call
    /// it on launch when `sessionState` is `authorizing`, and feed the redirect the system
    /// delivers to `handleRedirect(_:)`. It waits for that redirect (for what is left of the
    /// request's ten minutes), validates it against the restored request, exchanges the code,
    /// validates the ID token and persists the grant, the same steps `login` ends with, and
    /// publishes `authenticated`. Returns without effect when nothing is pending; a failure
    /// settles the state as `login` does and is thrown.
    public func resumePendingAuthorization() async throws {
        let coordinator = self.coordinator
        try await coordinator.operation { try await coordinator.resumePendingLogin() }
    }

    /// Signs out (`spec/oauth-sdk-api.md` section 12): revokes, ends the provider's session
    /// through the browser, wipes locally; the wipe is unconditional.
    public func logout(_ options: LogoutOptions = .default) async -> LogoutOutcome {
        let coordinator = self.coordinator
        return await coordinator.operation { await coordinator.logout(revoke: options.revoke, endSession: options.endSession) }
    }

    /// The access token, refreshed first if it is at or within its refresh skew. **The escape
    /// hatch**: `authenticatedSession` attaches it without the value passing through app code.
    public func accessToken() async throws -> AccessToken {
        let coordinator = self.coordinator
        return try await coordinator.operation { try await coordinator.accessToken() }
    }

    /// Spends the refresh token now, once, whatever the access token's remaining lifetime.
    public func refresh() async throws {
        let coordinator = self.coordinator
        _ = try await coordinator.operation { try await coordinator.refresh() }
    }

    /// `GET` on the UserInfo endpoint with the session's token; `sub` must equal the ID token's.
    public func userInfo() async throws -> UserInfo {
        guard let subject = await coordinator.restoreClaims()?.subject else {
            throw OAuthError.reauthenticate(.grantRejected)
        }
        let coordinator = self.coordinator
        let userInfoClient = self.userInfoClient
        return try await coordinator.operation { try await userInfoClient.fetch(tokens: coordinator, expectedSubject: subject) }
    }

    /// Which tier the DPoP key reached, or nil under `.bearer`. Asking this generates the key.
    public func keyAttestation() async throws -> KeyAttestation? { try await dpopKey?.attestation() }

    /// A session that attaches the token to requests for `origins` and nothing else
    /// (`spec/oauth-sdk-api.md` section 10), never follows redirects, refreshes once on a 401.
    public func authenticatedSession(origins: Set<String>? = nil) throws -> AuthenticatedSession {
        let scope = origins ?? configuration.protectedOrigins
        if scope.isEmpty {
            throw OAuthError.configuration(.invalidConfiguration(detail: "the authenticated session needs at least one protected origin; none is configured"))
        }
        let coordinator = self.coordinator
        return AuthenticatedSession(tokens: coordinator, scope: try RequestScope(origins: scope), dpop: proofs, session: httpSession, onStepUp: { await coordinator.stepUpRequired() })
    }

    /// Hands a redirect the app received by other means (a Universal Link while the app was
    /// cold) to a pending authorization. Returns whether the URL was this client's redirect.
    public func handleRedirect(_ url: URL) async -> Bool {
        guard let browser, Self.isRedirect(url, to: configuration.core.redirectUri) else { return false }
        await browser.deliver(url)
        return true
    }

    /// The redirect is the configured address, nothing looser: the query and fragment are the
    /// response, not part of the address. Scheme and host compare case-insensitively (RFC 3986
    /// section 3.1 and 3.2.2), the port with its default filled in, and the path exactly as sent,
    /// percent-encoding included: `URL.path` would decode `%2F` and drop a trailing slash, so
    /// `/oauth/` and `/oauth%2Fx` must not match `/oauth` and `/oauth/x`. An empty http(s) path is
    /// `/` (RFC 9110 section 4.2.3). Kept pure so the rule is tested directly.
    static func isRedirect(_ url: URL, to redirectUri: URL) -> Bool {
        guard let actual = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let expected = URLComponents(url: redirectUri, resolvingAgainstBaseURL: false),
              let actualScheme = actual.scheme?.lowercased(), actualScheme == expected.scheme?.lowercased()
        else { return false }
        // A private-use scheme has no host (`com.example.app:/path`), so the host is compared as
        // optionals: nil matches nil and nothing else.
        return actual.host?.lowercased() == expected.host?.lowercased()
            && port(actual, scheme: actualScheme) == port(expected, scheme: actualScheme)
            && path(actual, scheme: actualScheme) == path(expected, scheme: actualScheme)
    }

    private static func port(_ components: URLComponents, scheme: String) -> Int? {
        components.port ?? defaultPort(for: scheme)
    }

    private static func defaultPort(for scheme: String) -> Int? {
        switch scheme {
        case "https": 443
        case "http": 80
        default: nil
        }
    }

    private static func path(_ components: URLComponents, scheme: String) -> String {
        let path = components.percentEncodedPath
        return path.isEmpty && (scheme == "https" || scheme == "http") ? "/" : path
    }

    private func refuseWhileAuthorizing() async throws {
        try await flow.ensureRestored()
        if await flow.states.current == .authorizing {
            throw OAuthError.configuration(.invalidConfiguration(detail: "an authorization is already in progress; observe sessionStates() before asking again"))
        }
    }

    // MARK: - Wiring

    private static func build(
        configuration: OAuthConfiguration,
        presentationAnchor: (@MainActor @Sendable () -> ASPresentationAnchor)?,
        browser injectedBrowser: BrowserAuthorizationSession?,
        credentialStore injectedCredentials: CredentialStore?,
        pendingStore injectedPending: PendingAuthorizationStore?,
        metadataCache injectedMetadataCache: ProviderMetadataCache?,
        jwksCache injectedJwksCache: JwksCache?,
        makeDpopKey: (@Sendable (_ requireHardware: Bool, _ logger: any OAuthLogger) -> SecureEnclaveDpopKey)?
    ) throws -> OAuthClient {
        let logger = configuration.logger
        if let warning = configuration.redirectUriWarning { logger.warn(warning) }
        let core = configuration.core
        let httpClient = URLSessionHTTPClient(session: configuration.urlSession)
        let directory = try cacheDirectory(for: configuration.storageKey)

        let discovery: DiscoveryService
        if let endpoints = configuration.endpoints {
            var metadata = endpoints.toMetadata()
            if let endSession = configuration.endSessionEndpoint { metadata.endSessionEndpoint = endSession }
            discovery = DiscoveryService(issuer: core.issuer, client: StaticDiscoveryClient(metadata: metadata), cache: MemoryMetadataCache())
        } else {
            discovery = DiscoveryService(
                issuer: core.issuer,
                client: EndSessionOverride(delegate: HTTPDiscoveryClient(httpClient: httpClient), endSessionEndpoint: configuration.endSessionEndpoint),
                cache: injectedMetadataCache ?? FileProviderMetadataCache(directory: directory)
            )
        }

        let dpopKey: SecureEnclaveDpopKey?
        if case .dpop(let required) = configuration.tokenBinding {
            dpopKey = makeDpopKey?(required, logger) ?? SecureEnclaveDpopKey(storageKey: configuration.storageKey, requireHardware: required, logger: logger)
        } else {
            dpopKey = nil
        }
        let proofs: DpopProofFactory? = dpopKey.map { DpopProofFactory(key: $0) }

        let credentialStore: CredentialStore = injectedCredentials ?? KeychainCredentialStore(storageKey: configuration.storageKey, unlockPolicy: configuration.unlockPolicy)
        let pendingStore: PendingAuthorizationStore = injectedPending ?? KeychainPendingAuthorizationStore(storageKey: configuration.storageKey, unlockPolicy: configuration.unlockPolicy)
        let webBrowser: WebAuthenticationBrowser? = injectedBrowser == nil
            ? WebAuthenticationBrowser(presentationAnchor: presentationAnchor!, appState: Self.isForeground, logger: logger)
            : nil
        let states = SessionStateHub()
        let flow = AuthorizationFlow(
            configuration: core,
            discovery: discovery,
            pendingStore: pendingStore,
            browser: injectedBrowser ?? webBrowser!,
            states: states,
            tokenBinding: configuration.tokenBinding,
            dpopKey: proofs,
            hasStoredGrant: { try await credentialStore.hasGrant() },
            starter: PushedAuthorizationStarter(configuration: core, httpClient: httpClient, policy: configuration.pushedAuthorization),
            logger: logger
        )
        let jwks = JwksClient(httpClient: httpClient, cache: injectedJwksCache ?? FileJwksCache(directory: directory))
        let validator = JwksIdTokenValidator(
            // The issuer the provider signs under: discovery's, which may carry a trailing slash.
            issuer: { try await discovery.metadata().issuer },
            clientId: core.clientId,
            jwksUri: { try await discovery.metadata().jwksUri },
            allowedAlgorithms: { try await discovery.metadata().idTokenSigningAlgValuesSupported },
            jwks: jwks,
            clockSkewTolerance: configuration.clockSkewTolerance
        )
        let tokenClient = try HTTPTokenClient(
            configuration: core,
            metadata: { try await discovery.metadata() },
            httpClient: httpClient,
            dpop: proofs,
            tokenBinding: configuration.tokenBinding,
            // Nothing a standard does not define (ADR 0001).
            sendIdempotencyKey: false
        )
        let coordinator = SessionCoordinator(
            flow: flow,
            tokenClient: tokenClient,
            credentialStore: credentialStore,
            retryPolicy: configuration.retryPolicy,
            onCredentialsWiped: {
                await proofs?.clearNonces()
                try await dpopKey?.destroy()
            },
            logger: logger,
            refreshTokens: .optional,
            idTokenValidator: validator
        )
        let userInfo = HTTPUserInfoClient(
            userinfoEndpoint: { try await discovery.metadata().userinfoEndpoint },
            httpClient: httpClient,
            dpop: proofs,
            verifier: JwsVerifier(
                jwksUri: { try await discovery.metadata().jwksUri },
                allowedAlgorithms: { try await discovery.metadata().idTokenSigningAlgValuesSupported },
                jwks: jwks
            )
        )
        return OAuthClient(configuration: configuration, flow: flow, coordinator: coordinator, userInfoClient: userInfo, proofs: proofs, dpopKey: dpopKey, browser: webBrowser, httpSession: configuration.urlSession)
    }

    /// Application Support, excluded from backup: the pending request and the refresh token
    /// are in the Keychain, but the caches must not be restored onto another device either.
    private static func cacheDirectory(for storageKey: String) throws -> URL {
        let base = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        var directory = base.appendingPathComponent("versola-oauth", isDirectory: true).appendingPathComponent(storageKey, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? directory.setResourceValues(values)
        return directory
    }

    /// Whether the app is in the foreground at the moment the browser reports a cancel: the
    /// pairing `spec/state-machine.md`'s cancel table requires. Foreground in UIKit's own terms,
    /// `.active` or `.inactive`: the system sheet the session presents makes the app
    /// `.inactive` for as long as it is up, and the completion runs before the app is active
    /// again, so "active" alone would read every user cancel as a system one and strand the
    /// pending request. Only `.background` is the system's doing. macOS has no such state.
    @MainActor
    private static func isForeground() -> Bool {
        #if canImport(UIKit)
        return UIApplication.shared.applicationState != .background
        #else
        return true
        #endif
    }
}

#if canImport(UIKit)
import UIKit
#else
import AppKit
#endif

/// The one discovered value a configuration may replace (`spec/oauth-sdk-api.md` section 3).
private struct EndSessionOverride: DiscoveryClient {
    let delegate: DiscoveryClient
    let endSessionEndpoint: String?
    func fetch(issuer: String) async throws -> ProviderMetadata {
        var metadata = try await delegate.fetch(issuer: issuer)
        if let endSessionEndpoint { metadata.endSessionEndpoint = endSessionEndpoint }
        return metadata
    }
}
