import AuthenticationServices
import Foundation
import OAuthClient
import OAuthCore
import VersolaEdge

/// A session with a Versola deployment, for a native app (`spec/versola-sdk-api.md`): sign-in in the
/// system browser, started and finished through the edge's native endpoints, refresh and revocation
/// through the same edge, authenticated HTTP to it, and sign-out. The app sees a session,
/// observable through ``sessionStates()``, and never a token.
///
/// The edge is the only server this class calls. It is the OAuth client towards `auth`; the device
/// holds a DPoP key, generated at the first sign-in and kept in the Secure Enclave where the device
/// has one, and every token is bound to it. There is no discovery, no bearer mode and no direct
/// call to `auth`: a deployment with cells has an edge at its issuer's address, which serves the
/// sign-in pages and nothing a client calls. An app that talks to an `auth` directly uses
/// `OAuthClient`.
public final class Versola: VersolaApi, Sendable {
    /// The configuration this client was created with.
    public let configuration: VersolaConfiguration
    private let flow: AuthorizationFlow
    private let coordinator: SessionCoordinator
    private let proofs: DpopProofFactory
    private let dpopKey: SecureEnclaveDpopKey
    private let grantedScope: any GrantedScopeStore
    private let browser: WebAuthenticationBrowser?
    /// Single flight for the resume `create` starts and an explicit `resumePendingAuthorization()`.
    private let backgroundResume: ResumeFlight
    /// The `login()` or `stepUp()` this client is carrying out, which a second identical call joins.
    private let loginFlights = LoginFlights()

    /// One client per storage key per process: a second `create` with the same edge, issuer and
    /// client id returns the first instance (two coordinators over one Keychain item would race each
    /// other's refresh), and a *different* configuration for the same key is refused.
    private static let registry = Registry()

    private actor Registry {
        var clients: [String: Versola] = [:]

        /// `created` is true only for the call that built the client: that call, and no later one
        /// that merely gets the instance back, starts the resume of a cold start.
        func resolve(_ configuration: VersolaConfiguration, build: () throws -> Versola) throws -> (client: Versola, created: Bool) {
            if let existing = clients[configuration.storageKey] {
                if existing.configuration.fingerprint != configuration.fingerprint {
                    throw OAuthError.configuration(.invalidConfiguration(detail: "a client for \(configuration.edgeOrigin) / \(configuration.clientId) already exists in this process with a different configuration"))
                }
                // The session and the logger are part of the configuration for this purpose, by identity:
                // returning the first client would silently drop the app's new timeouts, pinning or
                // logging. An app that re-runs `create` (a scene reconnecting) holds on to them.
                if !existing.configuration.sharesWiring(with: configuration) {
                    throw OAuthError.configuration(.invalidConfiguration(detail: "a client for \(configuration.edgeOrigin) / \(configuration.clientId) already exists in this process with a different urlSession or logger"))
                }
                return (existing, false)
            }
            let client = try build()
            clients[configuration.storageKey] = client
            return (client, true)
        }

        /// Ends the resumes the forgotten clients started, and waits for them.
        func forgetAll() async {
            let forgotten = Array(clients.values)
            clients.removeAll()
            for client in forgotten { await client.backgroundResume.cancelInFlight() }
        }
    }

    /// Wires the client for `configuration`. No network I/O and no key generation happen here: the
    /// DPoP key is generated at the first sign-in, and there is no discovery to fetch.
    ///
    /// Restores the persisted state (a read of the Keychain, no network). An authorization that
    /// outlived the process that began it (the app was killed while the browser was up) is finished
    /// from there: when the restored state is `authorizing`, the SDK waits for the redirect the app
    /// hands to ``handleRedirect(_:)`` for what is left of the lifetime edge gave the request (at
    /// most ten minutes), then runs the tail of ``login(_:)`` and publishes `authenticated`. Observe
    /// ``sessionStates()`` to follow it. A failure is logged, not thrown.
    ///
    /// One instance per edge, issuer and client id per process: a second call with the same
    /// configuration returns the first instance, so a scene that reconnects may call this again; one
    /// that differs in anything else is refused with `configuration(.invalidConfiguration)` rather than
    /// silently sharing the first one's settings. The `urlSession` and the `logger` are compared by
    /// identity, so keep them.
    ///
    /// - Parameter presentationAnchor: the window the browser sheet is presented from, supplied by
    ///   the app; the SDK never finds a window by itself.
    public static func create(
        configuration: VersolaConfiguration,
        presentationAnchor: @escaping @MainActor @Sendable () -> ASPresentationAnchor
    ) async throws -> Versola {
        let (client, created) = try await registry.resolve(configuration) {
            try build(configuration: configuration, presentationAnchor: presentationAnchor, wiring: nil)
        }
        if created { await client.restore() }
        return client
    }

    /// What a test replaces: the browser leg, the stores, the DPoP key, the HTTP client and the clock.
    package struct Wiring: Sendable {
        package var browser: BrowserAuthorizationSession
        package var credentialStore: CredentialStore
        package var pendingStore: PendingAuthorizationStore
        package var endpointsStore: any EdgeEndpointsStore
        package var grantedScopeStore: any GrantedScopeStore
        package var httpClient: HTTPClient?
        /// The DPoP key, built from the configuration's hardware requirement and the logger; told whether a
        /// grant is stored, as the real one is.
        package var makeDpopKey: @Sendable (_ requireHardware: Bool, _ logger: any OAuthLogger, _ isGrantHeld: @escaping @Sendable () async throws -> Bool) -> SecureEnclaveDpopKey
        package var clock: Clock

        package init(
            browser: BrowserAuthorizationSession, credentialStore: CredentialStore, pendingStore: PendingAuthorizationStore,
            endpointsStore: any EdgeEndpointsStore, grantedScopeStore: any GrantedScopeStore, httpClient: HTTPClient? = nil,
            makeDpopKey: @escaping @Sendable (Bool, any OAuthLogger, @escaping @Sendable () async throws -> Bool) -> SecureEnclaveDpopKey,
            clock: Clock = .system
        ) {
            self.browser = browser
            self.credentialStore = credentialStore
            self.pendingStore = pendingStore
            self.endpointsStore = endpointsStore
            self.grantedScopeStore = grantedScopeStore
            self.httpClient = httpClient
            self.makeDpopKey = makeDpopKey
            self.clock = clock
        }
    }

    /// Wiring for a test: the browser leg, the stores, the HTTP client and the key replaced. Package
    /// access, not public: the browser contract stays URI-only.
    package static func create(configuration: VersolaConfiguration, wiring: Wiring) async throws -> Versola {
        let (client, created) = try await registry.resolve(configuration) {
            try build(configuration: configuration, presentationAnchor: nil, wiring: wiring)
        }
        if created { await client.restore() }
        return client
    }

    /// Forgets every client this process created, for tests that each stage an edge at the same
    /// address. The instances are not closed.
    package static func forgetAll() async {
        await registry.forgetAll()
    }

    private init(
        configuration: VersolaConfiguration, flow: AuthorizationFlow, coordinator: SessionCoordinator, proofs: DpopProofFactory,
        dpopKey: SecureEnclaveDpopKey, grantedScope: any GrantedScopeStore, browser: WebAuthenticationBrowser?,
        backgroundResume: ResumeFlight
    ) {
        self.configuration = configuration
        self.flow = flow
        self.coordinator = coordinator
        self.proofs = proofs
        self.dpopKey = dpopKey
        self.grantedScope = grantedScope
        self.browser = browser
        self.backgroundResume = backgroundResume
    }

    // MARK: - Surface

    /// The state machine of `spec/state-machine.md`, one stream per observer. The first value is the
    /// restored state: an app killed while the browser was up observes `authorizing` on cold start,
    /// and the sign-in whose redirect reaches that process is finished by the SDK itself.
    public func sessionStates() async -> AsyncStream<SessionState> {
        await restoreForObservers()
        return await flow.states.stream()
    }

    /// The state now, after the restore a cold start owes; for code that must choose a screen at once.
    public var sessionState: SessionState {
        get async {
            await restoreForObservers()
            return await flow.states.current
        }
    }

    /// The claims of this session's ID token, or nil when there is no session. Its `iss`, `aud`,
    /// `exp`, `nonce` and `auth_time` were checked; its signature was not, because no key set is
    /// reachable from a native app (`spec/versola-sdk-api.md` section 9). Use it to show who is
    /// signed in; what the user may do is the edge's decision, made from the access token.
    public var claims: IdTokenClaims? {
        get async { await coordinator.restoreClaims() }
    }

    /// Signs in: asks the edge to start an authorization, opens the system browser on the address it
    /// answers, validates the redirect, redeems the code through the edge, checks the ID token and
    /// persists the grant, in that order. `authenticated` is published only once the grant is
    /// durably stored. Returns nothing on purpose: the session is observable.
    ///
    /// While `authenticated`, a successful sign-in replaces the session, as another user if that is
    /// who signed in; a cancelled or failed one leaves it as it was. The same call made again while
    /// one is in flight joins it; a different one is refused with `configuration(.invalidConfiguration)`.
    ///
    /// The sign-in has as long as the edge said (`expires_in` of its answer, at most ten minutes).
    /// After that the call fails with `recoverable(.pendingRequestExpired)`: offer to start again.
    public func login(_ options: LoginOptions = LoginOptions()) async throws {
        try await authorize(options, acrValues: options.acrValues, maxAge: options.maxAge, expectedSubject: nil)
    }

    /// Answers the `OAuthError.stepUp` the authenticated session raised by signing the user in again at
    /// the authentication context the edge asked for; the app then re-issues the call that was refused.
    /// Without `options` the scopes are the ones the session was granted, which the SDK remembers.
    ///
    /// The step-up must come back as the user of the session. Nothing on the wire ties the two
    /// together, so the SDK compares the subject: a person who signs in as someone else in the browser
    /// gets `recoverable(.accountMismatch)`, nothing of that sign-in is kept and the session is as it
    /// was. Tell the user which account to continue with. Any error other than `.stepUp`, and a call
    /// with no session to strengthen, is `configuration(.invalidConfiguration)`.
    public func stepUp(_ challenge: OAuthError, options: LoginOptions? = nil) async throws {
        guard case .stepUp(let acrValues, let maxAge) = challenge else {
            throw OAuthError.configuration(.invalidConfiguration(detail: "stepUp needs an OAuthError.stepUp challenge"))
        }
        // Read before the browser opens, and not swallowed: a step-up that cannot learn whose session
        // it strengthens (a locked store) fails here with the store's own error.
        guard let subject = try await coordinator.sessionSubject() else {
            throw OAuthError.configuration(.invalidConfiguration(detail: "stepUp() strengthens a session and there is none; call login()"))
        }
        let remembered = options == nil ? await grantedScope.load() : []
        let effective = options ?? LoginOptions(scopes: remembered)
        try await authorize(effective, acrValues: acrValues, maxAge: maxAge, expectedSubject: subject)
    }

    /// `login()` and `stepUp()` are the same operation with different arguments: asking for the same
    /// thing twice joins the call already running (`spec/oauth-sdk-api.md` section 5). The expected
    /// subject is part of what is asked.
    private func authorize(_ options: LoginOptions, acrValues: [String], maxAge: Int?, expectedSubject: String?) async throws {
        let scopes = try options.requestedScopes()
        let parameters = try options.authorizationParameters(maxAge: maxAge)
        let request = LoginRequest(
            scopes: scopes, acrValues: acrValues, maxAge: maxAge, parameters: parameters,
            ephemeralBrowser: options.ephemeralBrowser, expectedSubject: expectedSubject
        )
        try await flow.ensureRestored()
        // A resume that only waits for its redirect (a cold start restored the request and the user
        // abandoned that sheet) is not an authorization to protect: it is ended, as `logout()` ends it.
        if await flow.isAwaitingRedirect { await backgroundResume.cancelInFlight() }
        let coordinator = self.coordinator
        let flow = self.flow
        let grantedScope = self.grantedScope
        let refusal = OAuthError.configuration(.invalidConfiguration(detail: "an authorization is already in progress; observe sessionStates() before asking again"))
        try await loginFlights.run(request, refusal: refusal, elsewhere: { await flow.authorizationInFlight }) {
            let response = try await coordinator.operation {
                try await coordinator.login(
                    scopes: scopes, acrValues: acrValues, maxAge: maxAge, parameters: parameters,
                    ephemeralBrowser: options.ephemeralBrowser, expectedSubject: expectedSubject
                )
            }
            // What the next step-up asks for again, saved after the grant is stored (inside the call
            // that stored it, so a caller that was cancelled meanwhile does not lose it).
            await Self.rememberScope(of: response, requested: scopes, in: grantedScope)
        }
    }

    /// The response's own `scope` when it has one (the server may grant less than was asked), else
    /// what was requested.
    private static func rememberScope(of response: TokenResponse, requested: [String], in store: any GrantedScopeStore) async {
        let granted = response.scope.map { Set($0.split(separator: " ").map(String.init)) } ?? []
        await store.save(granted.isEmpty ? Set(requested).union(["offline_access"]) : granted)
    }

    /// Finishes an authorization that outlived the process that started it. The SDK starts this work
    /// itself when a restore finds `authorizing`, so an app only feeds the redirect the system
    /// delivers to ``handleRedirect(_:)``; calling this after `create` is harmless (it waits for that
    /// resume and returns, or throws its failure, rather than making a second attempt: the code is
    /// single-use). It remains the way to finish a pending request the automatic resume did not see
    /// or could not finish. Returns without effect when nothing is pending.
    public func resumePendingAuthorization() async throws {
        try await backgroundResume.resume()
    }

    private func restore() async {
        // A failure is not final: `sessionState` and every operation restore again.
        try? await flow.ensureRestored()
    }

    /// Signs out: revokes the refresh token through the edge, ends the session at the issuer in the
    /// system browser, and wipes everything credential-shaped, the DPoP key included. The wipe is
    /// unconditional: `unauthenticated` is reached whatever the two server-side steps did, and the
    /// outcome says which of them the server acknowledged. A sign-in still waiting for its redirect
    /// is abandoned first.
    public func logout(_ options: LogoutOptions = LogoutOptions()) async -> LogoutOutcome {
        await backgroundResume.cancelInFlight()
        await loginFlights.cancelAll()
        let coordinator = self.coordinator
        return await coordinator.operation { await coordinator.logout(revoke: options.revoke, endSession: options.endSession) }
    }

    /// Spends the refresh token now, once, however many callers ask. Rarely needed:
    /// ``session()`` refreshes when a token is within its refresh skew or a call comes back 401.
    public func refresh() async throws {
        let coordinator = self.coordinator
        _ = try await coordinator.operation { try await coordinator.refresh() }
    }

    /// Which tier the DPoP key reached, read back from the key and not from what was asked for.
    /// Asking this generates the key.
    public func keyAttestation() async throws -> KeyAttestation? {
        try await dpopKey.attestation()
    }

    /// A session that authenticates every request to the edge: the access token, a DPoP proof for that
    /// request, one nonce retry, one proof retry, one refresh and replay on a 401 that is neither, and
    /// the edge's step-up challenge raised as `OAuthError.stepUp`. A request to any other origin passes
    /// through untouched, and the scope cannot be widened: the token is bound to the device key and is
    /// presented to the edge only.
    public func session() throws -> AuthenticatedSession {
        let coordinator = self.coordinator
        return AuthenticatedSession(
            tokens: coordinator, scope: try RequestScope(origins: [configuration.edgeOrigin]), dpop: proofs,
            session: configuration.urlSession, onStepUp: { await coordinator.stepUpRequired() },
            operation: { call in try await coordinator.operation(call) }
        )
    }

    /// Hands a redirect the app received by other means (a Universal Link while the app was cold) to a
    /// pending authorization. Returns whether the URL was this client's redirect.
    public func handleRedirect(_ url: URL) async -> Bool {
        guard let browser, OAuthClient.isRedirect(url, to: configuration.core.redirectUri) else { return false }
        await browser.deliver(url)
        return true
    }

    /// What an observer's first look does: read the stored session. A store that needs the device
    /// unlocked has already published `locked`; any other failure cannot be thrown from a property,
    /// so it is logged, and the next look reads again.
    private func restoreForObservers() async {
        do {
            try await flow.ensureRestored()
        } catch OAuthError.recoverable(.unlockRequired) {
            // Published as `locked`; not a warning.
        } catch {
            configuration.logger.warn("restoring the stored session failed: \(error is OAuthError ? String(describing: error) : String(describing: type(of: error)))")
        }
    }

    // MARK: - Wiring

    private static func build(
        configuration: VersolaConfiguration,
        presentationAnchor: (@MainActor @Sendable () -> ASPresentationAnchor)?,
        wiring: Wiring?
    ) throws -> Versola {
        let logger = configuration.logger
        let core = configuration.core
        guard let edgeUrl = URL(string: configuration.edgeOrigin) else {
            throw OAuthError.configuration(.invalidConfiguration(detail: "edgeUrl is not a URL"))
        }
        let httpClient: HTTPClient = wiring?.httpClient ?? URLSessionHTTPClient(session: configuration.urlSession)
        let clock = wiring?.clock ?? .system
        let storageKey = configuration.storageKey

        let credentialStore: CredentialStore
        let pendingStore: PendingAuthorizationStore
        let endpoints: any EdgeEndpointsStore
        let grantedScope: any GrantedScopeStore
        let webBrowser: WebAuthenticationBrowser?
        let browser: BrowserAuthorizationSession
        let makeKey: @Sendable (_ isGrantHeld: @escaping @Sendable () async throws -> Bool) -> SecureEnclaveDpopKey
        if let wiring {
            credentialStore = wiring.credentialStore
            pendingStore = wiring.pendingStore
            endpoints = wiring.endpointsStore
            grantedScope = wiring.grantedScopeStore
            webBrowser = nil
            browser = wiring.browser
            makeKey = { wiring.makeDpopKey(configuration.requireHardwareKey, logger, $0) }
        } else {
            // Application Support, excluded from backup, under a name of this facade's own: the pending
            // request and the refresh token are in the Keychain, but the files must not be restored onto
            // another device either.
            let directory = try OAuthClient.cacheDirectory(for: storageKey, under: "versola-sdk")
            // The Keychain outlives the app: a reinstall must not open signed in as the previous
            // install's user (`FirstLaunchGuard`). One guard for every Keychain store of this client.
            let firstLaunch = FirstLaunchGuard(directory: directory, deleteAll: { try KeychainStorage.deleteAll(forStorageKey: storageKey) })
            credentialStore = KeychainCredentialStore(storageKey: storageKey, unlockPolicy: configuration.unlockPolicy, firstLaunch: firstLaunch, logger: logger)
            pendingStore = KeychainPendingAuthorizationStore(storageKey: storageKey, unlockPolicy: configuration.unlockPolicy, firstLaunch: firstLaunch, logger: logger)
            // Unencrypted: two URLs the edge hands to anyone who asks, and scope names.
            endpoints = FileEdgeEndpointsStore(file: directory.appendingPathComponent("native-endpoints.json"))
            grantedScope = FileGrantedScopeStore(file: directory.appendingPathComponent("granted-scope"))
            let anchor = presentationAnchor!
            let created = WebAuthenticationBrowser(presentationAnchor: anchor, appState: { OAuthClient.isForeground(window: anchor()) }, logger: logger)
            webBrowser = created
            browser = created
            makeKey = { isGrantHeld in
                SecureEnclaveDpopKey(storageKey: storageKey, requireHardware: configuration.requireHardwareKey, logger: logger, firstLaunch: firstLaunch, isGrantHeld: isGrantHeld)
            }
        }
        // Told whether a grant is stored, so a key that has gone while one is is `credentialsInvalidated`
        // at the proof rather than a new key the server would refuse (`SecureEnclaveDpopKey.key(mayGenerate:)`).
        let dpopKey = makeKey { try await credentialStore.hasGrant() }
        // One factory for the edge and for the proofs addressed to auth's endpoints. Its nonce cache and its
        // clock offsets are keyed by origin, so the two never mix.
        let proofs = DpopProofFactory(key: dpopKey, clock: clock)

        // Stated, not fetched: the issuer's address serves no discovery document. The issuer is the one the
        // app wrote, not the core's copy, which drops a trailing slash: the redirect's `iss` and the ID
        // token's are compared with it byte for byte (RFC 9207), and `https://a/` and `https://a` are two issuers.
        let discovery = DiscoveryService(
            issuer: core.issuer,
            client: try EdgeMetadata(issuer: configuration.issuer, edgeUrl: edgeUrl, clientId: core.clientId),
            cache: MemoryMetadataCache(),
            clock: clock,
            logger: logger
        )
        let states = SessionStateHub()
        let resumeFlight = ResumeFlight()
        let flow = AuthorizationFlow(
            configuration: core,
            discovery: discovery,
            pendingStore: pendingStore,
            browser: browser,
            states: states,
            tokenBinding: .dpop(requireHardware: configuration.requireHardwareKey),
            dpopKey: proofs,
            clock: clock,
            hasStoredGrant: { try await credentialStore.hasGrant() },
            starter: try EdgeAuthorizationStarter(
                configuration: core,
                native: try HTTPNativeAuthorizationStarter(clientId: core.clientId, edgeUrl: edgeUrl, httpClient: httpClient, dpop: proofs)
            ),
            logger: logger,
            // A restore that finds `authorizing` is the cold start of scenario 12: finish it.
            didRestoreAuthorizing: { await resumeFlight.startIfIdle() }
        )
        let coordinator = SessionCoordinator(
            flow: flow,
            tokenClient: try EdgeNativeTokenClient(
                clientId: core.clientId, issuer: configuration.issuer, edgeUrl: edgeUrl, httpClient: httpClient,
                dpop: proofs, endpoints: endpoints, clock: clock
            ),
            credentialStore: credentialStore,
            retryPolicy: configuration.retryPolicy,
            clock: clock,
            // What the core cannot reach and `spec/state-machine.md` wipes with the grant. The endpoints
            // stay: they are not credentials and survive logout (`spec/versola-sdk-api.md` section 11).
            onCredentialsWiped: {
                await proofs.clearNonces()
                await grantedScope.clear()
                try await dpopKey.destroy()
            },
            logger: logger,
            // Claims without the signature: no key set is reachable (`TlsTrustedIdTokenValidator`).
            idTokenValidator: TlsTrustedIdTokenValidator(
                issuer: configuration.issuer, clientId: core.clientId,
                clockSkewTolerance: configuration.clockSkewTolerance, clock: clock
            )
        )
        resumeFlight.bind(
            run: {
                let resumed = try await coordinator.operation { try await coordinator.resumePendingLogin() }
                guard let resumed else { return false }
                await Self.rememberScope(of: resumed, requested: ["openid"], in: grantedScope)
                return true
            },
            // The typed error's own text, which carries no secret; for anything else only the type.
            log: { error in logger.warn("resuming the pending authorization failed: \(error is OAuthError ? String(describing: error) : String(describing: type(of: error)))") }
        )
        return Versola(
            configuration: configuration, flow: flow, coordinator: coordinator, proofs: proofs, dpopKey: dpopKey,
            grantedScope: grantedScope, browser: webBrowser, backgroundResume: resumeFlight
        )
    }
}
