import Foundation

/// The browser leg of the state machine: `unauthenticated -> authorizing -> (validated grant)`,
/// with the cancel and process-death transitions of `spec/state-machine.md`.
///
/// It lives in the core rather than the facade because the orchestration is the protocol: the
/// order of the redirect checks and the moment the pending request is persisted are both
/// normative. It stops at a validated `AuthorizationGrant`; redeeming the code and persisting
/// the result is the session coordinator's job, which then calls `completeLogin()`.
///
/// Nothing here knows about Versola. Every URL it uses comes from discovery.
///
/// Serialisation: `authorize`, `resumePendingAuthorization` and `endSession` share one browser
/// and one redirect channel, so a second call while one awaits the browser must wait, not
/// interleave. An actor alone does not give that, because each `await` on the browser is a
/// point where another caller enters. The gate below is a boolean plus a FIFO queue of
/// continuations, held on this actor; a waiter that is cancelled leaves the queue and throws
/// `CancellationError`. Android's equivalent lock is process-wide; here it is per instance,
/// because Swift forbids a global mutable lock and the facade creates one flow per client.
package actor AuthorizationFlow {
    package nonisolated let configuration: CoreConfiguration

    private let discovery: DiscoveryService
    private let pendingStore: PendingAuthorizationStore
    private let browser: BrowserAuthorizationSession
    /// The state machine both the flow and the coordinator publish on; the facade streams it.
    package nonisolated let states: SessionStateHub
    private let tokenBinding: TokenBinding
    private let dpopKey: DpopProofSource?
    private let clock: Clock
    private let random: RandomSource
    private let hasStoredGrant: @Sendable () async throws -> Bool
    private let starter: AuthorizationStarter?
    private let logger: OAuthLogger?

    private var restored = false
    private var restoreTask: Task<Void, Error>?
    private var expiredOnRestore = false

    private var gateHeld = false
    private var gateQueue: [(id: UUID, continuation: CheckedContinuation<Void, Error>)] = []

    /// `state` values of authorizations whose caller was cancelled while their tab was open: the
    /// redirects a later call may have to step over. Bounded, because an app that cancels
    /// repeatedly without ever redirecting would otherwise grow this without end; dropping the
    /// oldest only restores the old behaviour for it, a state mismatch.
    private var abandonedStates: [String] = []
    private static let maxAbandonedStates = 8

    /// - Parameters:
    ///   - dpopKey: the key `dpop_jkt` commits to. Needed when `tokenBinding` is `.dpop`; a key
    ///     handed in alongside `.bearer` is ignored rather than quietly overriding the choice.
    ///   - hasStoredGrant: whether a refresh grant is durably stored (`CredentialStore.hasGrant`).
    ///     One bit rather than the store itself, because it is the one question a store answers
    ///     without its key, so a cold start does not become an unlock prompt. The default
    ///     ("no grant") suits the browser leg on its own; a coordinator must supply the real one,
    ///     or a returning session reads as signed out on every cold start.
    ///   - starter: builds the request when it is not the plain PKCE request this class builds.
    package init(
        configuration: CoreConfiguration,
        discovery: DiscoveryService,
        pendingStore: PendingAuthorizationStore,
        browser: BrowserAuthorizationSession,
        states: SessionStateHub,
        tokenBinding: TokenBinding = .bearer,
        dpopKey: DpopProofSource? = nil,
        clock: Clock = .system,
        random: RandomSource = SystemRandomSource(),
        hasStoredGrant: @escaping @Sendable () async throws -> Bool = { false },
        starter: AuthorizationStarter? = nil,
        logger: OAuthLogger? = nil
    ) {
        self.configuration = configuration
        self.discovery = discovery
        self.pendingStore = pendingStore
        self.browser = browser
        self.states = states
        self.tokenBinding = tokenBinding
        self.dpopKey = dpopKey
        self.clock = clock
        self.random = random
        self.hasStoredGrant = hasStoredGrant
        self.starter = starter
        self.logger = logger
    }

    /// The provider's metadata, fetched once and cached across restarts and logout.
    package func metadata() async throws -> ProviderMetadata {
        try await discovery.metadata()
    }

    // MARK: Restoration

    /// Reads the persisted state once and publishes it. Idempotent, and concurrent callers share
    /// one read. A cold start killed mid-browser publishes `authorizing`, never `unauthenticated`
    /// (scenario 12).
    ///
    /// A stored grant outranks a pending request, and is read first (`spec/state-machine.md`):
    /// the request beside it is the residue of a login killed between persisting the token and
    /// clearing the slot, its code already redeemed, so resuming it could only fail as
    /// `invalid_grant`. A store that is not readable yet (locked device, `onAppUnlock`) publishes
    /// `locked` and throws `recoverable(.unlockRequired)`; the restore is retried by the next call. A pending request older than ten minutes is discarded and remembered, so
    /// that `resumePendingAuthorization()` can say it expired rather than that nothing was there.
    package func ensureRestored() async throws {
        if restored { return }
        if let restoreTask { return try await restoreTask.value }
        let task = Task { try await self.restore() }
        restoreTask = task
        try await task.value
    }

    private func restore() async throws {
        defer { restoreTask = nil }
        let next: SessionState
        do {
            // The grant first, then the pending request only when there is no grant: a slot
            // that cannot be read (a Keychain item of a locked device) must neither hide a
            // returning user's session nor stand between it and `authenticated`.
            if try await hasStoredGrant() {
                // The residue of a login killed between persisting the token and clearing the
                // slot; discarded unread.
                try await pendingStore.clear()
                next = .authenticated
            } else if let pending = try await pendingStore.load() {
                if pending.isExpired(at: clock.now()) {
                    try await pendingStore.clear()
                    expiredOnRestore = true
                    next = .unauthenticated
                } else {
                    next = .authorizing
                }
            } else {
                next = .unauthenticated
            }
        } catch let error as OAuthError {
            // A store that needs the device unlocked has not said there is nothing in it: the
            // state is `locked`, never a false `unauthenticated`, and the restore is not
            // remembered, so the next call (once the app has asked the user to unlock) reads
            // again. Any other failure is the caller's to see; the hub is left as it was.
            if case .recoverable(.unlockRequired) = error { await states.set(.locked) }
            throw error
        }
        await states.set(next)
        restored = true
    }

    // MARK: Transitions the coordinator drives

    /// `authorizing -> authenticated`: called once the coordinator holds a durably stored
    /// refresh token, never before. Wipes the pending request, which `authorize` and
    /// `resumePendingAuthorization` deliberately leave in place until this point, so a process
    /// killed between redeeming the code and persisting the token still finds an `authorizing`
    /// session to resume.
    package func completeLogin() async throws {
        try await pendingStore.clear()
        await states.set(.authenticated)
    }

    /// The exchange failed, or the caller walked away from it: the code is spent and the slot
    /// can never complete, so it goes, and the session settles where the authorization was
    /// entered from rather than on a state the grant on disk contradicts.
    package func abandonLogin() async {
        do {
            try await pendingStore.clear()
        } catch {
            // The slot expires by itself within ten minutes; a failed clear must not replace the
            // error that brought us here.
            logger?.warn("the pending authorization request could not be cleared")
        }
        await states.set(await settledState())
    }

    /// `authenticated -> stepUpRequired`; nothing else moves, the grant is intact.
    package func enterStepUpRequired() async {
        if await states.current == .authenticated { await states.set(.stepUpRequired) }
    }

    /// `loggingOut -> unauthenticated`: the local half of logout. Wipes the pending request too,
    /// so a login abandoned mid-browser cannot survive a sign-out and resume into the next
    /// user's session.
    package func completeLogout() async {
        do {
            try await pendingStore.clear()
        } catch {
            logger?.warn("the pending authorization request could not be cleared")
        }
        await states.set(.unauthenticated)
    }

    /// Pushes a state the coordinator owns (`refreshing`, `locked`, a return to `authenticated`);
    /// this class performs none of those transitions itself, it only hosts the hub.
    package func setState(_ next: SessionState) async {
        await states.set(next)
    }

    /// Where a browser leg that did not end in a grant leaves the session: `authenticated` while
    /// a grant is stored (a step-up the user cancelled is not a sign-out), else `unauthenticated`.
    /// A probe that fails counts as "no grant": this runs on error paths, where the original
    /// error matters more.
    private func settledState() async -> SessionState {
        ((try? await hasStoredGrant()) ?? false) ? .authenticated : .unauthenticated
    }

    // MARK: Authorize

    /// Opens the system browser, waits for the redirect, and validates it.
    ///
    /// The pending request is persisted before the browser opens, because the app can be killed
    /// between the two. A slot left behind by a cancelled caller is superseded, not protected:
    /// the app is asking for a new authorization and cannot be made to wait out the old slot's
    /// ten minutes. The abandoned tab can still redirect, so its `state` is remembered and that
    /// redirect is discarded rather than allowed to fail this call as a mismatch.
    ///
    /// On success the state stays `authorizing` and the pending request stays stored; the
    /// coordinator completes the login after the token exchange.
    package func authorize(
        scopes: [String],
        acrValues: [String] = [],
        maxAge: Int? = nil,
        parameters: AuthorizationParameters = .none,
        ephemeralBrowser: Bool = false
    ) async throws -> AuthorizationGrant {
        try await exclusivelyOrRefuse {
            try await ensureRestored()
            let metadata = try await discovery.metadata()
            // `code_challenge_methods_supported` present without S256 is a provider this SDK
            // cannot talk to, since it sends S256 and nothing else. Absent means unknown, and
            // S256 is sent (`spec/oauth-sdk-api.md` section 6).
            if !metadata.codeChallengeMethodsSupported.isEmpty,
               !metadata.codeChallengeMethodsSupported.contains("S256") {
                throw OAuthError.configuration(.providerUnsupported(capability: "S256"))
            }
            let request = AuthorizationRequest.create(
                configuration: configuration,
                scopes: scopes,
                acrValues: acrValues,
                maxAge: maxAge,
                dpopJkt: try await dpopJkt(metadata),
                parameters: parameters,
                random: random
            )
            let pending: PendingAuthorizationRequest
            let uri: URL
            if let starter {
                let started = try await starter.start(request: request, metadata: metadata, now: clock.now())
                pending = started.pending
                uri = started.browserUri
            } else {
                pending = request.toPending(
                    createdAt: clock.now(), issRequired: metadata.authorizationResponseIssParameterSupported
                )
                uri = try request.toUri(authorizationEndpoint: metadata.authorizationEndpoint)
            }
            // Before the state changes and before the browser opens: the order is the point.
            try await pendingStore.save(pending)
            await states.set(.authorizing)

            let options = BrowserSessionOptions(ephemeral: ephemeralBrowser, redirectURI: configuration.redirectUri)
            let outcome: BrowserOutcome
            do {
                // The user's time in the browser is not the SDK's retrying (`OperationBudget.paused`).
                let first = try await OperationBudget.paused { try await browser.authorize(uri, options: options) }
                outcome = try await belongingTo(pending, first: first)
            } catch is CancellationError {
                // The caller was cancelled, and on this platform that closed the sheet: the
                // browser session's cancellation handler dismisses it, so no redirect can
                // follow. The request and the `authorizing` state go with it; left behind they
                // would refuse every `login()` for ten minutes (`spec/state-machine.md`, the
                // iOS note under cancel). Android's Custom Tab outlives its caller and keeps
                // the slot; that difference is the platform's, not the state machine's. The
                // state is still remembered as abandoned: a redirect the app hands in later
                // through other means with that state is discarded rather than failed.
                rememberAbandoned(pending.state)
                await abandonLogin()
                throw CancellationError()
            } catch {
                // Launching or awaiting the browser failed outright (no browser available, say).
                // Nothing is pending, so neither the request nor `authorizing` may survive: a
                // later cold start would otherwise look resumable and wait for a redirect that
                // can never arrive.
                await abandonLogin()
                throw error
            }
            return try await complete(outcome, pending: pending, metadata: metadata)
        }
    }

    // MARK: Resume

    /// Finishes an authorization that outlived the process that started it.
    ///
    /// Returns nil when nothing is pending. Throws `recoverable(.pendingRequestExpired)` when the
    /// restored request is older than ten minutes, or when the redirect did not arrive in what
    /// remains of them: the wait is bounded because an unbounded one would hold the gate, and
    /// with it every later login, for as long as the app lives. A system cancel leaves a pending
    /// request with no live caller, which is what this call is for; a user cancel wipes it.
    ///
    /// The `BrowserAuthorizationSession.awaitPendingRedirect()` implementation must return or
    /// throw when its task is cancelled, or the timeout cannot take effect.
    package func resumePendingAuthorization() async throws -> AuthorizationGrant? {
        try await exclusively {
            try await ensureRestored()
            guard let pending = try await pendingStore.load() else {
                // Restoring already discarded it, and "expired" is not "nothing was pending":
                // the caller asked to resume a flow that existed and can no longer be finished.
                if expiredOnRestore {
                    expiredOnRestore = false
                    throw OAuthError.recoverable(.pendingRequestExpired)
                }
                return nil
            }
            let now = clock.now()
            if pending.isExpired(at: now) {
                await abandonLogin()
                throw OAuthError.recoverable(.pendingRequestExpired)
            }
            await states.set(.authorizing)
            let remaining = PendingAuthorizationRequest.maxAge - now.timeIntervalSince(pending.createdAt)
            guard let outcome = try await awaitRedirect(pending, within: remaining) else {
                await abandonLogin()
                throw OAuthError.recoverable(.pendingRequestExpired)
            }
            return try await complete(outcome, pending: pending, metadata: try await discovery.metadata())
        }
    }

    /// The next redirect that answers `pending`, or nil when `seconds` pass first.
    private func awaitRedirect(
        _ pending: PendingAuthorizationRequest, within seconds: TimeInterval
    ) async throws -> BrowserOutcome? {
        let nanoseconds = UInt64(max(seconds, 0) * 1_000_000_000)
        return try await withThrowingTaskGroup(of: BrowserOutcome?.self) { group in
            group.addTask {
                let first = try await OperationBudget.paused { try await self.browser.awaitPendingRedirect() }
                return try await self.belongingTo(pending, first: first)
            }
            group.addTask {
                try await Task.sleep(nanoseconds: nanoseconds)
                return nil
            }
            defer { group.cancelAll() }
            guard let winner = try await group.next() else { return nil }
            return winner
        }
    }

    // MARK: End session

    /// The server leg of logout: the provider's `end_session_endpoint` in the system browser,
    /// with `id_token_hint` so the session ends without a confirmation page, and
    /// `post_logout_redirect_uri` so the browser comes back once it has.
    ///
    /// Returns whether the provider acknowledged: the redirect came back carrying the `state`
    /// that was sent. False covers everything else (no endpoint advertised, the user dismissed
    /// the page, the browser failed, a wrong `state`), and none of it is thrown, because only the
    /// local teardown is unconditional and the caller wipes regardless. Never ephemeral: the
    /// point is to end the session the shared browser holds.
    package func endSession(idTokenHint: String?) async throws -> Bool {
        try await exclusively {
            try await ensureRestored()
            guard let endpoint = try await discovery.metadata().endSessionEndpoint, !endpoint.isEmpty else {
                return false
            }
            let postLogoutRedirectUri = configuration.postLogoutRedirectUri
            // `state` goes whether or not a redirect URI does: it costs nothing and is what lets
            // the redirect be told apart from a stale one.
            let expectedState = SecureTokens.generate(random)
            var pairs: [(String, String)] = []
            if let idTokenHint { pairs.append(("id_token_hint", idTokenHint)) }
            if let postLogoutRedirectUri { pairs.append(("post_logout_redirect_uri", postLogoutRedirectUri.absoluteString)) }
            pairs.append(("state", expectedState))
            guard let uri = try? FormEncoding.withQuery(endpoint, pairs) else { return false }

            let outcome: BrowserOutcome
            do {
                outcome = try await OperationBudget.paused { try await browser.authorize(uri, options: BrowserSessionOptions(redirectURI: postLogoutRedirectUri)) }
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                // No browser, or it failed to launch: the server session outlives this logout,
                // which is exactly what the return value says.
                return false
            }
            guard case .redirect(let url) = outcome, let state = AuthorizationResponseValidator.stateOf(url) else {
                return false
            }
            return SecureTokens.constantTimeEquals(expectedState, state)
        }
    }

    // MARK: Internals

    /// Consumes redirects until one answers `pending`. A tab abandoned by a cancelled caller can
    /// redirect after this call started; that redirect carries a `state` this process issued
    /// itself, so failing on it would lose a live authorization to a tab the user forgot about.
    /// Each abandoned `state` is discarded once, which is also what bounds the loop; anything
    /// else, an unknown `state` included, still reaches the validator.
    private func belongingTo(_ pending: PendingAuthorizationRequest, first: BrowserOutcome) async throws
        -> BrowserOutcome {
        var outcome = first
        while isAbandoned(outcome, pending: pending) {
            outcome = try await OperationBudget.paused { try await browser.awaitPendingRedirect() }
        }
        return outcome
    }

    private func isAbandoned(_ outcome: BrowserOutcome, pending: PendingAuthorizationRequest) -> Bool {
        guard case .redirect(let url) = outcome, let state = AuthorizationResponseValidator.stateOf(url),
              state != pending.state, let index = abandonedStates.firstIndex(of: state) else { return false }
        abandonedStates.remove(at: index)
        return true
    }

    private func rememberAbandoned(_ state: String) {
        abandonedStates.append(state)
        if abandonedStates.count > Self.maxAbandonedStates { abandonedStates.removeFirst() }
    }

    private func complete(
        _ outcome: BrowserOutcome, pending: PendingAuthorizationRequest, metadata: ProviderMetadata
    ) async throws -> AuthorizationGrant {
        // Being answered is what stops this request being anyone's leftover, whichever way it
        // ends: a resumed one is no longer abandoned, and a rejected one never will be.
        abandonedStates.removeAll { $0 == pending.state }
        switch outcome {
        case .userCancelled:
            await abandonLogin()
            throw OAuthError.recoverable(.userCancelled)
        case .systemCancelled:
            // The OS tore the session down: the request and `authorizing` are kept so the flow
            // can be resumed (`spec/state-machine.md`, the cancel table).
            throw OAuthError.recoverable(.systemCancelled)
        case .redirect(let url):
            do {
                return try AuthorizationResponseValidator.validate(
                    redirect: url,
                    pending: pending,
                    issuer: configuration.issuer,
                    issParameterSupported: metadata.authorizationResponseIssParameterSupported
                )
                // Deliberately still `authorizing` with the request still stored: the machine
                // reaches `authenticated` only once a refresh token is durably held.
            } catch {
                // A rejected response is unsafe to continue from, whichever way it was rejected.
                await abandonLogin()
                throw error
            }
        }
    }

    /// The thumbprint to commit to, and the point at which a required binding is enforced
    /// against the deployment: before the browser opens, so an app that cannot be served finds
    /// out at the first login rather than at the first API call. A deployment that does not
    /// advertise DPoP gets no `dpop_jkt`; sending one anyway would bind a code the token endpoint
    /// will redeem without a proof.
    private func dpopJkt(_ metadata: ProviderMetadata) async throws -> String? {
        guard case .dpop(let required) = tokenBinding else { return nil }
        // A starter that binds the key on a call of its own sets `dpop_jkt` from the proof it
        // verified: a thumbprint named here would be a claim it cannot verify.
        if starter?.bindsDpopKeyItself == true { return nil }
        // A key-bound session without a key would send no `dpop_jkt` and authorize unbound
        // without the app ever being told. Wiring, not deployment, but the initializer cannot
        // throw, so it fails here, before anything is persisted.
        guard let dpopKey else {
            throw OAuthError.configuration(.invalidConfiguration(
                detail: "TokenBinding.dpop needs a DPoP key; pass one or select TokenBinding.bearer"
            ))
        }
        if !metadata.supportsDpop {
            if required { throw OAuthError.configuration(.providerUnsupported(capability: "dpop")) }
            logger?.warn("the provider does not advertise DPoP; continuing with bearer tokens")
            return nil
        }
        return try await dpopKey.thumbprint()
    }

    // MARK: Gate

    private func exclusively<T: Sendable>(_ body: () async throws -> T) async throws -> T {
        try await acquire()
        defer { release() }
        return try await body()
    }

    /// `authorize` does not queue behind an open browser: a second `login()` while one is
    /// outstanding is refused under the gate, so two calls in flight (a double tap) cannot both
    /// read `unauthenticated` and open two sheets (`spec/oauth-sdk-api.md` section 5).
    private func exclusivelyOrRefuse<T: Sendable>(_ body: () async throws -> T) async throws -> T {
        try Task.checkCancellation()
        if gateHeld {
            throw OAuthError.configuration(.invalidConfiguration(detail: "an authorization is already in progress; observe sessionStates() before asking again"))
        }
        gateHeld = true
        defer { release() }
        return try await body()
    }

    private func acquire() async throws {
        try Task.checkCancellation()
        if !gateHeld {
            gateHeld = true
            return
        }
        let id = UUID()
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
                gateQueue.append((id: id, continuation: continuation))
            }
        } onCancel: {
            Task { await self.cancelWaiter(id) }
        }
    }

    /// Ownership passes straight to the next waiter, so the gate is never observably free
    /// between two callers and a third cannot slip in.
    private func release() {
        if gateQueue.isEmpty {
            gateHeld = false
        } else {
            gateQueue.removeFirst().continuation.resume()
        }
    }

    private func cancelWaiter(_ id: UUID) {
        guard let index = gateQueue.firstIndex(where: { $0.id == id }) else { return }
        gateQueue.remove(at: index).continuation.resume(throwing: CancellationError())
    }
}
