import CryptoKit
import Foundation

/// The session: what `login()` produced, kept alive by refresh, ended by `logout()`
/// (`spec/state-machine.md`). One refresh in flight at a time, callers coalescing on its
/// result, the rotation slot persisted before the request and the new token before any caller
/// sees it. An actor: every `await` inside is a point another caller can enter, so the epoch
/// is re-checked after each one and nothing persisted belongs to a session that ended meanwhile.
///
/// Mirrors Android's `SessionCoordinator` (the behavioural reference) with the actor replacing
/// its mutex, and a refresh flight that is an unstructured `Task`: a caller cancelled while it
/// awaits the flight does not cancel the refresh, which is what keeps the rotation slot sound
/// and the persistence of a token that already came back from being skipped.
package actor SessionCoordinator: AccessTokenSource {
    private let flow: AuthorizationFlow
    private let tokenClient: TokenClient
    private let credentialStore: CredentialStore
    private let retryPolicy: RetryPolicy
    private let clock: Clock
    private let onCredentialsWiped: @Sendable () async throws -> Void
    private let logger: OAuthLogger?
    private let refreshTokens: RefreshTokenPolicy
    private let idTokenValidator: IdTokenValidator?

    private struct Cached: Sendable {
        let response: TokenResponse
        let receivedAt: Date
    }

    /// A session the provider issued no refresh token for: the access token in memory and the
    /// ID token beside it, ending when the token does (`spec/state-machine.md`, "no refresh token").
    private struct MemorySession: Sendable {
        let rawIdToken: String?
    }

    private var cachedAccessToken: Cached?
    private var memorySession: MemorySession?
    private var claimsRestored = false
    private var warnedOfflineAccess = false
    private var warnedExpiresIn = false
    /// Bumped by every wipe: a flight that started in an older epoch persists nothing.
    private var epoch: UInt64 = 0
    private var flight: Task<TokenResponse, Error>?

    /// The claims of the validated ID token of this session, or nil when there is no session.
    package private(set) var claims: IdTokenClaims?

    package init(
        flow: AuthorizationFlow,
        tokenClient: TokenClient,
        credentialStore: CredentialStore,
        retryPolicy: RetryPolicy = .default,
        clock: Clock = .system,
        onCredentialsWiped: @escaping @Sendable () async throws -> Void = {},
        logger: OAuthLogger? = nil,
        refreshTokens: RefreshTokenPolicy = .required,
        idTokenValidator: IdTokenValidator? = nil
    ) {
        self.flow = flow
        self.tokenClient = tokenClient
        self.credentialStore = credentialStore
        self.retryPolicy = retryPolicy
        self.clock = clock
        self.onCredentialsWiped = onCredentialsWiped
        self.logger = logger
        self.refreshTokens = refreshTokens
        self.idTokenValidator = idTokenValidator
    }

    // MARK: - Claims

    /// The claims, read back from the stored ID token after a cold start: it was validated
    /// before it was stored, so a parse is enough (its `exp` says nothing about the session).
    package func restoreClaims() async -> IdTokenClaims? {
        if let claims { return claims }
        if idTokenValidator == nil || claimsRestored { return nil }
        let stored: String?
        do {
            if let inMemory = memorySession?.rawIdToken { stored = inMemory } else { stored = try await credentialStore.rawIdToken() }
        } catch {
            return nil
        }
        claimsRestored = true
        guard let stored, let parsed = try? IdTokenClaimsParser.parseStored(stored) else { return nil }
        claims = parsed
        return parsed
    }

    // MARK: - Access token

    package func accessToken() async throws -> AccessToken {
        if claims == nil && !claimsRestored { _ = await restoreClaims() }
        if let cached = cachedAccessToken, usable(cached) { return accessToken(of: cached.response) }
        if memorySession != nil { try await expireMemorySession() }
        return accessToken(of: try await refresh(rejected: cachedAccessToken, onlyIfStale: true))
    }

    package func renewAccessToken() async throws -> AccessToken {
        if memorySession != nil { try await expireMemorySession() }
        return accessToken(of: try await refresh(rejected: nil, onlyIfStale: false))
    }

    private func accessToken(of response: TokenResponse) -> AccessToken {
        AccessToken(value: response.accessToken, tokenType: response.tokenType)
    }

    private func usable(_ cached: Cached) -> Bool {
        clock.now().timeIntervalSince(cached.receivedAt) < RefreshSkew.usableFor(response: cached.response)
    }

    /// `authenticated → unauthenticated` for a session without a refresh token: nothing to
    /// spend, so no token request and no browser; the ID token and claims go.
    private func expireMemorySession() async throws -> Never {
        epoch += 1
        cachedAccessToken = nil
        memorySession = nil
        claims = nil
        logger?.warn("the access token expired and the provider issued no refresh token; the session is over")
        await flow.completeLogout()
        throw OAuthError.reauthenticate(.sessionExpired)
    }

    // MARK: - Login

    /// `login()` in full: the browser leg, the code exchange, ID-token validation, persistence,
    /// and only then `authenticated`. One attempt at the exchange, with no retry budget around
    /// it: a code is single-use and a replay can revoke what was issued from it.
    @discardableResult
    package func login(
        scopes: [String],
        acrValues: [String] = [],
        maxAge: Int? = nil,
        parameters: AuthorizationParameters = .none,
        ephemeralBrowser: Bool = false
    ) async throws -> TokenResponse {
        // OpenID Connect Core §11: under `required` the scope that buys a refresh token is
        // asked for here; under `optional` the scopes go as given and the provider's own rule
        // applies (`spec/providers.md`), with one warning when it advertises the scope.
        var requested = scopes
        if refreshTokens == .required, !requested.contains(Self.offlineAccess) { requested.append(Self.offlineAccess) }
        if refreshTokens == .optional, !requested.contains(Self.offlineAccess), !warnedOfflineAccess,
           try await flow.metadata().scopesSupported.contains(Self.offlineAccess) {
            warnedOfflineAccess = true
            logger?.warn("the provider advertises offline_access and the configured scopes omit it; a refresh token may not be issued")
        }
        let grant = try await flow.authorize(scopes: requested, acrValues: acrValues, maxAge: maxAge, parameters: parameters, ephemeralBrowser: ephemeralBrowser)
        return try await finishLogin(grant, maxAge: maxAge)
    }

    /// Finishes a login that outlived the process that started it (scenario 12): the redirect is
    /// awaited and validated against the restored request, then the exchange, ID-token check,
    /// persistence and `authenticated` are the steps `login` ends with. `max_age` comes from the
    /// restored request, since no caller is left to supply it. Nil when nothing was pending.
    @discardableResult
    package func resumePendingLogin() async throws -> TokenResponse? {
        guard let grant = try await flow.resumePendingAuthorization() else { return nil }
        return try await finishLogin(grant, maxAge: grant.maxAge)
    }

    /// The tail of a login, everything after the redirect has been validated. Shared by `login`
    /// and `resumePendingLogin` so a sign-in finished in a cold-started process passes through
    /// exactly the checks and the persistence order of one finished in the process that began it.
    private func finishLogin(_ grant: AuthorizationGrant, maxAge: Int?) async throws -> TokenResponse {
        // The exchange and the persistence run in their own task: a caller cancelled after
        // the server spent the code must not strand a token that came back.
        let flow = self.flow
        let exchange = Task { [self] () throws -> (TokenResponse, IdTokenClaims?) in
            do {
                let issued = try await tokenClient.exchange(grant)
                // Validated before anything is persisted (`spec/oauth-sdk-api.md` section 11).
                var validated: IdTokenClaims?
                if let validator = idTokenValidator {
                    guard let idToken = issued.idToken else { throw OAuthError.configuration(.idTokenRejected(.malformed)) }
                    validated = try await validator.validate(idToken: idToken, expectedNonce: grant.nonce, accessToken: issued.accessToken, maxAge: maxAge, previous: nil, serverTime: issued.serverDate)
                }
                warnIfNoExpiry(issued)
                if refreshTokens == .required, issued.refreshToken == nil {
                    throw OAuthError.configuration(.tokenResponseMalformed(detail: "refresh_token is missing"))
                }
                return (issued, validated)
            } catch {
                await flow.abandonLogin()
                throw error
            }
        }
        let (response, validated) = try await exchange.value
        if let refreshToken = response.refreshToken {
            try await credentialStore.save(refreshToken: refreshToken, rawIdToken: response.idToken)
            memorySession = nil
        } else {
            // A grant already on disk belongs to the session this login replaces; left there it
            // would come back on the next cold start as the previous user (the ghost session
            // `spec/state-machine.md` forbids).
            if (try? await credentialStore.hasGrant()) == true { await clearStoredGrant() }
            memorySession = MemorySession(rawIdToken: response.idToken)
            logger?.warn("the provider issued no refresh token; the session lasts as long as the access token")
        }
        claimsRestored = true
        claims = validated
        try await flow.completeLogin()
        cachedAccessToken = Cached(response: response, receivedAt: clock.now())
        return response
    }

    package func stepUpRequired() async {
        await flow.enterStepUpRequired()
    }

    // MARK: - Refresh

    /// Spends the refresh token now, once, however many callers ask at the same time.
    @discardableResult
    package func refresh() async throws -> TokenResponse {
        try await refresh(rejected: nil, onlyIfStale: false)
    }

    private func refresh(rejected: Cached?, onlyIfStale: Bool) async throws -> TokenResponse {
        if onlyIfStale, let current = cachedAccessToken, current.receivedAt != rejected?.receivedAt, usable(current) {
            return current.response
        }
        if let flight {
            // Joining: a cancellation of this caller leaves the flight to the others.
            return try await flight.value
        }
        // The flight is registered before anything is awaited: an `await` here is a point
        // another caller enters this actor, and finding no flight it would start a second
        // refresh (actor reentrancy, `ios-swift.md`). Everything that suspends runs inside it.
        let startedIn = epoch
        let task = Task { [self] in
            defer { endFlight() }
            // The state `refreshing` is entered from: not assumed to be `authenticated`,
            // because a refresh with no grant stored enters from `unauthenticated` and a
            // step-up from `stepUpRequired`; a flight's own state is never somewhere to return to.
            let current = await flow.states.current
            let priorState: SessionState = current == .refreshing ? .authenticated : current
            await flow.setState(.refreshing)
            return try await performRefresh(startedIn: startedIn, priorState: priorState)
        }
        flight = task
        return try await task.value
    }

    private func endFlight() {
        flight = nil
    }

    private func performRefresh(startedIn: UInt64, priorState: SessionState) async throws -> TokenResponse {
        do {
            // Step 1: the rotation slot. A key already in it is a process death between steps
            // 1 and 2 of a previous attempt: the token on disk has not changed since, so
            // replaying with it is correct rather than merely convenient.
            let idempotencyKey: String
            if let pending = try await credentialStore.pendingRotation() {
                idempotencyKey = pending
            } else {
                guard let token = try await credentialStore.refreshToken() else { throw Self.noGrantStored() }
                idempotencyKey = Self.idempotencyKey(for: token)
                try await credentialStore.savePendingRotation(idempotencyKey)
            }
            let origin = DpopOrigin.of(URL(string: try await flow.metadata().tokenEndpoint) ?? URL(string: "https://invalid")!)
            let budget = retryPolicy.newBudget(clock: clock)
            let tokenClient = self.tokenClient
            let store = self.credentialStore
            let issued = try await budget.execute(origin: origin) {
                // A fresh read per attempt: the token is read for the duration of one request.
                guard let token = try await store.refreshToken() else { throw Self.noGrantStored() }
                return try await tokenClient.refresh(refreshToken: token, idempotencyKey: idempotencyKey)
            }
            // An ID token on a refresh is validated with the login rules minus the nonce, and
            // against the claims it replaces (OpenID Connect Core 12.2), before persistence.
            var refreshedClaims: IdTokenClaims?
            if let validator = idTokenValidator, let idToken = issued.idToken {
                refreshedClaims = try await validator.validate(idToken: idToken, expectedNonce: nil, accessToken: issued.accessToken, maxAge: nil, previous: await restoreClaims(), serverTime: issued.serverDate)
            }
            warnIfNoExpiry(issued)
            // The grant was wiped while this request was out (a logout, another caller's
            // invalid_grant): the answer is for a session that has ended.
            if epoch != startedIn { throw WipedMeanwhile() }
            if let refreshedClaims { claims = refreshedClaims }
            // Step 2: persisted before returning to any caller. A response omitting the
            // refresh token leaves the stored value alone rather than overwriting it.
            if let rotated = issued.refreshToken { try await credentialStore.save(refreshToken: rotated, rawIdToken: issued.idToken) }
            // Step 3: the slot is cleared only now.
            try await credentialStore.savePendingRotation(nil)
            cachedAccessToken = Cached(response: issued, receivedAt: clock.now())
            await flow.setState(.authenticated)
            return issued
        } catch is WipedMeanwhile {
            throw OAuthError.reauthenticate(.grantRejected)
        } catch let error as OAuthError {
            switch error {
            case .recoverable(let cause):
                // The grant is intact: a locked store is `locked`, anything else reverts.
                await publishIfCurrent(startedIn, cause == .unlockRequired ? .locked : priorState == .unauthenticated ? .unauthenticated : .authenticated)
            case .reauthenticate:
                // `grantRejected` and `credentialsInvalidated`: the grant itself is gone, so the
                // same teardown `logout()` runs, once.
                if epoch == startedIn { await wipe() }
            default:
                // A configuration fault or a defect: not a reason to sign the user out.
                await publishIfCurrent(startedIn, priorState == .unauthenticated ? .unauthenticated : .authenticated)
            }
            throw error
        } catch {
            await publishIfCurrent(startedIn, priorState == .unauthenticated ? .unauthenticated : .authenticated)
            throw error
        }
    }

    private struct WipedMeanwhile: Error {}

    private func publishIfCurrent(_ startedIn: UInt64, _ state: SessionState) async {
        if epoch == startedIn { await flow.setState(state) }
    }

    private static func noGrantStored() -> OAuthError { .reauthenticate(.grantRejected) }

    // MARK: - Logout

    /// Revokes (when asked and advertised), ends the provider's session through the browser
    /// (when asked and advertised), and wipes everything credential-shaped unconditionally.
    package func logout(revoke: Bool = true, endSession: Bool = true) async -> LogoutOutcome {
        _ = await flow.states.current
        await flow.setState(.loggingOut)
        var serverSessionEnded = false
        var revoked = false
        if let flight { _ = try? await flight.value }
        if revoke { revoked = await revokeQuietly() }
        if endSession {
            var hint: String?
            do {
                if let inMemory = memorySession?.rawIdToken { hint = inMemory } else { hint = try await credentialStore.rawIdToken() }
            } catch {
                logger?.warn("logout: id_token_hint unavailable; ending the session without it")
            }
            serverSessionEnded = (try? await flow.endSession(idTokenHint: hint)) ?? false
        }
        await wipe()
        return LogoutOutcome(sessionEnded: serverSessionEnded, tokenRevoked: revoked)
    }

    private func revokeQuietly() async -> Bool {
        do {
            guard let token = try await credentialStore.refreshToken() else { return false }
            try await tokenClient.revoke(refreshToken: token)
            return true
        } catch {
            logger?.warn("logout: revocation failed; the grant dies at expiry instead")
            return false
        }
    }

    private func clearStoredGrant() async {
        epoch += 1
        cachedAccessToken = nil
        try? await credentialStore.clear()
        do { try await onCredentialsWiped() } catch {
            logger?.warn("login: teardown of the previous grant's key or nonce caches failed")
        }
    }

    private func warnIfNoExpiry(_ response: TokenResponse) {
        if response.expiresIn <= 0 && !warnedExpiresIn {
            warnedExpiresIn = true
            logger?.warn("the token response carries no expires_in; the access token is treated as of unknown lifetime and refreshed on a 401")
        }
    }

    private func wipe() async {
        epoch += 1
        cachedAccessToken = nil
        memorySession = nil
        claims = nil
        claimsRestored = false
        try? await credentialStore.clear()
        do { try await onCredentialsWiped() } catch {
            logger?.warn("logout: teardown of the DPoP key or nonce caches failed")
        }
        await flow.completeLogout()
    }

    /// The key of the rotation being spent: derived from the token, so a replay after a
    /// dropped response names the same rotation. Not reversible, never logged.
    static func idempotencyKey(for refreshToken: String) -> String {
        Base64Url.encode(Data(SHA256.hash(data: Data(refreshToken.utf8))))
    }

    private static let offlineAccess = "offline_access"
}

/// How long a token response is usable for after it arrives: its lifetime less a skew of at
/// most 30 s or a tenth of the lifetime. A lifetime of zero is `expires_in` absent (unknown,
/// not expired): the token is used until a 401 says otherwise.
enum RefreshSkew {
    static func usableFor(response: TokenResponse) -> TimeInterval {
        let lifetime = TimeInterval(response.expiresIn)
        if lifetime <= 0 { return .infinity }
        return lifetime - min(30, lifetime / 10)
    }
}
