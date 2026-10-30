package versola.oauth.core

import java.net.URI
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * The other half of the grant [AuthorizationFlow] deliberately stops short of, and all of
 * `spec/state-machine.md`'s `Authenticated → Refreshing → Authenticated` corner: single-flight
 * refresh, the rotation slot, the idempotency key, and what `invalid_grant` wipes.
 *
 * `login()` and `refresh()` are the only two places a refresh token is ever spent, and both
 * follow the same three-step persistence ordering from `spec/state-machine.md`:
 *
 * 1. what is about to be spent is recorded — the pending authorization request before the
 *    browser opens ([AuthorizationFlow.authorize]), the rotation slot before a refresh request
 *    is sent (below).
 * 2. the response is durably stored before anything downstream sees it.
 * 3. the step-1 record is cleared only now — [AuthorizationFlow.completeLogin] for a login,
 *    [CredentialStore.savePendingRotation] with `null` for a refresh.
 *
 * A process killed between 1 and 2 recovers by finding step 1's record still in place on next
 * start and either resuming (login: `resumePendingAuthorization()`) or replaying with the same
 * idempotency key (refresh: below). Under DPoP the server renews the refresh token in place
 * (`BoundRenewal`), so a refresh response carries no new value to store and step 3 clears a
 * slot that was never load-bearing to begin with — inert, not skipped, which is why this class
 * runs the same three steps unconditionally rather than branching on the token binding.
 */
@VersolaInternalApi
public class SessionCoordinator(
    private val flow: AuthorizationFlow,
    private val tokenClient: TokenClient,
    private val credentialStore: CredentialStore,
    private val retryPolicy: RetryPolicy = RetryPolicy.Default,
    /**
     * Monotonic milliseconds, used only to measure how long ago a token response arrived.
     *
     * Deliberately not the wall clock and not the skew-corrected clock [DpopProofSource]
     * stamps `iat` from: those answer what time the *server* thinks it is, whereas the only
     * question here is how much of a lifetime has elapsed since a response was received. A
     * user or an NTP step moving the wall clock mid-session must not make a live token look
     * expired, nor an expired one look live.
     */
    private val elapsedMillis: () -> Long = { System.nanoTime() / NANOS_PER_MILLI },
    /**
     * What the platform wiring tears down alongside the stored grant: both nonce caches and
     * the DPoP key, which live in `:dpop` and are out of this module's reach. Run on every
     * path that ends the grant — `logout()` and `invalid_grant` alike, which
     * `spec/state-machine.md` treats identically ("the DPoP key follows the logout rule").
     * Never fails the caller: a teardown that throws would leave a sign-out half done.
     */
    private val onCredentialsWiped: suspend () -> Unit = {},
    private val logger: VersolaLogger? = null,
    /**
     * Whether a session needs a refresh token. [RefreshTokenPolicy.Required] is the Versola
     * facade's model: `offline_access` is asked for and an exchange without a refresh token
     * is refused. [RefreshTokenPolicy.Optional] is the generic facade's
     * (`spec/oauth-sdk-api.md` section 8): nothing is added to the scopes, and a session
     * without a refresh token lives in memory until its access token expires, then ends in
     * `Reauthenticate(SessionExpired)`.
     */
    private val refreshTokens: RefreshTokenPolicy = RefreshTokenPolicy.Required,
    /**
     * Validates the ID token before the token response is persisted, at login and on a
     * refresh that returns one (OpenID Connect Core 3.1.3.7, 12.2). Null validates nothing,
     * which is the Versola facade's state until architecture review F5 is scheduled; the
     * generic facade always passes one.
     */
    private val idTokenValidator: IdTokenValidator? = null,
    /**
     * The clock the retry budget and the cooldown measure on: monotonic milliseconds, injected
     * so a test of a `Retry-After` needs no sleeps. Separate from [elapsedMillis], whose tests
     * pin token ages and must not move with a retry delay.
     */
    retryClock: () -> Long = { System.nanoTime() / NANOS_PER_MILLI },
    retryRandom: kotlin.random.Random = kotlin.random.Random.Default,
    /**
     * Whether a refresh may be repeated after a failure that may have come after the provider
     * acted. The Versola facade sends an `Idempotency-Key`, so a repeat resolves to the same
     * rotation and this is true. The generic facade sends none, and a repeat of a refresh the
     * provider already rotated is a replay that a rotating provider can answer by revoking the
     * family; with false, a refresh is repeated only when it provably was not processed
     * ([ServerFault.wasNotProcessed]) and every other failure is surfaced after one request.
     */
    private val repeatsRefreshAfterAmbiguousFailure: Boolean = true,
) : AccessTokenSource {

    /**
     * Where each application-visible operation gets its retry budget and where a server's
     * `Retry-After` is remembered (`spec/retry-policy.md`). The facades wrap the calls the
     * coordinator does not own (`metadata()`, `userInfo()`) in it too, so that one call is one
     * budget whichever class serves it.
     */
    public val retryScope: RetryScope = RetryScope(retryPolicy, retryClock, retryRandom)

    init {
        // Without the probe, restoration knows only what the browser leg left behind, and a
        // returning session — a stored grant, no pending request — reads as `Unauthenticated`
        // on every cold start until something happens to call [refresh]. Wiring, not
        // deployment: it fails here rather than by signing users out one launch at a time.
        if (!flow.restoresStoredGrant) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.InvalidConfiguration(
                    "AuthorizationFlow needs hasStoredGrant = credentialStore::hasGrant to restore a stored session",
                ),
            )
        }
    }

    /**
     * The state machine of `spec/state-machine.md`, observable — the full seven states, not
     * only the browser leg [AuthorizationFlow] hosts on its own. Delegates to
     * [AuthorizationFlow.sessionState] because that is where the underlying stream lives;
     * every state this class enters or leaves lands there too, through [AuthorizationFlow]'s
     * internal setters.
     *
     * Its first emission is the restored state, which is `Authenticated` whenever a grant is
     * durably stored — [AuthorizationFlow] asks the probe this class's constructor insists on.
     */
    public val sessionState: Flow<SessionState> get() = flow.sessionState

    @Volatile
    private var cachedAccessToken: Cached? = null

    /** A response and the instant it arrived, which is the half [TokenResponse] cannot carry. */
    private class Cached(val response: TokenResponse, val receivedAt: Long)

    /**
     * The claims of the last validated ID token, memory only (`spec/state-machine.md`'s
     * persistence table): null until a login validated one, after a sign-out, and always
     * when no [idTokenValidator] was given.
     */
    @Volatile
    public var claims: IdTokenClaims? = null
        private set

    /**
     * A session the provider issued no refresh token for, held in memory only. Its ID token
     * is kept here for `id_token_hint`, since nothing was written to the credential store.
     */
    @Volatile
    private var memorySession: MemorySession? = null

    private class MemorySession(val rawIdToken: String?)

    /** Whether the stored ID token was already read back into [claims] since the last wipe. */
    @Volatile
    private var claimsRestored = false

    @Volatile
    private var warnedOfflineAccess = false

    @Volatile
    private var warnedExpiresIn = false

    /**
     * [claims] as the stored ID token has them, read once after a cold start: a stored grant
     * restores `Authenticated` with nothing in memory, and the app's claims and the refresh
     * check against the previous `sub` need what the token carried. Nothing is re-verified;
     * the token was validated before it was stored. No-op without a validator.
     */
    public suspend fun restoreClaims(): IdTokenClaims? {
        claims?.let { return it }
        if (idTokenValidator == null || claimsRestored) return null
        val stored = try {
            memorySession?.rawIdToken ?: credentialStore.rawIdToken()
        } catch (e: VersolaError) {
            return null
        }
        claimsRestored = true
        return stored?.let(IdTokenClaims::ofStored)?.also { claims = it }
    }

    /**
     * The most recently issued token response, held in memory only — `spec/state-machine.md`'s
     * persistence summary keeps the access token out of storage because it is short-lived and
     * re-derivable. Null before this process's first [login] or [refresh].
     *
     * Returned whatever its age: this is the escape hatch, and [accessToken] is the method
     * that applies the refresh skew.
     */
    public fun currentAccessToken(): TokenResponse? = cachedAccessToken?.response

    /**
     * A token fit to send: the cached one while it is outside its refresh skew, otherwise the
     * result of a [refresh].
     *
     * The expiry policy lives here rather than in the HTTP client because the issuance instant
     * does — [TokenResponse] carries a lifetime and no start, and the cache this class owns is
     * the only thing that knows when the response arrived. Every caller that would otherwise
     * have to re-derive that would have to be given the instant anyway.
     *
     * `Refreshing` is entered only when a refresh actually happens, so a call served from the
     * cache publishes no state transition at all.
     */
    override suspend fun accessToken(): AccessToken {
        if (claims == null && !claimsRestored) restoreClaims()
        val cached = cachedAccessToken
        if (cached != null && cached.usable()) return AccessToken.of(cached.response)
        if (memorySession != null) expireMemorySession()
        // The entry judged stale is handed on, because this verdict was taken outside the
        // lock that hands out a refresh flight and a flight can finish before this caller
        // reaches it. [refresh] re-reads the cache under that lock and rotates only if it
        // still holds what was rejected here.
        return AccessToken.of(retryScope.operation { refresh(rejected = cached, onlyIfStale = true) })
    }

    /** Outside its refresh skew, measured on the monotonic clock this class was given. */
    private fun Cached.usable(): Boolean =
        elapsedMillis() - receivedAt < RefreshSkew.usableForMillis(response)

    override suspend fun renewAccessToken(): AccessToken {
        if (memorySession != null) expireMemorySession()
        return AccessToken.of(retryScope.operation { refresh() })
    }

    /**
     * `Authenticated → Unauthenticated` for a session without a refresh token: there is
     * nothing to spend, so no token request is made and the browser is not opened; the ID
     * token and claims go, the state says so, and the caller is told to sign in again.
     */
    private suspend fun expireMemorySession(): Nothing {
        refreshFlight.mutex.withLock {
            epoch.incrementAndGet()
            cachedAccessToken = null
            memorySession = null
            claims = null
        }
        logger?.warn("the access token expired and the provider issued no refresh token; the session is over")
        flow.completeLogout()
        throw VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.SessionExpired)
    }

    /**
     * `login()`, in full: [AuthorizationFlow.authorize] for the browser leg, the code exchange,
     * persistence, and only then [AuthorizationFlow.completeLogin] — which is what moves the
     * pending request's ten-minute survival past the exchange and into `Authenticated`.
     *
     * A failed exchange abandons the login: the redirect has been consumed and the code is
     * spent, so the pending request can never complete and keeping it would only make the
     * next cold start report `Authorizing` for a flow nothing can resume
     * (`spec/state-machine.md`, `Authorizing → Unauthenticated: authorization error`). The
     * session settles where it was entered from — `Authenticated` when a grant is still
     * stored, as during a step-up, otherwise `Unauthenticated`.
     */
    public suspend fun login(
        scopes: Set<String>,
        acrValues: List<String> = emptyList(),
        maxAge: Long? = null,
        parameters: AuthorizationParameters = AuthorizationParameters(),
        ephemeralBrowser: Boolean = false,
    ): TokenResponse = retryScope.operation {
        // OpenID Connect Core §11: a refresh token is issued for a grant that asked for
        // `offline_access`, and auth issues none otherwise. This session model has nothing to
        // hold without one — the exchange below refuses a response that omits it — so the
        // scope is asked for here rather than left for every integrator to discover from a
        // failed first login. An app that listed it already is unchanged.
        // Under [RefreshTokenPolicy.Optional] the scopes go as given: the generic facade adds
        // nothing silently, and `providers.md` says per provider which scope buys a refresh
        // token.
        val requested = if (refreshTokens == RefreshTokenPolicy.Required) scopes + OFFLINE_ACCESS else scopes
        if (refreshTokens == RefreshTokenPolicy.Optional && OFFLINE_ACCESS !in requested && !warnedOfflineAccess &&
            OFFLINE_ACCESS in flow.metadata().scopesSupported
        ) {
            // Said once (`spec/oauth-sdk-api.md` section 15): the provider offers refresh
            // tokens for the asking, and the integrator did not ask. "May": Keycloak advertises
            // the scope and issues a refresh token without it (scenario 31 against it), so the
            // scope's absence is not proof of the token's.
            warnedOfflineAccess = true
            logger?.warn("the provider advertises offline_access and the configured scopes omit it; a refresh token may not be issued")
        }
        // A cooldown from an earlier Retry-After refuses here, before the browser opens, where a
        // refusal costs the user nothing; the code exchange after the browser is never refused (a
        // code just obtained is not wasted on a request the provider was going to answer anyway).
        retryScope.refuseIfCoolingDown(tokenOrigin())
        val grant = flow.authorize(requested, acrValues, maxAge, parameters, ephemeralBrowser)
        finishLogin(grant, maxAge)
    }

    /**
     * The tail of a login: everything after the redirect has been validated. Shared by [login] and
     * [resumePendingLogin] so that a sign-in finished in a cold-started process passes through
     * exactly the checks and the persistence order of one finished in the process that began it.
     */
    private suspend fun finishLogin(grant: AuthorizationGrant, maxAge: Long?): TokenResponse {
        // One attempt, with no retry budget around it. An authorization code is single-use
        // and the token endpoint offers no idempotency for `authorization_code` —
        // `Idempotency-Key` is honoured for the refresh family alone (`OAuthTokenService`) —
        // so a retry after a dropped response replays a spent code, which RFC 6749 §4.1.2
        // lets the server answer by revoking what it already issued from it. That trades a
        // login that failed for one that cannot be completed, and `spec/retry-policy.md`
        // draws exactly this line: a retry is only safe on an operation the server can
        // recognise as a repeat. The nonce and clock-skew retries inside [TokenClient] still
        // apply — those answer a challenge raised before the code was redeemed.
        var validated: IdTokenClaims? = null
        // What the provider issued, once it has: a login that fails after this point discards it
        // unused, and the refresh token is then a live credential nobody holds (below).
        var exchanged: TokenResponse? = null
        val response = try {
            val issued = try {
                tokenClient.exchange(grant)
            } catch (e: VersolaError.Recoverable) {
                // Made once, so it never reaches the budget; a Retry-After on it still quiets the origin.
                retryScope.endedBy(tokenOrigin(), e)
                throw e
            }
            exchanged = issued
            // Validated before anything is persisted (`spec/oauth-sdk-api.md` section 11): a
            // rejected ID token leaves the store exactly as it was.
            validated = idTokenValidator?.let { validator ->
                val idToken = issued.idToken ?: throw VersolaError.Configuration(
                    VersolaError.Configuration.Detail.IdTokenRejected(IdTokenRejection.Malformed),
                )
                validator.validate(
                    idToken,
                    expectedNonce = grant.nonce,
                    accessToken = issued.accessToken,
                    maxAge = maxAge,
                    previous = null,
                    serverTime = issued.serverDate,
                )
            }
            warnIfNoExpiry(issued)
            if (refreshTokens == RefreshTokenPolicy.Required) {
                // RFC 6749 permits an authorization_code response to omit refresh_token, but
                // this session model has nothing to hold on to without one: there is no prior
                // value to fall back to the way a refresh's BoundRenewal omission falls back
                // to the one already on disk.
                issued.refreshToken ?: throw VersolaError.Configuration(
                    VersolaError.Configuration.Detail.TokenResponseMalformed("refresh_token is missing"),
                )
            }
            issued
        } catch (e: CancellationException) {
            // The caller walked away mid-exchange. The response may still arrive at a server
            // that has already spent the code, and nothing here can collect it: the slot is
            // abandoned for the same reason a failure abandons it.
            withContext(NonCancellable) { flow.abandonLogin() }
            throw e
        } catch (e: Throwable) {
            flow.abandonLogin()
            // The provider already issued these and the SDK is throwing them away: an ID token that
            // failed validation, or could not be checked, leaves a refresh token that is valid at the
            // server for as long as it lives and that no device holds. Best effort and after the
            // state has settled; whatever it does, the caller gets the error that ended the login.
            exchanged?.let { revokeDiscarded(it) }
            throw e
        }
        val refreshToken = response.refreshToken
        if (refreshToken != null) {
            credentialStore.save(refreshToken, response.idToken)
            memorySession = null
        } else {
            // A grant already on disk belongs to the session this login replaces; left there
            // it would come back on the next cold start as the previous user (the ghost
            // session `spec/state-machine.md` forbids). The same teardown a wipe does.
            if (credentialStore.hasGrant()) withContext(NonCancellable) { clearStoredGrant() }
            // Nothing to persist: the session is the access token in memory and ends with it
            // (`spec/state-machine.md`, "no refresh token"). Said once, here, so an
            // integrator who expected a refresh token learns it from the log rather than
            // from a sign-in an hour later.
            memorySession = MemorySession(response.idToken)
            logger?.warn("the provider issued no refresh token; the session lasts as long as the access token")
        }
        claimsRestored = true
        claims = validated
        flow.completeLogin()
        cachedAccessToken = Cached(response, elapsedMillis())
        return response
    }

    /**
     * Finishes a login that outlived the process that started it (scenario 12): the redirect is
     * awaited ([AuthorizationFlow.resumePendingAuthorization]), validated against the restored
     * request, and the code exchanged, the ID token validated, the grant persisted and
     * `Authenticated` published by the same steps [login] ends with. `max_age` comes from the
     * restored request, since no caller is left to supply it.
     *
     * Returns null when nothing was pending. Throws what [login] throws, and
     * `Recoverable(PendingRequestExpired)` when the request is older than ten minutes or its
     * redirect does not arrive within what is left of them.
     */
    public suspend fun resumePendingLogin(): TokenResponse? = retryScope.operation {
        val grant = flow.resumePendingAuthorization() ?: return@operation null
        finishLogin(grant, grant.maxAge)
    }

    /**
     * `Authenticated → StepUpRequired`: edge refused a call for want of a stronger
     * authentication context. The grant is intact, so nothing is wiped; the state says why
     * the next thing the app does is a `stepUp()` rather than a `login()`.
     */
    override fun stepUpRequired() {
        flow.enterStepUpRequired()
    }

    /**
     * Keyed on [credentialStore]'s own identity rather than owned by this instance:
     * `DataStoreCredentialStore` already promises one instance per file per process, but
     * nothing stops two [SessionCoordinator]s from being built on top of that one shared
     * instance, and an instance-local [Mutex] cannot see across them. Two such coordinators
     * would each run their own single-flight coalescing correctly in isolation, and still
     * both win at once against the one store underneath — which is exactly the concurrent,
     * unrelated refresh requests this class exists to rule out.
     *
     * A `WeakHashMap` so a [CredentialStore] that outlives no coordinator does not pin an
     * entry here forever; `synchronized` rather than a suspend-friendly lock because every
     * access is one non-suspending map lookup.
     */
    private class RefreshFlight {
        val mutex = Mutex()

        /**
         * The refresh in flight, or null. Its value is the outcome every other caller takes
         * delivery of — or null for a flight whose winner was cancelled, which is not an
         * outcome and must not be delivered as one; see [refresh].
         */
        var pending: CompletableDeferred<Result<TokenResponse>?>? = null
    }

    private companion object {
        private val flightsByStore = java.util.WeakHashMap<CredentialStore, RefreshFlight>()

        private fun flightFor(store: CredentialStore): RefreshFlight =
            synchronized(flightsByStore) { flightsByStore.getOrPut(store) { RefreshFlight() } }
    }

    private val refreshFlight = flightFor(credentialStore)

    /**
     * Exactly one `refresh_token` request per call that finds none already in flight; every
     * concurrent caller that arrives while one is running coalesces onto its result instead of
     * starting its own.
     *
     * This is not an optimisation. Under bearer rotation, concurrent refreshes are concurrent
     * replays of the same refresh token, and `detectReplay` on the server revokes the whole
     * family — the user is silently logged out by a client that made five API calls at once.
     *
     * Coalescing rather than a plain `Mutex.withLock`: a lock alone would still let five
     * queued callers make five *sequential* requests, one per caller, each spending a refresh
     * token the previous one already rotated. What is shared here is the *result* of the one
     * request that was actually needed, not merely serialised access to making one each.
     *
     * Cancellation belongs to the caller that was cancelled and to nobody else: the callers
     * waiting on an abandoned flight take it over rather than fail with it.
     */
    public suspend fun refresh(): TokenResponse = retryScope.operation { refresh(rejected = null, onlyIfStale = false) }

    /**
     * [refresh], with the staleness verdict of [accessToken] re-taken under the lock that
     * hands out the flight.
     *
     * Reading the cache and acquiring a flight are two steps, and between them a flight
     * started by somebody else can resolve and retire itself: its successor then finds no
     * flight to join, wins one of its own, and rotates a grant that was refreshed moments
     * earlier. Under bearer binding that second rotation is a second replay of one refresh
     * token, which `detectReplay` answers by revoking the family. So a conditional caller
     * re-reads the cache here, where no flight can be created or retired concurrently, and
     * rotates only if what it rejected is still what the cache holds.
     */
    private suspend fun refresh(rejected: Cached?, onlyIfStale: Boolean): TokenResponse {
        while (true) {
            // The lazy restore — disk I/O, and so a point a caller can be cancelled at —
            // happens *before* a flight exists. A flight handed out and then abandoned here
            // would never be retired, and every later refresh in the process would wait on
            // it. Also captures the state `Refreshing` is entered from: not assumed to be
            // `Authenticated`, because `refresh()` with no grant stored enters from
            // `Unauthenticated`, and a step-up enters from `StepUpRequired`.
            //
            // Read outside the mutex, so it can catch another flight's `Refreshing` just
            // before that flight retires: restoring *that* on a cancellation would leave the
            // session in `Refreshing` with no flight to ever resolve it. A flight's own
            // state is never somewhere to return to, so it settles on `Authenticated`.
            val priorState = flow.sessionState.first().takeUnless { it == SessionState.Refreshing }
                ?: SessionState.Authenticated
            var winner = false
            val flight = refreshFlight.mutex.withLock {
                if (onlyIfStale) {
                    val current = cachedAccessToken
                    if (current != null && current !== rejected && current.usable()) {
                        return current.response
                    }
                }
                refreshFlight.pending ?: CompletableDeferred<Result<TokenResponse>?>().also {
                    refreshFlight.pending = it
                    winner = true
                }
            }
            if (!winner) {
                // Null is the winner's caller having walked away rather than the refresh
                // having resolved. That says nothing about this caller, whose own job is
                // still very much alive, so it takes the flight over instead of inheriting a
                // `CancellationException` raised in a coroutine it has nothing to do with —
                // which would cancel it too, and abandoning one request would fail every
                // concurrent refresh with it.
                //
                // Taking over is safe precisely because of the rotation slot: an abandoned
                // winner that had already sent its request left its idempotency key behind,
                // and the next winner replays with that key rather than deriving a new one.
                val outcome = flight.await() ?: continue
                return outcome.getOrThrow()
            }

            val startedIn = epoch.get()
            flow.setState(SessionState.Refreshing)

            val result = try {
                Result.success(performRefresh(startedIn))
            } catch (e: CancellationException) {
                withContext(NonCancellable) {
                    // `Refreshing` was pushed by this flight and nothing resolved it, so it
                    // would otherwise be the last state an app ever observes. Reverting to
                    // the state actually entered from — not a hardcoded `Authenticated` —
                    // costs a successor one extra transition and never publishes a session
                    // that was never there to begin with.
                    publishIfCurrent(startedIn, priorState)
                    endFlight(flight, null)
                }
                throw e
            } catch (e: Throwable) {
                Result.failure(e)
            }
            // Retired whatever happens to this job from here on: a flight left pending is
            // every later refresh in the process hanging on it.
            withContext(NonCancellable) { endFlight(flight, result) }
            return result.getOrThrow()
        }
    }

    /**
     * Moves every time the grant is wiped. A refresh that was in flight when `logout()` — or
     * an `invalid_grant` on another caller — wiped the grant must not persist its answer
     * afterwards: that would put the refresh token back on disk and publish `Authenticated`
     * over a session the app just watched end. Checked under the flight mutex, where the wipe
     * also moves it, so the two cannot interleave.
     */
    private val epoch = AtomicLong()

    /** Publishes [state] unless the grant was wiped since [startedIn]; the wipe's own state stands then. */
    private suspend fun publishIfCurrent(startedIn: Long, state: SessionState) {
        refreshFlight.mutex.withLock { if (epoch.get() == startedIn) flow.setState(state) }
    }

    /**
     * Retires [flight] before publishing [outcome], so a caller arriving between the two
     * starts a fresh one rather than joining a flight that has already finished. Null is an
     * abandoned flight, which its awaiters retry rather than adopt.
     */
    private suspend fun endFlight(
        flight: CompletableDeferred<Result<TokenResponse>?>,
        outcome: Result<TokenResponse>?,
    ) {
        refreshFlight.mutex.withLock { if (refreshFlight.pending === flight) refreshFlight.pending = null }
        flight.complete(outcome)
    }

    private suspend fun performRefresh(startedIn: Long): TokenResponse {
        val response = try {
            // Step 1. Recorded once, from one unwrap that spends nothing — hashing does not
            // take ownership of what it reads, so this unwrap is independent of the one(s)
            // below and leaves the stored token exactly as it was.
            //
            // A key already in the slot is a process death between steps 1 and 2 of a
            // previous attempt: the token on disk has not changed since that key was derived
            // from it (step 2 never ran), so replaying with it is correct rather than merely
            // convenient.
            val idempotencyKey = credentialStore.pendingRotation() ?: run {
                val key = credentialStore.useRefreshToken { idempotencyKeyFor(it) } ?: noGrantStored()
                credentialStore.savePendingRotation(key)
                key
            }
            val issued = retrying(
                tokenOrigin(),
                mayRepeat = if (repeatsRefreshAfterAmbiguousFailure) { _ -> true } else ServerFault::wasNotProcessed,
            ) {
                // A fresh unwrap per attempt, not one unwrap shared across retries:
                // `TokenClient.refresh` takes ownership of the bytes it is given and zeroes
                // them once the request body is formed, so a second attempt handed the same
                // (by then zeroed) array would spend nothing. `credentialStore.useRefreshToken`
                // re-unwraps the still-untouched ciphertext each time, which is also exactly
                // the "unwrapped for the duration of one token request and no longer" rule
                // `spec/state-machine.md`'s `Locked` section states for every other caller.
                credentialStore.useRefreshToken { tokenClient.refresh(it, idempotencyKey) } ?: noGrantStored()
            }
            // Step 2 comes before the ID token is judged, and for a reason the validator cannot
            // give: by now the provider has rotated, so the response's refresh token is the only
            // live one and the stored one is spent. Validating first would let a key set that
            // cannot be fetched, an unknown `kid` or a changed `sub` — or a caller cancelled
            // during that fetch — drop the new token on the floor, and the next refresh would
            // present the spent one: `invalid_grant`, a wipe, and on a provider that treats
            // reuse as theft a revoked family. A bad ID token costs the ID token, never the grant.
            val validator = idTokenValidator
            val rawIdToken = issued.idToken
            val validating = validator != null && rawIdToken != null
            // The raw ID token is stored only once it has been validated (what is on disk is
            // read back as claims without being re-verified, and replayed as `id_token_hint`),
            // so this write carries none and a copy of the token is held for the one that does.
            val rotated = issued.refreshToken
            val rotatedForIdToken = if (validating) rotated?.copyOf() else null
            try {
                withContext(NonCancellable) {
                    refreshFlight.mutex.withLock {
                        // The grant was wiped while this request was out — a `logout()`, or another
                        // caller's `invalid_grant`. The server's answer is for a session that has
                        // ended, and persisting it would resurrect the session; the wipe's state stands.
                        if (epoch.get() != startedIn) throw WipedMeanwhile()
                        // `BoundRenewal` echoes the same `refresh_token`, which is stored again as
                        // it was; a response omitting it leaves the stored value alone rather than
                        // overwriting it with an absence. Step 3 rides on the same write — see
                        // [CredentialStore.replaceRefreshToken] — and under DPoP clears a slot
                        // whose value never moved: inert, per the class doc, not skipped.
                        //
                        // Both inside this same try: a key that locks or is invalidated between the
                        // server answering and the write landing is exactly what the catches below
                        // already map to `Locked` or `Unauthenticated`, and leaving it outside would
                        // let that failure escape with `Refreshing` never resolved — the one state
                        // this class must never leave stuck. And under the flight mutex, so a wipe
                        // cannot slip between the check and the write.
                        if (rotated != null) {
                            credentialStore.replaceRefreshToken(rotated, rawIdToken.takeUnless { validator != null })
                        } else {
                            credentialStore.savePendingRotation(null)
                        }
                        if (!validating) {
                            cachedAccessToken = Cached(issued, elapsedMillis())
                            flow.setState(SessionState.Authenticated)
                        }
                    }
                }
                if (validating) {
                    // An ID token on a refresh response is validated with the login rules minus
                    // the nonce, and against the claims it replaces (OpenID Connect Core 12.2). A
                    // refusal is a `Configuration` fault handled below, a key set that cannot be
                    // fetched a `Recoverable` one; either way the grant — the rotated token just
                    // stored — stays, and nothing else from this response is kept: not the access
                    // token, which the same ID token vouches for, nor the ID token, nor its claims.
                    val refreshedClaims = checkNotNull(validator).validate(
                        checkNotNull(rawIdToken),
                        expectedNonce = null,
                        accessToken = issued.accessToken,
                        maxAge = null,
                        previous = restoreClaims(),
                        serverTime = issued.serverDate,
                    )
                    withContext(NonCancellable) {
                        refreshFlight.mutex.withLock {
                            if (epoch.get() != startedIn) throw WipedMeanwhile()
                            rotatedForIdToken?.let { credentialStore.save(it, rawIdToken) }
                            claims = refreshedClaims
                            cachedAccessToken = Cached(issued, elapsedMillis())
                            flow.setState(SessionState.Authenticated)
                        }
                    }
                }
            } finally {
                rotatedForIdToken?.fill(0)
            }
            warnIfNoExpiry(issued)
            issued
        } catch (e: WipedMeanwhile) {
            // Not a failure of the refresh and nothing to wipe: the caller that asked is told
            // the grant is gone, which is what it will find.
            throw VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.GrantRejected)
        } catch (e: CancellationException) {
            // Not an outcome of the refresh, and not this function's to settle: [refresh]
            // retires the abandoned flight and reverts the state where a successor can see
            // it, under `NonCancellable`, which nothing here can do from a cancelled job.
            throw e
        } catch (e: VersolaError.Recoverable) {
            // The grant is intact for everything this budget can throw: a network failure
            // exhausting its retries, a nonce loop, or the storage key's unlock window having
            // elapsed. Only the last of those is a state change rather than a reversion — the
            // grant is out of reach, not gone, so the session enters `Locked` instead of
            // settling back on `Authenticated`. The same is true whether the key locked
            // during the request or during step 2/3's own wrap: [CredentialKeyProvider] is
            // the same lock either way.
            publishIfCurrent(
                startedIn,
                if (e.reason is VersolaError.Recoverable.Cause.UnlockRequired) {
                    SessionState.Locked
                } else {
                    SessionState.Authenticated
                },
            )
            throw e
        } catch (e: VersolaError.Reauthenticate) {
            // `GrantRejected` (the token endpoint's invalid_grant) and `CredentialsInvalidated`
            // (the stored bytes no longer unwrap, from `useRefreshToken` or, here, from step
            // 2/3's own wrap) are the two ways the grant itself is gone rather than merely
            // unreachable — `spec/state-machine.md` wipes everything credential-shaped for
            // both (`Refreshing → Unauthenticated`, `Locked → Unauthenticated`), so both are
            // handled identically here regardless of which step raised it.
            // The same teardown `logout()` runs, DPoP key included: `spec/state-machine.md`'s
            // `Refreshing → Unauthenticated` names the key as following the logout rule.
            // Once, though: a wipe that already happened while this request was out is not
            // repeated on its account.
            withContext(NonCancellable) { if (epoch.get() == startedIn) wipe() }
            throw e
        } catch (e: Throwable) {
            // A `Configuration` fault or anything unforeseen: a deployment or SDK defect, not
            // a reason to sign the user out. The grant is left exactly as it was.
            publishIfCurrent(startedIn, SessionState.Authenticated)
            throw e
        }
        return response
    }

    /** Raised inside the persistence step when the grant was wiped during the request. */
    private class WipedMeanwhile : RuntimeException()

    /**
     * There was no refresh token to spend — `credentialStore.useRefreshToken` answered null,
     * which happens only when the session was already signed out in substance, whatever state
     * the caller last observed. Modelled as the same `Reauthenticate(GrantRejected)` the token
     * endpoint's own `invalid_grant` produces, so the one `catch` above wipes and settles
     * `Unauthenticated` for this case exactly as it does for that one.
     */
    private fun noGrantStored(): Nothing =
        throw VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.GrantRejected)

    /**
     * `Authenticated → LoggingOut → Unauthenticated` (#10, scenario 18), in the order
     * `spec/state-machine.md` fixes: revoke the refresh token, end the server session in the
     * browser, wipe. The first two are best effort and the third is not — reaching
     * `Unauthenticated` locally is unconditional, and happens even when this call is
     * cancelled or either server leg throws.
     *
     * The refresh token is revoked *before* the browser opens: a user who dismisses the
     * signed-out page has still had the grant killed at the server, which is the half of the
     * teardown that matters on a shared device.
     *
     * Returns whether auth acknowledged the end of its session, so an app that cares can tell
     * "signed out everywhere" from "signed out here". Most will not look.
     */
    public suspend fun logout(revoke: Boolean = true, endSession: Boolean = true): LogoutOutcome = retryScope.operation {
        flow.sessionState.first()
        flow.setState(SessionState.LoggingOut)
        var serverSessionEnded = false
        var revoked = false
        try {
            refreshFlight.mutex.withLock { refreshFlight.pending }?.let { flight -> runCatching { flight.await() } }
            if (revoke) revoked = revokeQuietly()
            if (endSession) {
                val hint = try {
                    memorySession?.rawIdToken ?: credentialStore.rawIdToken()
                } catch (e: VersolaError) {
                    logger?.warn("logout: id_token_hint unavailable (${e.message}); ending the session without it")
                    null
                }
                serverSessionEnded = flow.endSession(hint)
            }
        } finally {
            withContext(NonCancellable) { wipe() }
        }
        LogoutOutcome(sessionEnded = serverSessionEnded, tokenRevoked = revoked)
    }

    /**
     * RFC 7009 revocation of the refresh token of a response this session is not going to keep, so
     * that a login refused after the exchange does not leave a live grant at the provider. Revoking
     * the refresh token also ends the access tokens issued from the same grant (RFC 7009 section
     * 2.1: the server "SHOULD" invalidate them), which is why only the refresh token is sent; a
     * response with none has nothing the SDK can revoke and its access token dies at expiry.
     *
     * Never throws a [VersolaError] or anything else but the caller's cancellation: the login's
     * own failure is what the app must see. Repeated under the operation's budget, so an
     * unreachable provider costs what the login had left and no more.
     */
    private suspend fun revokeDiscarded(response: TokenResponse) {
        val token = response.refreshToken ?: return
        try {
            retrying(revocationOrigin()) { tokenClient.revoke(token.copyOf()) }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            logger?.warn("login: revoking the refresh token of the rejected response failed (${if (e is VersolaError) e.message else e.javaClass.simpleName}); it dies at expiry instead")
        } finally {
            token.fill(0)
        }
    }

    /** True when the provider took the revocation (RFC 7009: taken, not necessarily live). */
    private suspend fun revokeQuietly(): Boolean = try {
        // Repeated under the operation's budget (RFC 7009: revoking a revoked token succeeds), with a
        // fresh unwrap per attempt for the reason `performRefresh` gives.
        retrying(revocationOrigin()) { credentialStore.useRefreshToken { tokenClient.revoke(it) } } != null
    } catch (e: CancellationException) {
        throw e
    } catch (e: VersolaError) {
        logger?.warn("logout: revocation failed (${e.message}); the grant dies at expiry instead")
        false
    }

    /**
     * Everything credential-shaped goes, in one place, for both callers that end the grant.
     * Teardown of the pieces this module cannot see — nonce caches, the DPoP key — runs
     * through [onCredentialsWiped] and is not allowed to fail the sign-out: a Keystore that
     * refuses to delete a key is a warning, not a session that cannot end.
     */
    /**
     * The stored grant goes, with the key and nonce teardown, but the memory session a login
     * is establishing stays: the caller sets it right after. Under the flight mutex with the
     * epoch moved, so a refresh in flight for the old grant cannot persist its answer.
     */
    private suspend fun clearStoredGrant() {
        refreshFlight.mutex.withLock {
            epoch.incrementAndGet()
            cachedAccessToken = null
        }
        try {
            credentialStore.clear()
        } finally {
            try {
                onCredentialsWiped()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                logger?.warn("login: teardown of the previous grant's key or nonce caches failed: ${e.message}")
            }
        }
    }

    /** `spec/oauth-sdk-api.md` section 15: a response that does not say when its token dies, once. */
    private fun warnIfNoExpiry(response: TokenResponse) {
        if (response.expiresInSeconds <= 0 && !warnedExpiresIn) {
            warnedExpiresIn = true
            logger?.warn("the token response carries no expires_in; the access token is treated as of unknown lifetime and refreshed on a 401")
        }
    }

    private suspend fun wipe() {
        refreshFlight.mutex.withLock {
            epoch.incrementAndGet()
            cachedAccessToken = null
            memorySession = null
            claims = null
            claimsRestored = false
        }
        try {
            credentialStore.clear()
        } finally {
            try {
                onCredentialsWiped()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                logger?.warn("logout: teardown of the DPoP key or nonce caches failed: ${e.message}")
            }
            flow.completeLogout()
        }
    }

    /**
     * RFC 7638-shaped, not RFC 7638 itself: this hashes the refresh token being spent rather
     * than a JWK, but the reasoning is the same one [CodeVerifier.challengeS256] uses — a
     * deterministic digest of exactly the secret being consumed, so the same generation always
     * derives the same key and a dropped response's retry resolves to the same rotation
     * (`OAuthTokenService.findIdempotentRetry`) instead of reading as a replay.
     */
    private fun idempotencyKeyFor(refreshToken: ByteArray): String =
        Base64Url.encode(MessageDigest.getInstance("SHA-256").digest(refreshToken))

    private suspend fun tokenOrigin(): String =
        with(URI(flow.metadata().tokenEndpoint)) { "$scheme://$authority" }

    /**
     * The origin a revocation goes to: the revocation endpoint's, which a provider may serve from
     * another host than the token endpoint, so that a 429 from one never holds the other's origin.
     */
    private suspend fun revocationOrigin(): String =
        flow.metadata().revocationEndpoint?.let { with(URI(it)) { "$scheme://$authority" } } ?: tokenOrigin()
}

private const val NANOS_PER_MILLI = 1_000_000L

/** OpenID Connect Core §11. */
private const val OFFLINE_ACCESS = "offline_access"

/**
 * How long before its stated expiry a token is treated as due for refresh
 * (`spec/state-machine.md`).
 *
 * ```text
 * skew = min(30 s, expires_in / 10)
 * ```
 *
 * Proportional rather than a flat constant because `expires_in` is per-client configuration on
 * the server (`OAuthClientRecord.accessTokenTtl`, 3600 s in the bootstrap default) and nothing
 * stops a deployment from issuing twenty-second tokens. A flat 30 s — or AppAuth's 60 s —
 * marks such a token stale at the instant it is issued, and the session then refreshes before
 * every single call, which under bearer rotation is a rotation per call. The tenth is what
 * makes that unrepresentable at any lifetime: proactive refresh can never add more than one
 * token request per ten uses. The 30 s cap is the other end — an hour-long token refreshed six
 * minutes early buys nothing.
 */
internal object RefreshSkew {

    private const val MAX_SKEW_MILLIS = 30_000L
    private const val LIFETIME_FRACTION = 10

    /**
     * Milliseconds a response may be used for after it arrives.
     *
     * A lifetime of zero is `expires_in` absent from the response ([TokenResponse] defaults it)
     * — *unknown*, not *expired*. There is nothing to be early about, so the token is used
     * until a 401 says otherwise; a response that declines to say when its token dies is not
     * saying it is already dead. [Long.MAX_VALUE] rather than a flag because every caller's
     * question is "how long", and "forever" answers it without a second branch.
     *
     * A lifetime past what milliseconds can express takes the same answer, for the same
     * reason it is indistinguishable from one: a deployment claiming 300 million years is not
     * making a statement about expiry either, and the multiplication below would wrap into a
     * negative and expire the token immediately.
     */
    fun usableForMillis(response: TokenResponse): Long {
        val lifetime = response.expiresInSeconds
        if (lifetime <= 0 || lifetime > Long.MAX_VALUE / 1000) return Long.MAX_VALUE
        val lifetimeMillis = lifetime * 1000
        return lifetimeMillis - minOf(MAX_SKEW_MILLIS, lifetimeMillis / LIFETIME_FRACTION)
    }
}

/** Whether a session needs a refresh token; see [SessionCoordinator]'s constructor. */
public enum class RefreshTokenPolicy {
    /** `offline_access` is requested and an exchange without a refresh token is refused. */
    Required,

    /** Scopes go as given; a session without a refresh token lives as long as its access token. */
    Optional,
}

/**
 * What the server-side half of a sign-out achieved. The local wipe is unconditional and not
 * reported: `Unauthenticated` is published whatever these say (`spec/state-machine.md`).
 */
public class LogoutOutcome(
    /** The provider acknowledged RP-initiated logout: the browser came back with the `state` sent. */
    public val sessionEnded: Boolean,
    /** The provider took the refresh token's revocation. False when none is advertised or it failed. */
    public val tokenRevoked: Boolean,
)
