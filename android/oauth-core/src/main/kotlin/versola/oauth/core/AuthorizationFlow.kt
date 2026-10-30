package versola.oauth.core

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.emitAll
import kotlinx.coroutines.flow.flow
import java.net.URLEncoder
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull

/**
 * The browser leg of the state machine: `Unauthenticated → Authorizing → (validated grant)`,
 * with the cancel and process-death transitions of `spec/state-machine.md`.
 *
 * Lives in `core`, not in the facade, for two reasons: the orchestration *is* the protocol —
 * the order of the redirect checks and the moment the pending request is persisted are both
 * normative — and keeping it here lets the request, the verifier and the configuration
 * factory stay internal instead of being published so a wiring layer can reach them.
 *
 * Nothing here knows about Versola. Every URL it uses comes from discovery.
 */
@VersolaInternalApi
public class AuthorizationFlow(
    public val configuration: VersolaConfiguration,
    private val discovery: DiscoveryService,
    private val pendingStore: PendingAuthorizationStore,
    private val browser: BrowserAuthorizationSession,
    /**
     * The key `dpop_jkt` commits to, or null for a session that is not key-bound. A key
     * handed in alongside [TokenBinding.Bearer] is ignored rather than quietly overriding the
     * integrator's choice.
     */
    private val dpopKey: DpopKeyBinding? = null,
    /**
     * Declared after [dpopKey] so the default cannot be the one pairing this class rejects.
     * The policy default — DPoP unless the integrator refuses it — belongs to `configure()`;
     * what this class defaults to is whatever the key it was handed can actually deliver.
     */
    private val tokenBinding: TokenBinding =
        if (dpopKey == null) TokenBinding.Bearer else TokenBinding.Dpop(),
    private val clock: () -> Long = System::currentTimeMillis,
    /**
     * Whether a refresh grant is durably stored — [CredentialStore.hasGrant], wired in by
     * whoever owns both halves. A probe rather than the store itself: restoration needs one
     * bit, and `hasGrant` is the one question a store answers without its key, so a cold
     * start does not become an unlock prompt under [UnlockPolicy.OnAppUnlock].
     *
     * Defaulting to "no grant" keeps a flow constructed on its own — the browser leg in
     * isolation, and every test of it — behaving exactly as before. Leaving it at the default
     * underneath a [SessionCoordinator] would make a returning session read as signed out on
     * every cold start, so that pairing is refused rather than defaulted; see
     * [restoresStoredGrant].
     */
    private val hasStoredGrant: suspend () -> Boolean = NO_STORED_GRANT,
    /**
     * Builds the request the browser opens when it is not the plain PKCE request this class
     * builds itself: a facade's back channel that pushes the request and keeps the verifier.
     * Absent, the request is built here and sent to the authorization endpoint directly.
     * What the starter needs at the exchange travels in [PendingAuthorizationRequest.extension].
     */
    private val starter: AuthorizationStarter? = null,
) {

    /**
     * Whether [hasStoredGrant] was actually supplied. Read by [SessionCoordinator], which
     * cannot restore `Authenticated` without it and refuses the pairing at construction
     * rather than signing users out one cold start at a time.
     */
    internal val restoresStoredGrant: Boolean get() = hasStoredGrant !== NO_STORED_GRANT

    init {
        // A key-bound session without a key would send no `dpop_jkt` and skip the
        // `requireHardware` check with it, so an app that asked to be bound to hardware would
        // authorize unbound and never be told. Wiring, not deployment: it fails here rather
        // than at the first authorization.
        if (tokenBinding is TokenBinding.Dpop && dpopKey == null) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.InvalidConfiguration(
                    "TokenBinding.Dpop needs a DpopKeyBinding; pass one or select TokenBinding.Bearer",
                ),
            )
        }
    }

    private val state = MutableStateFlow<SessionState>(SessionState.Unauthenticated)

    /**
     * Called once, when the restore finds a pending request to resume (`Authorizing`): a
     * cold-started process's cue to finish the sign-in its redirect answers. A hook rather than
     * a check at construction because the restore can fail (see [ensureRestored]) and succeed on
     * a later read, and the resume belongs to that moment.
     */
    public var onRestoredAuthorizing: (() -> Unit)? = null

    private val restoreLock = Mutex()
    private var restored = false
    private var expiredOnRestore = false

    /**
     * The observable state machine.
     *
     * A cold flow whose first emission is the *restored* state, not a default: an app killed
     * while the browser was open must observe [SessionState.Authorizing] on cold start and
     * never [SessionState.Unauthenticated] (scenario 12). A hot `StateFlow` would have to
     * publish a placeholder before the store had been read.
     */
    public val sessionState: Flow<SessionState> = flow {
        try {
            ensureRestored()
        } catch (e: VersolaError.Recoverable) {
            // The store could not be read yet; the state says `Locked` and the next read tries
            // again. A collector is not handed a storage error.
        }
        emitAll(state)
    }

    /** The provider's metadata, fetched once and cached on disk across restarts and logout. */
    public suspend fun metadata(): ProviderMetadata = discovery.metadata()

    /**
     * `Authorizing` → `Authenticated`: called once the session coordinator (#8) holds a
     * durably stored refresh token, never before. Wipes the pending request — [authorize] and
     * [resumePendingAuthorization] deliberately leave it in place until this point, so a
     * process killed between redeeming the code and persisting the refresh token still finds
     * an `Authorizing` session to resume rather than one that looks like it never started.
     *
     * Internal because redeeming a grant and persisting its result is not this class's job —
     * this class stops at a validated [AuthorizationGrant] — but hosting the state every leg
     * of the machine shares is, so the coordinator's transition has to land here rather than
     * on a flow of its own.
     */
    internal suspend fun completeLogin() {
        pendingStore.clear()
        state.value = SessionState.Authenticated
    }

    /**
     * The exchange failed, or the caller walked away from it: the code is spent and the slot
     * can never complete, so it goes, and the session settles where the authorization was
     * entered from rather than on a state the grant on disk contradicts.
     */
    internal suspend fun abandonLogin() {
        pendingStore.clear()
        state.value = settledState()
    }

    /** [authorize] bodies running, whether or not they have reached the browser yet. */
    private val browserLegs = AtomicInteger()

    /** Validated redirects whose code exchange the coordinator has not finished; see [exchangeFinished]. */
    private val exchanges = AtomicInteger()

    /**
     * Whether this process is carrying an authorization out: a `login()` or `stepUp()` has its
     * browser up (or being opened) with a live awaiter, or a validated redirect's code exchange has
     * not finished. This, not the `Authorizing` state, is what makes a second `login()` wrong. A
     * pending request that nobody awaits (a cancelled caller left it for a resume the app never asked
     * for, or a cold start restored it) is only a leftover, and a resume that merely waits for its
     * redirect is pre-empted: [authorize] supersedes both. The state alone cannot tell these apart,
     * and refusing on it blocked `login()` for the leftover's ten minutes
     * (`spec/oauth-sdk-api.md` section 5).
     */
    public val authorizationInFlight: Boolean get() = browserLegs.get() > 0 || exchanges.get() > 0

    /**
     * The coordinator's `finishLogin` has ended, however it ended: the exchange is no longer in flight.
     * A counter rather than a flag so two flows over one store cannot clear each other's; clamped so
     * a caller that used [authorize] without a coordinator (a test) cannot drive it negative.
     */
    internal fun exchangeFinished() {
        exchanges.updateAndGet { maxOf(0, it - 1) }
    }

    private inline fun <T> leg(block: () -> T): T {
        browserLegs.incrementAndGet()
        try {
            return block()
        } finally {
            browserLegs.decrementAndGet()
        }
    }

    /**
     * Completed to end a [resumePendingAuthorization] that is only *waiting* for a redirect, so that
     * whatever needs the authorize lock next does not wait out the request's ten minutes behind it:
     * [authorize] (a `login()` or `stepUp()`), [endSession] and the local wipe of a sign-out all do
     * this first. Null when no resume is running. Process-wide, like [AUTHORIZE_LOCK] it belongs to.
     * Written under [AUTHORIZE_LOCK] by the resume, read
     * without it by the pre-empting caller, which is the point: it must reach a resume that holds the
     * lock.
     *
     * A resume is not "an authorization carried out": nothing is open in this process that a new
     * `login()` could disturb, only a request that may or may not still be answered. A browser that is
     * up for a live `login()` is, and so is a code exchange; neither is pre-empted (see
     * [authorizationInFlight]). If the resume's redirect has already arrived it is past the wait and
     * its exchange is counted, so the signal finds nobody to wake.
     */
    private fun preemptResume() {
        resumeSignal?.complete(Unit)
    }

    /**
     * Waits for [block], the resume's wait for a redirect, until [signal] says a newer operation
     * wants the lock: then [block] is cancelled and the answer is null. The caller's own
     * cancellation is not this: it propagates.
     */
    private suspend fun awaitUnlessPreempted(signal: CompletableDeferred<Unit>, block: suspend () -> BrowserOutcome): BrowserOutcome? =
        coroutineScope {
            val work = async { block() }
            select {
                work.onAwait { it }
                signal.onAwait {
                    work.cancel()
                    null
                }
            }
        }

    /** `Authenticated → StepUpRequired`; nothing else moves, the grant is intact. */
    internal fun enterStepUpRequired() {
        if (state.value == SessionState.Authenticated) state.value = SessionState.StepUpRequired
    }

    /**
     * Where a browser leg that did not end in a grant leaves the session: `Authenticated`
     * while a grant is stored — a step-up or a re-authorization the user cancelled is not a
     * sign-out, and UI bound to the state must not show one over a live session —
     * otherwise `Unauthenticated`.
     */
    private suspend fun settledState(): SessionState =
        if (hasStoredGrant()) SessionState.Authenticated else SessionState.Unauthenticated

    /**
     * `LoggingOut → Unauthenticated`: the local half of `logout()` (#10), which is the half
     * that is not best-effort. Wipes the pending request — a `login()` abandoned mid-browser
     * must not survive a sign-out and resume into the next user's session — and settles
     * `Unauthenticated` whatever the server leg did.
     */
    internal suspend fun completeLogout() {
        // A resume still waiting for a redirect would otherwise redeem it into the session this
        // sign-out just ended: it is told to stand down before its request is wiped.
        preemptResume()
        pendingStore.clear()
        state.value = SessionState.Unauthenticated
    }

    /**
     * The server leg of `logout()`: auth's `end_session_endpoint` in the system browser, with
     * `id_token_hint` so the session ends without a confirmation page and
     * `post_logout_redirect_uri` so the browser comes back once it has.
     *
     * Returns whether the server acknowledged — the redirect came back carrying the `state`
     * that was sent. False covers everything else: the user dismissed the page, the provider
     * advertises no `end_session_endpoint`, the redirect carried the wrong `state`. None of
     * those is raised, because `spec/state-machine.md` makes only the local teardown
     * unconditional and the caller wipes regardless; what the browser did is reported, not
     * enforced.
     *
     * Under [AUTHORIZE_LOCK] for the same reason [authorize] is: the browser and the redirect
     * channel are one per process, and a `login()` racing a `logout()` for them is the bug,
     * not a case to support.
     */
    public suspend fun endSession(idTokenHint: String?): Boolean {
        // The sign-out's browser needs the lock a waiting resume holds for up to ten minutes.
        preemptResume()
        return endSessionUnderLock(idTokenHint)
    }

    private suspend fun endSessionUnderLock(idTokenHint: String?): Boolean = AUTHORIZE_LOCK.withLock {
        ensureRestored()
        val endpoint = discovery.metadata().endSessionEndpoint
        if (endpoint.isNullOrBlank()) return@withLock false
        // The user is about to be sent to it, with the ID token as `id_token_hint`.
        requireSecureEndpoint("end_session_endpoint", endpoint)
        val postLogoutRedirectUri = configuration.postLogoutRedirectUri?.value
        val expectedState = SecureTokens.generate(SecureRandom())
        val uri = endSessionUri(endpoint, idTokenHint, configuration.clientId, postLogoutRedirectUri, expectedState)

        val outcome = try {
            // Never ephemeral: the point is to end the session the shared browser holds.
            // The user's time in the browser is not the SDK's retrying: see [outsideRetryBudget].
            outsideRetryBudget { browser.authorize(uri, BrowserSessionOptions(redirectUri = postLogoutRedirectUri)) }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            // `NoBrowserAvailable`, or the browser failing to launch: the server session
            // outlives this logout, which is exactly what the return value says.
            return@withLock false
        }
        when (outcome) {
            is BrowserOutcome.UserCancelled -> false
            is BrowserOutcome.Redirect -> {
                val state = AuthorizationResponseValidator.stateOf(outcome.uri)
                state != null && SecureTokens.constantTimeEquals(expectedState, state)
            }
        }
    }

    /**
     * OpenID Connect RP-Initiated Logout §2: `id_token_hint`, `client_id`, `post_logout_redirect_uri`
     * when configured, and `state`. `state` goes whether or not a redirect URI does:
     * it costs nothing and is what lets the redirect be told apart from a stale one.
     */
    private fun endSessionUri(
        endpoint: String,
        idTokenHint: String?,
        clientId: String,
        postLogoutRedirectUri: String?,
        state: String,
    ): String {
        val parameters = buildList {
            idTokenHint?.let { add("id_token_hint" to it) }
            // RP-Initiated Logout §2: with no usable `id_token_hint` (an expired one is ignored, a
            // session with none has none) it is what tells the provider which client is asking, and
            // some validate `post_logout_redirect_uri` against it.
            add("client_id" to clientId)
            postLogoutRedirectUri?.let { add("post_logout_redirect_uri" to it) }
            add("state" to state)
        }
        val query = parameters.joinToString("&") { (name, value) -> "${encode(name)}=${encode(value)}" }
        val separator = if (endpoint.contains('?')) "&" else "?"
        return endpoint + separator + query
    }

    private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8").replace("+", "%20")

    /**
     * Pushes a state the session coordinator (#8) owns — `Refreshing`, `Locked`, or a return
     * to `Authenticated`/`Unauthenticated` once a refresh resolves. This class performs none
     * of that itself; it only hosts the [MutableStateFlow] [sessionState] reads from, so the
     * coordinator's transitions land on the same stream an app already observes.
     */
    internal fun setState(next: SessionState) {
        state.value = next
    }

    /**
     * Opens the system browser, waits for the redirect, and validates it.
     *
     * The pending request is persisted **before** the browser opens — the app can be killed
     * between the two, and on Android that is not a rare case.
     *
     * A slot left behind by a cancelled caller is **superseded**, not protected: the app is
     * asking for a new authorization and cannot be made to wait out the old slot's ten
     * minutes, and the tab behind it may never redirect at all. The abandoned tab can still
     * redirect, so its `state` is remembered and that redirect is discarded rather than
     * allowed to fail this call as a mismatch.
     */
    public suspend fun authorize(
        scopes: Set<String>,
        acrValues: List<String> = emptyList(),
        maxAge: Long? = null,
        parameters: AuthorizationParameters = AuthorizationParameters(),
        /** `spec/oauth-sdk-api.md` section 6: a browser without the user's shared state. */
        ephemeralBrowser: Boolean = false,
    ): AuthorizationGrant {
        // A resume that is only waiting for a redirect gives way: its request is the leftover this
        // call supersedes below. Before the lock, because the resume is holding it.
        preemptResume()
        return AUTHORIZE_LOCK.withLock {
            leg { authorizeUnderLock(scopes, acrValues, maxAge, parameters, ephemeralBrowser) }
        }
    }

    private suspend fun authorizeUnderLock(
        scopes: Set<String>,
        acrValues: List<String>,
        maxAge: Long?,
        parameters: AuthorizationParameters,
        ephemeralBrowser: Boolean,
    ): AuthorizationGrant {
        ensureRestored()
        val metadata = discovery.metadata()
        // `code_challenge_methods_supported` present without S256 is a provider this SDK cannot
        // talk to (it sends S256 and nothing else); absent, it is unknown and S256 is sent
        // (`spec/oauth-sdk-api.md` section 6, `spec/providers.md`).
        if (metadata.codeChallengeMethodsSupported.isNotEmpty() && "S256" !in metadata.codeChallengeMethodsSupported) {
            throw VersolaError.Configuration(VersolaError.Configuration.Detail.ProviderUnsupported("S256"))
        }

        val request = AuthorizationRequest.create(
            configuration = configuration,
            scopes = scopes,
            acrValues = acrValues,
            maxAge = maxAge,
            dpopJkt = dpopJkt(metadata),
            parameters = parameters,
        )
        val (pending, uri) = if (starter == null) {
            request.toPending(clock()) to request.toUri(metadata.authorizationEndpoint)
        } else {
            starter.start(request, metadata, clock()).let { it.pending to it.browserUri }
        }
        // A request still in the slot is a leftover nobody awaits (else this call would not be here,
        // the lock being held for as long as one is awaited): superseded, and its `state` remembered
        // so that a redirect its tab still delivers is stepped over rather than failing this login.
        pendingStore.load()?.let { rememberAbandoned(it.state) }
        pendingStore.save(pending)
        state.value = SessionState.Authorizing

        val browserOptions = BrowserSessionOptions(ephemeral = ephemeralBrowser, redirectUri = configuration.redirectUri.value)
        val outcome = try {
            belongingTo(pending, outsideRetryBudget { browser.authorize(uri, browserOptions) })
        } catch (e: CancellationException) {
            // The *caller* was cancelled, not the authorization. The browser may already be
            // in the foreground and its redirect may still arrive, so the slot and the
            // `Authorizing` state are left exactly as a process death would leave them and
            // `resumePendingAuthorization()` can still finish the flow.
            //
            // Cancellation before the launch intent actually fired leaves a slot nothing
            // will ever answer, which expires by itself within ten minutes. That is the safe
            // direction to be wrong in: a stale slot costs one expiry, while wiping a live
            // one loses an authorization the user has already completed.
            rememberAbandoned(pending.state)
            throw e
        } catch (e: Exception) {
            // Launching or awaiting the browser failed outright (notably
            // `NoBrowserAvailable`, before any browser ever opened). Nothing is pending, so
            // the request and the `Authorizing` state must not survive: a later cold start
            // would otherwise look resumable and wait forever for a redirect that can never
            // arrive.
            pendingStore.clear()
            state.value = settledState()
            throw e
        }
        return complete(outcome, pending, metadata)
    }

    /**
     * Finishes an authorization that outlived the process that started it.
     *
     * Returns null when nothing is pending. Throws `Recoverable(PendingRequestExpired)` when
     * the restored request is older than ten minutes — an authorization code would not have
     * outlived that either.
     *
     * This is the resumption half of the cancel distinction: a *system* cancel leaves a
     * pending request with no live caller, which is exactly what this call is for. A *user*
     * cancel wipes the request, so there is nothing here to resume.
     */
    public suspend fun resumePendingAuthorization(): AuthorizationGrant? = AUTHORIZE_LOCK.withLock {
        val signal = CompletableDeferred<Unit>()
        resumeSignal = signal
        try {
            resumeUnderLock(signal)
        } finally {
            resumeSignal = null
        }
    }

    private suspend fun resumeUnderLock(signal: CompletableDeferred<Unit>): AuthorizationGrant? {
        ensureRestored()
        val pending = pendingStore.load()
            // Restoring already discarded it, and "expired" is not "nothing was pending":
            // the caller asked to resume a flow that existed and can no longer be finished.
            ?: if (expiredOnRestore) {
                expiredOnRestore = false
                throw VersolaError.Recoverable(VersolaError.Recoverable.Cause.PendingRequestExpired)
            } else {
                return null
            }
        if (pending.isExpired(clock())) {
            pendingStore.clear()
            state.value = settledState()
            throw VersolaError.Recoverable(VersolaError.Recoverable.Cause.PendingRequestExpired)
        }
        state.value = SessionState.Authorizing
        // Bounded by what is left of the request's ten minutes: the redirect it waits for may
        // never come — a code spent by a login killed mid-exchange, a tab the user closed
        // before the process died — and an unbounded wait here holds the authorize lock, and
        // with it every later `login()`, for as long as the app lives.
        val remaining = PendingAuthorizationRequest.MAX_AGE_MILLIS - (clock() - pending.createdAtEpochMillis)
        var preempted = signal.isCompleted
        val outcome = if (preempted) null else withTimeoutOrNull(remaining) {
            awaitUnlessPreempted(signal) { belongingTo(pending, outsideRetryBudget { browser.awaitPendingRedirect() }) }
                .also { if (it == null) preempted = true }
        }
        if (preempted) {
            // A newer operation (a login, a sign-out) wants the lock. This request is its leftover:
            // its tab may yet redirect, so its `state` is remembered, and the slot is left to whoever
            // took over (a login's `save` replaces it, a sign-out's wipe clears it).
            rememberAbandoned(pending.state)
            return null
        }
        val answered = outcome
            ?: run {
                pendingStore.clear()
                state.value = settledState()
                throw VersolaError.Recoverable(VersolaError.Recoverable.Cause.PendingRequestExpired)
            }
        return complete(answered, pending, discovery.metadata())
    }

    /**
     * Consumes redirects until one answers [pending].
     *
     * A tab abandoned by a cancelled caller can redirect after this call has already drained
     * whatever was buffered. That redirect carries a `state` this process issued itself, so
     * failing on it would lose a live authorization to a tab the user forgot about. Each
     * abandoned `state` is discarded exactly once, which is also what bounds this loop;
     * everything else — an unknown `state` included — still reaches the validator.
     */
    private suspend fun belongingTo(
        pending: PendingAuthorizationRequest,
        first: BrowserOutcome,
    ): BrowserOutcome {
        var outcome = first
        while (isAbandoned(outcome, pending)) {
            outcome = outsideRetryBudget { browser.awaitPendingRedirect() }
        }
        return outcome
    }

    private fun isAbandoned(outcome: BrowserOutcome, pending: PendingAuthorizationRequest): Boolean {
        val redirect = outcome as? BrowserOutcome.Redirect ?: return false
        val state = AuthorizationResponseValidator.stateOf(redirect.uri) ?: return false
        return state != pending.state && forgetAbandoned(state)
    }

    private suspend fun complete(
        outcome: BrowserOutcome,
        pending: PendingAuthorizationRequest,
        metadata: ProviderMetadata,
    ): AuthorizationGrant {
        // Being answered is what stops this request being anyone's leftover, whichever way
        // it ends: a resumed one is no longer abandoned, and a rejected one never will be.
        forgetAbandoned(pending.state)
        return when (outcome) {
            is BrowserOutcome.UserCancelled -> {
                pendingStore.clear()
                state.value = settledState()
                throw VersolaError.Recoverable(VersolaError.Recoverable.Cause.UserCancelled)
            }

            is BrowserOutcome.Redirect -> try {
                AuthorizationResponseValidator.validate(
                    redirect = outcome.uri,
                    pending = pending,
                    // The issuer the provider announces, not the configured one: the configured
                    // value has lost a trailing slash the provider's `iss` keeps (RFC 9207 section
                    // 2.4 compares the strings as they are).
                    issuer = metadata.issuer,
                    issParameterSupported = metadata.authorizationResponseIssParameterSupported,
                ).also {
                    // From here to the coordinator's `finishLogin` ending, the code is being redeemed.
                    exchanges.incrementAndGet()
                }
                // Deliberately still Authorizing, and the pending request deliberately still
                // stored: the machine reaches Authenticated only once a refresh token is
                // durably held, and the slot is wiped only after that (#8).
            } catch (e: VersolaError) {
                // A rejected response is unsafe to continue from, whichever way it was
                // rejected.
                pendingStore.clear()
                state.value = settledState()
                throw e
            }
        }
    }

    /**
     * The thumbprint to commit to, and the point at which `requireHardware` is enforced
     * against the deployment: before the browser opens, so an app that cannot be served finds
     * out at the first `authorize()` rather than at the first API call (scenario 07).
     *
     * A deployment that does not advertise DPoP gets no `dpop_jkt`. Sending one anyway would
     * bind a code the token endpoint will redeem without a proof.
     */
    private suspend fun dpopJkt(metadata: ProviderMetadata): String? {
        val binding = tokenBinding as? TokenBinding.Dpop ?: return null
        // A starter that binds the key on a call of its own (the edge flow's /native/start)
        // sets `dpop_jkt` from the proof it verified: a thumbprint named here would be a claim
        // it cannot verify, so the parameter is left to it. Any other starter pushes the
        // request as built, `dpop_jkt` and the hardware check included.
        if (starter?.bindsDpopKeyItself == true) return null
        if (!metadata.supportsDpop) {
            if (binding.requireHardware) {
                throw VersolaError.Configuration(
                    VersolaError.Configuration.Detail.HardwareBindingUnavailable(
                        "the provider does not advertise dpop_signing_alg_values_supported",
                    ),
                )
            }
            return null
        }
        // Non-null under `Dpop` by construction; see `init`.
        return checkNotNull(dpopKey).jkt()
    }

    private suspend fun ensureRestored() {
        if (restored) return
        restoreLock.withLock {
            if (restored) return
            // The grant is read before the pending request, and asked without the key. A pending
            // slot that is out of reach (a locked key, a keystore fault) has not said there is
            // nothing in it, so with no grant to decide the state it must not be read as
            // `Unauthenticated`: the state is `Locked`, the operation that asked fails with the
            // storage error, and nothing is remembered (`restored` stays false), so the next call
            // reads again. The slot is never discarded on its account. With a grant the slot is
            // only residue and the state does not depend on it. Cancellation is not a
            // `Recoverable` and passes through.
            val granted = hasStoredGrant()
            if (granted) {
                // With a grant the slot is only residue — a login killed between persisting the
                // token and clearing it, its code already redeemed — and the state does not depend
                // on it, so it is cleared on every cold start **unread** (`spec/state-machine.md`,
                // the same rule as iOS): nothing is decrypted that nothing needs, and an unreadable
                // slot cannot hide behind not being read. A slot that cannot be cleared yet fails
                // the restore the way an unreadable one does without a grant: `Locked`, the storage
                // error to the operation that asked, nothing remembered, so the next call retries.
                //
                // The cost is a re-authorization started *over* a live session (a step-up, an
                // account switch) and then killed mid-browser: it is resolved in favour of the
                // session that already exists rather than resumed, since what is on disk cannot
                // tell it from a login whose code was already redeemed.
                try {
                    pendingStore.clear()
                } catch (e: VersolaError.Recoverable) {
                    state.value = SessionState.Locked
                    throw e
                }
                state.value = SessionState.Authenticated
                restored = true
                return
            }
            val pending = try {
                pendingStore.load()
            } catch (e: VersolaError.Recoverable) {
                state.value = SessionState.Locked
                throw e
            }
            state.value = when {
                pending == null -> SessionState.Unauthenticated
                pending.isExpired(clock()) -> {
                    pendingStore.clear()
                    expiredOnRestore = true
                    SessionState.Unauthenticated
                }
                else -> SessionState.Authorizing
            }
            restored = true
            if (state.value == SessionState.Authorizing) onRestoredAuthorizing?.invoke()
        }
    }

    private companion object {
        /**
         * Process-wide, not per instance, because everything it protects is process-wide: the
         * default [PendingAuthorizationStore] is one file under `noBackupFilesDir`, and the
         * redirect arrives through a single `RedirectDispatcher` fed by one exported
         * activity. Two `Versola.configure()` results therefore contend for the same slot and
         * the same channel, and an instance-scoped lock would leave them free to overwrite
         * each other's pending request and consume each other's redirect.
         *
         * Serializing across instances costs nothing real: the resource underneath is the
         * foreground browser, and a device has one of those. Two authorizations genuinely in
         * flight at once is not a case worth supporting — it is the bug.
         */
        private val AUTHORIZE_LOCK = Mutex()

        @Volatile
        private var resumeSignal: CompletableDeferred<Unit>? = null

        /**
         * `state` values of authorizations whose caller was cancelled while their tab was
         * open — the redirects a later call may have to step over. Process-wide and guarded
         * by [AUTHORIZE_LOCK], for the same reason the lock itself is: the tabs and the
         * dispatcher they redirect into are not per instance either.
         *
         * Bounded, because an app that cancels repeatedly without ever redirecting would
         * otherwise grow this without end. Eight is far more open tabs than a user has, and
         * dropping the oldest only restores the old behaviour for it: a mismatch.
         */
        /** The absent-probe sentinel; identity is what [restoresStoredGrant] compares. */
        private val NO_STORED_GRANT: suspend () -> Boolean = { false }

        private val ABANDONED_STATES = LinkedHashSet<String>()
        private const val MAX_ABANDONED_STATES = 8

        private fun rememberAbandoned(state: String) {
            ABANDONED_STATES += state
            while (ABANDONED_STATES.size > MAX_ABANDONED_STATES) {
                ABANDONED_STATES.remove(ABANDONED_STATES.first())
            }
        }

        private fun forgetAbandoned(state: String): Boolean = ABANDONED_STATES.remove(state)
    }
}
