package kz.versola.sdk.core

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.emitAll
import kotlinx.coroutines.flow.flow
import java.net.URLEncoder
import java.security.SecureRandom
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

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
     * Present under [BackChannel.Edge]: the authorization request is pushed through edge and
     * the browser opens on a `request_uri`, with PKCE and `state` edge's rather than this
     * class's. Absent, the request is built here and sent to auth directly.
     */
    private val nativeStarter: NativeAuthorizationStarter? = null,
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
        if (nativeStarter != null) {
            // Every native endpoint demands a proof, so there is no bearer variant of this
            // flow to fall back to; and the server registers an edge-fronted native client
            // with https redirect URIs only, so anything else fails at /par rather than here.
            if (tokenBinding !is TokenBinding.Dpop) {
                throw VersolaError.Configuration(
                    VersolaError.Configuration.Detail.InvalidConfiguration(
                        "BackChannel.Edge needs TokenBinding.Dpop: edge's native endpoints accept no bearer presentation",
                    ),
                )
            }
            if (configuration.redirectUri.kind != RedirectUriKind.AppLink) {
                throw VersolaError.Configuration(
                    VersolaError.Configuration.Detail.InvalidConfiguration(
                        "BackChannel.Edge needs an https App Link redirectUri: " +
                            "an edge-fronted native client is registered with https redirect URIs only",
                    ),
                )
            }
        }
    }

    private val state = MutableStateFlow<SessionState>(SessionState.Unauthenticated)
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
        ensureRestored()
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
     * `LoggingOut → Unauthenticated`: the local half of `logout()` (#10), which is the half
     * that is not best-effort. Wipes the pending request — a `login()` abandoned mid-browser
     * must not survive a sign-out and resume into the next user's session — and settles
     * `Unauthenticated` whatever the server leg did.
     */
    internal suspend fun completeLogout() {
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
    public suspend fun endSession(idTokenHint: String?): Boolean = AUTHORIZE_LOCK.withLock {
        ensureRestored()
        val endpoint = discovery.metadata().endSessionEndpoint
        if (endpoint.isNullOrBlank()) return@withLock false
        val postLogoutRedirectUri = configuration.postLogoutRedirectUri?.value
        val expectedState = SecureTokens.generate(SecureRandom())
        val uri = endSessionUri(endpoint, idTokenHint, postLogoutRedirectUri, expectedState)

        val outcome = try {
            browser.authorize(uri)
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
     * OpenID Connect RP-Initiated Logout §2. `state` goes whether or not a redirect URI does:
     * it costs nothing and is what lets the redirect be told apart from a stale one.
     */
    private fun endSessionUri(
        endpoint: String,
        idTokenHint: String?,
        postLogoutRedirectUri: String?,
        state: String,
    ): String {
        val parameters = buildList {
            idTokenHint?.let { add("id_token_hint" to it) }
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
    ): AuthorizationGrant = AUTHORIZE_LOCK.withLock {
        ensureRestored()
        val metadata = discovery.metadata()

        val request = AuthorizationRequest.create(
            configuration = configuration,
            scopes = scopes,
            acrValues = acrValues,
            maxAge = maxAge,
            dpopJkt = dpopJkt(metadata),
        )
        val (pending, uri) = if (nativeStarter == null) {
            request.toPending(clock()) to request.toUri(metadata.authorizationEndpoint)
        } else {
            startViaEdge(nativeStarter, request, metadata)
        }
        pendingStore.save(pending)
        state.value = SessionState.Authorizing

        val outcome = try {
            belongingTo(pending, browser.authorize(uri))
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
            state.value = SessionState.Unauthenticated
            throw e
        }
        complete(outcome, pending, metadata)
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
        ensureRestored()
        val pending = pendingStore.load()
            // Restoring already discarded it, and "expired" is not "nothing was pending":
            // the caller asked to resume a flow that existed and can no longer be finished.
            ?: if (expiredOnRestore) {
                expiredOnRestore = false
                throw VersolaError.Recoverable(VersolaError.Recoverable.Cause.PendingRequestExpired)
            } else {
                return@withLock null
            }
        if (pending.isExpired(clock())) {
            pendingStore.clear()
            state.value = SessionState.Unauthenticated
            throw VersolaError.Recoverable(VersolaError.Recoverable.Cause.PendingRequestExpired)
        }
        state.value = SessionState.Authorizing
        val outcome = belongingTo(pending, browser.awaitPendingRedirect())
        complete(outcome, pending, discovery.metadata())
    }

    /**
     * [BackChannel.Edge]'s version of building the request: edge builds it, pushes it to
     * `/par` with `dpop_jkt` set from the proof on this very call, and hands back the
     * `request_uri` to open, the `state` to expect and the blob that stands in for the
     * verifier. What is persisted before the browser opens is therefore edge's `state` and
     * blob rather than a verifier of this class's own — the same moment, the same reason.
     *
     * The authorization endpoint comes from discovery, not from edge's answer: the issuer is
     * the one URL the integrator vouched for, and `request_uri` is bound to the client at
     * auth either way. Edge's `authorization_endpoint` is informational for this SDK.
     */
    private suspend fun startViaEdge(
        starter: NativeAuthorizationStarter,
        request: AuthorizationRequest,
        metadata: ProviderMetadata,
    ): Pair<PendingAuthorizationRequest, String> {
        val started = starter.start(
            NativeStartRequest(
                redirectUri = configuration.redirectUri.value,
                scopes = request.scopes,
                nonce = request.nonce,
                acrValues = request.acrValues,
                maxAge = request.maxAge,
            ),
        )
        val pending = PendingAuthorizationRequest(
            state = started.state,
            nonce = request.nonce,
            codeVerifier = "",
            scopes = request.scopes.toList(),
            redirectUri = configuration.redirectUri.value,
            acrValues = request.acrValues,
            maxAge = request.maxAge,
            createdAtEpochMillis = clock(),
            blob = started.blob,
            tokenEndpoint = started.tokenEndpoint,
            revocationEndpoint = started.revocationEndpoint,
        )
        val query = "client_id=${encode(configuration.clientId)}&request_uri=${encode(started.requestUri)}"
        val separator = if (metadata.authorizationEndpoint.contains('?')) "&" else "?"
        return pending to (metadata.authorizationEndpoint + separator + query)
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
            outcome = browser.awaitPendingRedirect()
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
                state.value = SessionState.Unauthenticated
                throw VersolaError.Recoverable(VersolaError.Recoverable.Cause.UserCancelled)
            }

            is BrowserOutcome.Redirect -> try {
                AuthorizationResponseValidator.validate(
                    redirect = outcome.uri,
                    pending = pending,
                    issuer = configuration.issuer,
                    issParameterSupported = metadata.authorizationResponseIssParameterSupported,
                )
                // Deliberately still Authorizing, and the pending request deliberately still
                // stored: the machine reaches Authenticated only once a refresh token is
                // durably held, and the slot is wiped only after that (#8).
            } catch (e: VersolaError) {
                // A rejected response is unsafe to continue from, whichever way it was
                // rejected.
                pendingStore.clear()
                state.value = SessionState.Unauthenticated
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
        // Through edge the thumbprint reaches /par from the proof on /native/start, which is
        // the only place it can come from: a `dpop_jkt` the device named itself would be a
        // claim edge cannot verify, and edge sets the parameter from what it did verify.
        if (nativeStarter != null) return null
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
            val pending = pendingStore.load()
            state.value = when {
                // A stored grant outranks whatever the browser leg left behind, and it is
                // read first for both directions of that: without it a returning session
                // reports `Unauthenticated` on every cold start until something happens to
                // call refresh, and with a pending request beside it the request is the
                // residue of a login killed between persisting the token and clearing the
                // slot — a code already redeemed, so the redirect it still waits for can no
                // longer be spent and resuming it would only fail as `invalid_grant`.
                //
                // The cost is a re-authorization started *over* a live session (a step-up,
                // an account switch) and then killed mid-browser: it is resolved in favour
                // of the session that already exists rather than resumed. Nothing is lost
                // that the next 401 does not ask for again, and the alternative — believing
                // a pending request that may or may not have been redeemed — has no way to
                // tell the two apart.
                hasStoredGrant() -> {
                    if (pending != null) pendingStore.clear()
                    SessionState.Authenticated
                }
                pending == null -> SessionState.Unauthenticated
                pending.isExpired(clock()) -> {
                    pendingStore.clear()
                    expiredOnRestore = true
                    SessionState.Unauthenticated
                }
                else -> SessionState.Authorizing
            }
            restored = true
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
