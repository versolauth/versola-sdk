package kz.versola.sdk.core

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.emitAll
import kotlinx.coroutines.flow.flow
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
) {

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
    private val restoreLock = Mutex()
    // There is exactly one persisted slot and one process-wide redirect channel behind
    // `browser`; a second concurrent `authorize()` would keep its own local `pending` while
    // both share that slot and channel, so a redirect can wake the wrong caller and its
    // state-mismatch cleanup can clear the other flow's slot. Serializing here is what makes
    // "one slot" true rather than just persisted that way.
    private val authorizeLock = Mutex()
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
     * Opens the system browser, waits for the redirect, and validates it.
     *
     * The pending request is persisted **before** the browser opens — the app can be killed
     * between the two, and on Android that is not a rare case.
     */
    public suspend fun authorize(
        scopes: Set<String>,
        acrValues: List<String> = emptyList(),
        maxAge: Long? = null,
    ): AuthorizationGrant = authorizeLock.withLock {
        ensureRestored()
        val metadata = discovery.metadata()

        val request = AuthorizationRequest.create(
            configuration = configuration,
            scopes = scopes,
            acrValues = acrValues,
            maxAge = maxAge,
            dpopJkt = dpopJkt(metadata),
        )
        val pending = request.toPending(clock())
        pendingStore.save(pending)
        state.value = SessionState.Authorizing

        // If launching or awaiting the browser throws (notably `NoBrowserAvailable`, before
        // any browser ever opened), the pending request and the `Authorizing` state must not
        // survive it: nothing is actually pending, so a later cold start must not look
        // resumable and wait forever for a redirect that can never arrive.
        val outcome = try {
            browser.authorize(request.toUri(metadata.authorizationEndpoint))
        } catch (e: Exception) {
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
    public suspend fun resumePendingAuthorization(): AuthorizationGrant? = authorizeLock.withLock {
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
        complete(browser.awaitPendingRedirect(), pending, discovery.metadata())
    }

    private suspend fun complete(
        outcome: BrowserOutcome,
        pending: PendingAuthorizationRequest,
        metadata: ProviderMetadata,
    ): AuthorizationGrant = when (outcome) {
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
            // stored: the machine reaches Authenticated only once a refresh token is durably
            // held, and the slot is wiped only after that (#8).
        } catch (e: VersolaError) {
            // A rejected response is unsafe to continue from, whichever way it was rejected.
            pendingStore.clear()
            state.value = SessionState.Unauthenticated
            throw e
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
}
