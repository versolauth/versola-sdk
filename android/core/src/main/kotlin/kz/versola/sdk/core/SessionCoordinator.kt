package kz.versola.sdk.core

import java.net.URI
import java.security.MessageDigest
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
public class SessionCoordinator(
    private val flow: AuthorizationFlow,
    private val tokenClient: TokenClient,
    private val credentialStore: CredentialStore,
    private val retryPolicy: RetryPolicy = RetryPolicy.Default,
) {

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
    private var cachedAccessToken: TokenResponse? = null

    /**
     * The most recently issued token response, held in memory only — `spec/state-machine.md`'s
     * persistence summary keeps the access token out of storage because it is short-lived and
     * re-derivable. Null before this process's first [login] or [refresh].
     *
     * Whether it is still usable is the caller's question, not this class's: [TokenResponse]
     * carries [TokenResponse.expiresInSeconds] and a clock does not belong inside a class whose
     * job is persistence ordering rather than expiry policy.
     */
    public fun currentAccessToken(): TokenResponse? = cachedAccessToken

    /**
     * `login()`, in full: [AuthorizationFlow.authorize] for the browser leg, the code exchange,
     * persistence, and only then [AuthorizationFlow.completeLogin] — which is what moves the
     * pending request's ten-minute survival past the exchange and into `Authenticated`.
     *
     * A failed exchange leaves the session exactly where [AuthorizationFlow.authorize] left
     * it — `Authorizing`, pending request intact — deliberately: the pending request's
     * lifetime belongs to that request, not to how the exchange that follows it turned out,
     * and this class does not shorten it on a failure that has nothing to do with the
     * authorization response itself.
     */
    public suspend fun login(
        scopes: Set<String>,
        acrValues: List<String> = emptyList(),
        maxAge: Long? = null,
    ): TokenResponse {
        val grant = flow.authorize(scopes, acrValues, maxAge)
        // One attempt, with no retry budget around it. An authorization code is single-use
        // and the token endpoint offers no idempotency for `authorization_code` —
        // `Idempotency-Key` is honoured for the refresh family alone (`OAuthTokenService`) —
        // so a retry after a dropped response replays a spent code, which RFC 6749 §4.1.2
        // lets the server answer by revoking what it already issued from it. That trades a
        // login that failed for one that cannot be completed, and `spec/retry-policy.md`
        // draws exactly this line: a retry is only safe on an operation the server can
        // recognise as a repeat. The nonce and clock-skew retries inside [TokenClient] still
        // apply — those answer a challenge raised before the code was redeemed.
        val response = tokenClient.exchange(grant)
        // RFC 6749 permits an authorization_code response to omit refresh_token, but the SDK's
        // whole session model has nothing to hold on to without one: there is no prior value
        // to fall back to the way a refresh's BoundRenewal omission falls back to the one
        // already on disk.
        val refreshToken = response.refreshToken ?: throw VersolaError.Configuration(
            VersolaError.Configuration.Detail.TokenResponseMalformed("refresh_token is missing"),
        )
        credentialStore.save(refreshToken, response.idToken)
        flow.completeLogin()
        cachedAccessToken = response
        return response
    }

    private val refreshMutex = Mutex()

    /**
     * The refresh in flight, or null. Its value is the outcome every other caller takes
     * delivery of — or null for a flight whose winner was cancelled, which is not an outcome
     * and must not be delivered as one; see [refresh].
     */
    private var pendingRefresh: CompletableDeferred<Result<TokenResponse>?>? = null

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
    public suspend fun refresh(): TokenResponse {
        while (true) {
            var winner = false
            val flight = refreshMutex.withLock {
                pendingRefresh ?: CompletableDeferred<Result<TokenResponse>?>().also {
                    pendingRefresh = it
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

            val result = try {
                Result.success(performRefresh())
            } catch (e: CancellationException) {
                withContext(NonCancellable) {
                    // `Refreshing` was pushed by this flight and nothing resolved it, so it
                    // would otherwise be the last state an app ever observes. Reverting to
                    // the state the refresh was entered from costs a successor one extra
                    // transition and leaves no stuck session behind if there is none.
                    flow.setState(SessionState.Authenticated)
                    endFlight(flight, null)
                }
                throw e
            } catch (e: Throwable) {
                Result.failure(e)
            }
            endFlight(flight, result)
            return result.getOrThrow()
        }
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
        refreshMutex.withLock { if (pendingRefresh === flight) pendingRefresh = null }
        flight.complete(outcome)
    }

    private suspend fun performRefresh(): TokenResponse {
        // Forces AuthorizationFlow's lazy restore before this class starts pushing states of
        // its own onto the same stream; otherwise a `Refreshing` pushed before the first
        // collector ever ran would be overwritten the moment restoration finally happened.
        flow.sessionState.first()
        flow.setState(SessionState.Refreshing)

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
            retryPolicy.newBudget().execute(tokenOrigin()) {
                // A fresh unwrap per attempt, not one unwrap shared across retries:
                // `TokenClient.refresh` takes ownership of the bytes it is given and zeroes
                // them once the request body is formed, so a second attempt handed the same
                // (by then zeroed) array would spend nothing. `credentialStore.useRefreshToken`
                // re-unwraps the still-untouched ciphertext each time, which is also exactly
                // the "unwrapped for the duration of one token request and no longer" rule
                // `spec/state-machine.md`'s `Locked` section states for every other caller.
                credentialStore.useRefreshToken { tokenClient.refresh(it, idempotencyKey) } ?: noGrantStored()
            }
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
            // settling back on `Authenticated`.
            flow.setState(
                if (e.reason is VersolaError.Recoverable.Cause.UnlockRequired) {
                    SessionState.Locked
                } else {
                    SessionState.Authenticated
                },
            )
            throw e
        } catch (e: VersolaError.Reauthenticate) {
            // `GrantRejected` (the token endpoint's invalid_grant) and `CredentialsInvalidated`
            // (the stored bytes no longer unwrap, from `useRefreshToken`) are the two ways the
            // grant itself is gone rather than merely unreachable — `spec/state-machine.md`
            // wipes everything credential-shaped for both (`Refreshing → Unauthenticated`,
            // `Locked → Unauthenticated`), so both are handled identically here.
            credentialStore.clear()
            cachedAccessToken = null
            flow.setState(SessionState.Unauthenticated)
            throw e
        } catch (e: Throwable) {
            // A `Configuration` fault or anything unforeseen: a deployment or SDK defect, not
            // a reason to sign the user out. The grant is left exactly as it was.
            flow.setState(SessionState.Authenticated)
            throw e
        }

        // Step 2. Persisted before returning to any caller — including the one whose call
        // triggered this refresh. `BoundRenewal` omits `refresh_token` on the response because
        // the stored value did not change; saving nothing in that case is what leaves it
        // unchanged rather than overwriting it with an absence.
        response.refreshToken?.let { credentialStore.save(it, response.idToken) }
        // Step 3. Cleared only now. Under DPoP this clears a slot whose value never moved —
        // inert, per the class doc, not skipped.
        credentialStore.savePendingRotation(null)
        cachedAccessToken = response
        flow.setState(SessionState.Authenticated)
        return response
    }

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
}
