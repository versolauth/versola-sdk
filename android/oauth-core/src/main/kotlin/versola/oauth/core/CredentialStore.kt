package versola.oauth.core

/**
 * Where the grant lives between processes: the refresh token, the raw ID token that
 * `id_token_hint` needs at logout, and the rotation slot of `spec/state-machine.md`'s refresh
 * ordering. Everything here is wrapped by a [CredentialKeyProvider] before it reaches a disk.
 *
 * The access token is deliberately absent. It is short-lived and re-derivable, and the
 * persistence summary keeps it in memory for exactly that reason.
 *
 * Two shapes in this interface are not stylistic:
 *
 * The refresh token is handed out through [useRefreshToken] rather than returned, because the
 * plaintext is zeroed when the block ends. A returned `ByteArray` has no such moment, and a
 * returned `String` cannot be zeroed at all. Nothing caches the unwrapped value between
 * calls — holding it for a session would widen the exposure window from one network request
 * to the lifetime of the process, which leaves encrypting it at rest doing very little.
 *
 * [hasGrant] answers without unwrapping anything. Restoring [SessionState] at launch must not
 * need the key: under [UnlockPolicy.OnAppUnlock] that would turn every cold start into an
 * authentication prompt, before the app has any reason to spend the grant.
 */
public interface CredentialStore {

    /**
     * Persists a token response. **Takes ownership of [refreshToken]** and zeroes it once it
     * is wrapped, so a caller must not reuse the array.
     *
     * A null [rawIdToken] leaves the stored one in place rather than clearing it: a refresh
     * response is permitted to omit `id_token`, and the value exists to be replayed as
     * `id_token_hint` at logout, where the last one known is the right answer.
     */
    public suspend fun save(refreshToken: ByteArray, rawIdToken: String? = null)

    /**
     * Runs [block] against the unwrapped refresh token and zeroes the buffer afterwards,
     * whether [block] returned or threw. Returns null when no grant is stored — a block that
     * itself returns null cannot be told apart from that, so callers wanting the distinction
     * ask [hasGrant] first.
     *
     * Throws [VersolaError.Reauthenticate] with [VersolaError.Reauthenticate.Reason.CredentialsInvalidated]
     * when the stored bytes can never be unwrapped again (an invalidated key, a ciphertext that
     * fails authentication), and propagates [VersolaError.Recoverable.Cause.UnlockRequired]
     * unchanged: one is a grant that is gone, the other a grant that is merely out of reach.
     * Any other failure of the key is [VersolaError.Recoverable] and leaves the grant stored,
     * and a cancellation propagates as itself: neither says anything about the grant.
     */
    public suspend fun <T> useRefreshToken(block: suspend (ByteArray) -> T): T?

    /** Whether a refresh token is stored. Answered without the key, and so without a prompt. */
    public suspend fun hasGrant(): Boolean

    /** The raw ID token, for `id_token_hint` on an RP-initiated logout. */
    public suspend fun rawIdToken(): String?

    /**
     * The pending rotation slot: step 1 of the refresh ordering copies the outgoing
     * generation's idempotency key here before the request is sent, and step 3 clears it with
     * null once the response is durably stored.
     *
     * A process killed in between finds the key on next start and replays with it, and the
     * server resolves which generation is live. Under DPoP the server renews in place and
     * both steps are inert; the machinery exists for bearer deployments.
     */
    public suspend fun savePendingRotation(idempotencyKey: String?)

    public suspend fun pendingRotation(): String?

    /** Logout and `invalid_grant`. Everything credential-shaped goes, including the slot. */
    public suspend fun clear()
}
