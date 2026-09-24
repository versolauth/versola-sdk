package kz.versola.sdk.core

import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

private const val ISSUER = "https://id.versola.kz"

/** One slot, exactly like the real store: a second save replaces rather than accumulates. */
private class RecordingPendingStore : PendingAuthorizationStore {
    var stored: PendingAuthorizationRequest? = null
    var clears = 0

    override suspend fun save(request: PendingAuthorizationRequest) {
        stored = request
    }

    override suspend fun load(): PendingAuthorizationRequest? = stored

    override suspend fun clear() {
        clears++
        stored = null
    }
}

/** Answers with a redirect carrying the `state` the store was just given. */
private class FixedRedirectBrowser(private val store: RecordingPendingStore) : BrowserAuthorizationSession {
    override suspend fun authorize(uri: String): BrowserOutcome {
        val pending = checkNotNull(store.stored) { "authorize() must persist before opening the browser" }
        return BrowserOutcome.Redirect(
            "https://app.example.com/oauth?code=the-code&state=${pending.state}&iss=$ISSUER",
        )
    }

    override suspend fun awaitPendingRedirect(): BrowserOutcome =
        throw UnsupportedOperationException("not exercised by these tests")
}

private class StaticDiscoveryClient(private val metadata: ProviderMetadata) : DiscoveryClient {
    override suspend fun fetch(issuer: String): ProviderMetadata = metadata
}

private class NoopMetadataCache : ProviderMetadataCache {
    override suspend fun load(): ProviderMetadata? = null
    override suspend fun save(metadata: ProviderMetadata) = Unit
    override suspend fun clear() = Unit
}

/**
 * An in-memory [CredentialStore] that mimics [kz.versola.sdk.storage.DataStoreCredentialStore]'s
 * two load-bearing properties: [useRefreshToken] hands out a fresh copy on every call and
 * zeroes it when the block ends, and nothing here caches an unwrapped value between calls.
 *
 * [unwrapFailure] stands in for a wrap/unwrap failure the real Keystore-backed store would
 * raise — an unlock window elapsed, or an enrolment change invalidated the key.
 */
private class FakeCredentialStore : CredentialStore {
    var refreshToken: ByteArray? = null
    var rawIdToken: String? = null
    var pendingRotationSlot: String? = null
    var unwrapFailure: (() -> VersolaError)? = null

    val events = mutableListOf<String>()
    var clears = 0
    var unwraps = 0

    override suspend fun save(refreshToken: ByteArray, rawIdToken: String?) {
        events += "save"
        this.refreshToken = refreshToken.copyOf()
        refreshToken.fill(0)
        if (rawIdToken != null) this.rawIdToken = rawIdToken
    }

    override suspend fun <T> useRefreshToken(block: suspend (ByteArray) -> T): T? {
        val current = refreshToken ?: return null
        unwrapFailure?.let { throw it() }
        unwraps++
        val plaintext = current.copyOf()
        return try {
            block(plaintext)
        } finally {
            plaintext.fill(0)
        }
    }

    override suspend fun hasGrant(): Boolean = refreshToken != null

    override suspend fun rawIdToken(): String? = rawIdToken

    override suspend fun savePendingRotation(idempotencyKey: String?) {
        events += "savePendingRotation($idempotencyKey)"
        pendingRotationSlot = idempotencyKey
    }

    override suspend fun pendingRotation(): String? = pendingRotationSlot

    override suspend fun clear() {
        clears++
        refreshToken = null
        rawIdToken = null
        pendingRotationSlot = null
    }
}

/** Scriptable [TokenClient]: each queued action runs once per call, in order, then the last repeats. */
private class FakeTokenClient : TokenClient {
    val exchangeCalls = mutableListOf<AuthorizationGrant>()
    val refreshCalls = mutableListOf<Pair<ByteArray, String>>()
    var exchangeResult: suspend () -> TokenResponse = { issued() }
    var refreshActions: MutableList<suspend () -> TokenResponse> = mutableListOf()

    override suspend fun exchange(grant: AuthorizationGrant): TokenResponse {
        exchangeCalls += grant
        return exchangeResult()
    }

    override suspend fun refresh(refreshToken: ByteArray, idempotencyKey: String): TokenResponse {
        refreshCalls += refreshToken.copyOf() to idempotencyKey
        val action = if (refreshActions.size > 1) refreshActions.removeAt(0) else refreshActions.first()
        return action()
    }
}

private fun issued(
    accessToken: String = "access-1",
    refreshToken: String? = "rotated-refresh",
    idToken: String? = null,
) = TokenResponse.from(
    TokenResponsePayload(
        accessToken = accessToken,
        tokenType = "Bearer",
        expiresIn = 3600,
        refreshToken = refreshToken,
        idToken = idToken,
    ),
)

class SessionCoordinatorTest {

    private val metadata = ProviderMetadata(
        issuer = ISSUER,
        authorizationEndpoint = "$ISSUER/authorize",
        tokenEndpoint = "$ISSUER/token",
        authorizationResponseIssParameterSupported = true,
    )

    private val configuration = VersolaConfiguration.create(
        issuer = ISSUER,
        clientId = "mobile-app",
        redirectUri = "https://app.example.com/oauth",
    )

    private fun authFlow(pendingStore: RecordingPendingStore): AuthorizationFlow = AuthorizationFlow(
        configuration = configuration,
        discovery = DiscoveryService(ISSUER, StaticDiscoveryClient(metadata), NoopMetadataCache()),
        pendingStore = pendingStore,
        browser = FixedRedirectBrowser(pendingStore),
        tokenBinding = TokenBinding.Bearer,
    )

    private fun coordinator(
        pendingStore: RecordingPendingStore = RecordingPendingStore(),
        tokenClient: FakeTokenClient = FakeTokenClient(),
        credentialStore: FakeCredentialStore = FakeCredentialStore(),
        retryPolicy: RetryPolicy = RetryPolicy.Conservative,
    ) = Triple(
        SessionCoordinator(authFlow(pendingStore), tokenClient, credentialStore, retryPolicy),
        tokenClient,
        credentialStore,
    )

    // ---- login() ----------------------------------------------------------------------

    @Test
    fun `login exchanges, persists before completing, and reaches Authenticated`() = runTest {
        val pendingStore = RecordingPendingStore()
        val (coordinator, tokenClient, credentialStore) = coordinator(pendingStore)
        tokenClient.exchangeResult = { issued(accessToken = "at", refreshToken = "rt") }

        val response = coordinator.login(setOf("openid"))

        assertEquals("at", response.accessToken)
        assertEquals("rt", credentialStore.refreshToken?.toString(Charsets.UTF_8))
        // The pending request survives the exchange and is wiped only once completeLogin()
        // runs after persistence — never before.
        assertNull(pendingStore.stored)
        assertEquals(1, pendingStore.clears)
        assertEquals(SessionState.Authenticated, coordinator.sessionState.first())
        assertNotNull(coordinator.currentAccessToken())
    }

    @Test
    fun `a failed exchange leaves the pending request exactly where authorize left it`() = runTest {
        val pendingStore = RecordingPendingStore()
        val (coordinator, tokenClient, _) = coordinator(pendingStore)
        tokenClient.exchangeResult = {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.TokenRequestRejected("invalid_client", null),
            )
        }

        failure { coordinator.login(setOf("openid")) }

        // Still Authorizing, pending request intact: this class does not shorten the
        // request's own ten-minute lifetime on a failure that has nothing to do with the
        // authorization response itself.
        assertNotNull(pendingStore.stored)
        assertEquals(0, pendingStore.clears)
        assertEquals(SessionState.Authorizing, coordinator.sessionState.first())
    }

    @Test
    fun `login refuses a response with no refresh token rather than starting an unrecoverable session`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        tokenClient.exchangeResult = { issued(refreshToken = null) }

        val error = failure { coordinator.login(setOf("openid")) } as VersolaError.Configuration
        assertTrue(error.detail is VersolaError.Configuration.Detail.TokenResponseMalformed)
        assertNull(credentialStore.refreshToken)
    }

    // ---- refresh(): single-flight -------------------------------------------------------

    @Test
    fun `five concurrent refreshes produce exactly one token request`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        // The winner has to genuinely be in flight when the other four arrive: a scripted
        // action that returns without ever suspending would let the winner finish and clear
        // `pendingRefresh` before caller two is even started, and each of the five would then
        // run its own request rather than coalescing onto one.
        tokenClient.refreshActions = mutableListOf({
            yield()
            issued(accessToken = "the-one-response")
        })

        val callers = List(5) { async(start = CoroutineStart.UNDISPATCHED) { coordinator.refresh() } }
        val results = callers.map { it.await() }

        assertEquals(1, tokenClient.refreshCalls.size)
        assertTrue(results.all { it.accessToken == "the-one-response" })
    }

    @Test
    fun `a caller that arrives after the winner finishes still gets its result`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        tokenClient.refreshActions = mutableListOf({ issued(accessToken = "shared") })

        val response = coordinator.refresh()

        assertEquals("shared", response.accessToken)
        assertEquals(1, tokenClient.refreshCalls.size)
    }

    // ---- refresh(): rotation slot ordering and idempotency -------------------------------

    @Test
    fun `the rotation slot is written before the request and cleared only after persistence`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        tokenClient.refreshActions = mutableListOf({ issued(refreshToken = "rotated") })

        coordinator.refresh()

        // savePendingRotation(key) before the request, save() persists the new value, then
        // savePendingRotation(null) clears the slot — never the other order.
        val order = credentialStore.events
        val keySave = order.indexOfFirst { it.startsWith("savePendingRotation") && it != "savePendingRotation(null)" }
        val persist = order.indexOf("save")
        val clear = order.indexOf("savePendingRotation(null)")
        assertTrue("$order", keySave in 0 until persist && persist < clear)
        assertEquals("rotated", credentialStore.refreshToken?.toString(Charsets.UTF_8))
        assertNull(credentialStore.pendingRotationSlot)
    }

    @Test
    fun `the idempotency key is derived from the token being spent and reused across retries`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        credentialStore.refreshToken = "seed-bytes".toByteArray(Charsets.UTF_8)
        tokenClient.refreshActions = mutableListOf(
            { throw VersolaError.Recoverable(VersolaError.Recoverable.Cause.Network("dropped")) },
            { issued() },
        )

        coordinator.refresh()

        val keys = tokenClient.refreshCalls.map { it.second }.toSet()
        assertEquals("every attempt of one operation must carry the same key", 1, keys.size)
    }

    @Test
    fun `a pending rotation left by process death is replayed with its own key, not a new one`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        credentialStore.pendingRotationSlot = "key-from-before-the-crash"
        tokenClient.refreshActions = mutableListOf({ issued() })

        coordinator.refresh()

        assertEquals("key-from-before-the-crash", tokenClient.refreshCalls.single().second)
        // No extra unwrap to derive a fresh key when one was already on disk: one unwrap for
        // the request itself and nothing else.
        assertEquals(1, credentialStore.unwraps)
    }

    // ---- refresh(): outcomes --------------------------------------------------------------

    @Test
    fun `invalid_grant wipes the store, drops the cached access token, and settles Unauthenticated`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        tokenClient.refreshActions = mutableListOf({
            throw VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.GrantRejected)
        })

        failure { coordinator.refresh() }

        assertNull(credentialStore.refreshToken)
        assertNull(credentialStore.pendingRotationSlot)
        assertEquals(1, credentialStore.clears)
        assertNull(coordinator.currentAccessToken())
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
        // Never retried: a second call would be a second replay of an already-revoked family.
        assertEquals(1, tokenClient.refreshCalls.size)
    }

    @Test
    fun `an invalidated storage key wipes and settles Unauthenticated exactly like invalid_grant`() = runTest {
        val (coordinator, _, credentialStore) = coordinator()
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        credentialStore.unwrapFailure = {
            VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.CredentialsInvalidated)
        }

        failure { coordinator.refresh() }

        assertNull(credentialStore.refreshToken)
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
    }

    @Test
    fun `an elapsed unlock window enters Locked without touching the stored grant`() = runTest {
        val (coordinator, _, credentialStore) = coordinator()
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        credentialStore.unwrapFailure = { VersolaError.Recoverable(VersolaError.Recoverable.Cause.UnlockRequired) }

        failure { coordinator.refresh() }

        assertEquals("seed", credentialStore.refreshToken?.toString(Charsets.UTF_8))
        assertEquals(0, credentialStore.clears)
        assertEquals(SessionState.Locked, coordinator.sessionState.first())
    }

    @Test
    fun `an exhausted retry budget reverts to Authenticated without touching the stored grant`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator(retryPolicy = RetryPolicy.Conservative)
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        tokenClient.refreshActions = mutableListOf({
            throw VersolaError.Recoverable(VersolaError.Recoverable.Cause.Network("down"))
        })

        failure { coordinator.refresh() }

        assertEquals("seed", credentialStore.refreshToken?.toString(Charsets.UTF_8))
        assertEquals(0, credentialStore.clears)
        assertEquals(SessionState.Authenticated, coordinator.sessionState.first())
    }

    @Test
    fun `a BoundRenewal response with no refresh_token leaves the stored token untouched`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        credentialStore.refreshToken = "unchanged".toByteArray(Charsets.UTF_8)
        tokenClient.refreshActions = mutableListOf({ issued(accessToken = "fresh-access", refreshToken = null) })

        val response = coordinator.refresh()

        assertEquals("fresh-access", response.accessToken)
        assertEquals("unchanged", credentialStore.refreshToken?.toString(Charsets.UTF_8))
        assertEquals("save() must not run when there is nothing new to persist", 0, credentialStore.events.count { it == "save" })
        assertNull(credentialStore.pendingRotationSlot)
        assertNotNull(coordinator.currentAccessToken())
    }

    @Test
    fun `refreshing with no grant stored settles Unauthenticated instead of calling the token endpoint`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        // No refreshToken seeded.

        failure { coordinator.refresh() }

        assertEquals(0, tokenClient.refreshCalls.size)
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
    }

    private suspend fun failure(block: suspend () -> Unit): VersolaError = try {
        block()
        throw AssertionError("expected a VersolaError")
    } catch (e: VersolaError) {
        e
    }
}
