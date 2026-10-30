package versola.oauth.core

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.yield
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

private const val ISSUER = "https://id.versola.io"

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

/**
 * Answers with a redirect carrying the `state` the store was just given — or, for the
 * end-session URI `logout()` opens, whatever [logoutOutcome] says, echoing the `state` the
 * URI carried the way auth's signed-out page does.
 */
private class FixedRedirectBrowser(private val store: RecordingPendingStore) : BrowserAuthorizationSession {
    val launched = mutableListOf<String>()
    var logoutOutcome: suspend (String) -> BrowserOutcome = { uri ->
        BrowserOutcome.Redirect("https://app.example.com/signed-out?state=${stateOf(uri)}")
    }

    var loginOutcome: (suspend (String) -> BrowserOutcome)? = null

    override suspend fun authorize(uri: String): BrowserOutcome {
        launched += uri
        if (uri.startsWith("$ISSUER/logout")) return logoutOutcome(uri)
        loginOutcome?.let { return it(uri) }
        val pending = checkNotNull(store.stored) { "authorize() must persist before opening the browser" }
        return BrowserOutcome.Redirect(
            "https://app.example.com/oauth?code=the-code&state=${pending.state}&iss=$ISSUER",
        )
    }

    private fun stateOf(uri: String): String =
        Regex("[?&]state=([^&]+)").find(uri)!!.groupValues[1]

    /** What a process started by the redirect finds waiting: scripted per test. */
    var pendingRedirect: (suspend () -> BrowserOutcome)? = null

    override suspend fun awaitPendingRedirect(): BrowserOutcome =
        pendingRedirect?.invoke() ?: throw UnsupportedOperationException("not exercised by these tests")
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
 * An in-memory [CredentialStore] that mimics [versola.sdk.storage.DataStoreCredentialStore]'s
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

    /** Injected into [save], simulating a key that locks or invalidates after the server
     *  already answered — the request succeeded, but persisting its response did not. */
    var saveFailure: (() -> VersolaError)? = null

    /**
     * Injected into [savePendingRotation] only when it is asked to *clear* the slot (a null
     * key), never on the step-1 write before the request — this simulates the key locking or
     * invalidating between [save] landing and step 3's clear.
     */
    var savePendingRotationClearFailure: (() -> VersolaError)? = null

    /** Suspends [pendingRotation] until completed, so a caller can be cancelled mid-lookup. */
    var pendingRotationDelay: CompletableDeferred<Unit>? = null

    val events = mutableListOf<String>()
    var clears = 0
    var unwraps = 0

    override suspend fun save(refreshToken: ByteArray, rawIdToken: String?) {
        events += "save"
        saveFailure?.let { throw it() }
        this.refreshToken = refreshToken.copyOf()
        refreshToken.fill(0)
        if (rawIdToken != null) this.rawIdToken = rawIdToken
    }

    /** One write for the rotated token and the slot, as the DataStore-backed store does it. */
    override suspend fun replaceRefreshToken(refreshToken: ByteArray, rawIdToken: String?) {
        events += "replaceRefreshToken"
        saveFailure?.let { throw it() }
        savePendingRotationClearFailure?.let { throw it() }
        this.refreshToken = refreshToken.copyOf()
        refreshToken.fill(0)
        if (rawIdToken != null) this.rawIdToken = rawIdToken
        pendingRotationSlot = null
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

    /** Suspends [hasGrant] until completed, so a restore can be cancelled mid-probe. */
    var hasGrantGate: CompletableDeferred<Unit>? = null

    override suspend fun hasGrant(): Boolean {
        hasGrantGate?.await()
        return refreshToken != null
    }

    override suspend fun rawIdToken(): String? = rawIdToken

    override suspend fun savePendingRotation(idempotencyKey: String?) {
        events += "savePendingRotation($idempotencyKey)"
        if (idempotencyKey == null) savePendingRotationClearFailure?.let { throw it() }
        pendingRotationSlot = idempotencyKey
    }

    override suspend fun pendingRotation(): String? {
        pendingRotationDelay?.await()
        return pendingRotationSlot
    }

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
    val revokeCalls = mutableListOf<ByteArray>()
    var exchangeResult: suspend () -> TokenResponse = { issued() }
    var refreshActions: MutableList<suspend () -> TokenResponse> = mutableListOf()
    var revokeFailure: (() -> VersolaError)? = null

    override suspend fun revoke(refreshToken: ByteArray) {
        revokeCalls += refreshToken.copyOf()
        refreshToken.fill(0)
        revokeFailure?.let { throw it() }
    }

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

private fun stored(): ByteArray = "grant".toByteArray(Charsets.UTF_8)

private fun issued(
    accessToken: String = "access-1",
    refreshToken: String? = "rotated-refresh",
    idToken: String? = null,
    expiresIn: Long = 3600,
) = TokenResponse.from(
    TokenResponsePayload(
        accessToken = accessToken,
        tokenType = "Bearer",
        expiresIn = expiresIn,
        refreshToken = refreshToken,
        idToken = idToken,
    ),
)

class SessionCoordinatorTest {

    private val metadata = ProviderMetadata(
        issuer = ISSUER,
        authorizationEndpoint = "$ISSUER/authorize",
        tokenEndpoint = "$ISSUER/token",
        revocationEndpoint = "$ISSUER/revoke",
        endSessionEndpoint = "$ISSUER/logout",
        authorizationResponseIssParameterSupported = true,
        scopesSupported = listOf("openid", "offline_access"),
    )

    private val configuration = VersolaConfiguration.create(
        issuer = ISSUER,
        clientId = "mobile-app",
        redirectUri = "https://app.example.com/oauth",
    )

    private fun authFlow(
        pendingStore: RecordingPendingStore,
        credentialStore: FakeCredentialStore,
        browser: BrowserAuthorizationSession = FixedRedirectBrowser(pendingStore),
        providerMetadata: ProviderMetadata = metadata,
    ): AuthorizationFlow = AuthorizationFlow(
        configuration = configuration,
        discovery = DiscoveryService(ISSUER, StaticDiscoveryClient(providerMetadata), NoopMetadataCache()),
        pendingStore = pendingStore,
        browser = browser,
        // Bearer throughout: rotation is the binding that makes single-flight, the rotation
        // slot and the idempotency key load-bearing rather than inert, so every test here
        // runs the mode that can actually lose a user's session.
        tokenBinding = TokenBinding.Bearer,
        hasStoredGrant = credentialStore::hasGrant,
    )

    /** Advanced by hand, so a lifetime can elapse without a test sleeping through it. */
    private var elapsed = 0L

    /** What the facade tears down with the grant; counted so the logout rule is assertable. */
    private var teardowns = 0
    private var teardownFailure: (() -> Exception)? = null

    private fun coordinator(
        pendingStore: RecordingPendingStore = RecordingPendingStore(),
        tokenClient: FakeTokenClient = FakeTokenClient(),
        credentialStore: FakeCredentialStore = FakeCredentialStore(),
        retryPolicy: RetryPolicy = RetryPolicy.Conservative,
        browser: BrowserAuthorizationSession = FixedRedirectBrowser(pendingStore),
        retryClock: () -> Long = { System.nanoTime() / 1_000_000L },
        providerMetadata: ProviderMetadata = metadata,
    ) = Triple(
        SessionCoordinator(
            authFlow(pendingStore, credentialStore, browser, providerMetadata),
            tokenClient,
            credentialStore,
            retryPolicy,
            elapsedMillis = { elapsed },
            onCredentialsWiped = {
                teardowns++
                teardownFailure?.let { throw it() }
            },
            retryClock = retryClock,
        ),
        tokenClient,
        credentialStore,
    )

    private fun generic(
        pendingStore: RecordingPendingStore = RecordingPendingStore(),
        tokenClient: FakeTokenClient = FakeTokenClient(),
        credentialStore: FakeCredentialStore = FakeCredentialStore(),
        validator: IdTokenValidator? = null,
        logger: VersolaLogger? = null,
        browser: BrowserAuthorizationSession = FixedRedirectBrowser(pendingStore),
        retryPolicy: RetryPolicy = RetryPolicy.Conservative,
        retryClock: () -> Long = { System.nanoTime() / 1_000_000L },
    ) = Triple(
        SessionCoordinator(
            authFlow(pendingStore, credentialStore, browser),
            tokenClient,
            credentialStore,
            retryPolicy,
            elapsedMillis = { elapsed },
            onCredentialsWiped = { teardowns++ },
            logger = logger,
            refreshTokens = RefreshTokenPolicy.Optional,
            idTokenValidator = validator,
            // As the generic facade wires it: it sends no Idempotency-Key.
            repeatsRefreshAfterAmbiguousFailure = false,
            retryClock = retryClock,
        ),
        tokenClient,
        credentialStore,
    )

    /** Records what it was asked and answers with claims, or refuses. */
    private class RecordingValidator : IdTokenValidator {
        val calls = mutableListOf<List<Any?>>()
        var refusal: IdTokenRejection? = null
        override suspend fun validate(idToken: String, expectedNonce: String?, accessToken: String?, maxAge: Long?, previous: IdTokenClaims?, serverTime: java.time.Instant?): IdTokenClaims {
            calls += listOf(idToken, expectedNonce, accessToken, maxAge, previous, serverTime)
            refusal?.let { throw VersolaError.Configuration(VersolaError.Configuration.Detail.IdTokenRejected(it)) }
            return IdTokenClaims(
                subject = "alice", issuer = "https://id.example.com", audience = listOf("mobile-app"),
                issuedAt = java.time.Instant.EPOCH, expiresAt = java.time.Instant.EPOCH.plusSeconds(3600),
            )
        }
    }

    private class WarningLogger : VersolaLogger {
        val warnings = mutableListOf<String>()
        override fun info(message: String) {}
        override fun warn(message: String) {
            warnings += message
        }
    }

    // ---- the generic facade's policies ---------------------------------------------------

    @Test
    fun `under the optional refresh-token policy the scopes go as given and a response without one makes a memory session`() = runTest {
        val pendingStore = RecordingPendingStore()
        val logger = WarningLogger()
        val (coordinator, tokenClient, credentialStore) = generic(pendingStore, logger = logger)
        tokenClient.exchangeResult = { issued(accessToken = "at", refreshToken = null, expiresIn = 3600) }

        coordinator.login(setOf("openid", "profile"))

        assertEquals(setOf("openid", "profile"), tokenClient.exchangeCalls.single().scopes)
        assertNull(credentialStore.refreshToken)
        assertEquals(SessionState.Authenticated, coordinator.sessionState.first())
        assertEquals("at", coordinator.accessToken().value)
        assertTrue(logger.warnings.any { it.contains("no refresh token") })
    }

    @Test
    fun `a memory session ends in SessionExpired once its token is stale, with no token request and no browser`() = runTest {
        val (coordinator, tokenClient, _) = generic()
        tokenClient.exchangeResult = { issued(accessToken = "at", refreshToken = null, expiresIn = 600) }
        coordinator.login(setOf("openid"))

        elapsed += 600_000
        val error = runCatching { coordinator.accessToken() }.exceptionOrNull() as VersolaError.Reauthenticate

        assertEquals(VersolaError.Reauthenticate.Reason.SessionExpired, error.reason)
        assertTrue(tokenClient.refreshCalls.isEmpty())
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
        assertNull(coordinator.claims)
        assertNull(coordinator.currentAccessToken())
    }

    @Test
    fun `the ID token is validated before persistence at login, and a refusal persists nothing`() = runTest {
        val validator = RecordingValidator()
        val (coordinator, tokenClient, credentialStore) = generic(validator = validator)
        tokenClient.exchangeResult = { issued(accessToken = "at", refreshToken = "rt", idToken = "h.p.s") }

        coordinator.login(setOf("openid"), maxAge = 300)

        val call = validator.calls.single()
        assertEquals("h.p.s", call[0])
        assertEquals(tokenClient.exchangeCalls.single().nonce, call[1])
        assertEquals("at", call[2])
        assertEquals(300L, call[3])
        assertNull(call[4])
        assertEquals("alice", coordinator.claims?.subject)
        assertEquals("rt", credentialStore.refreshToken?.toString(Charsets.UTF_8))

        val refusing = RecordingValidator().apply { refusal = IdTokenRejection.Nonce }
        val (second, client2, store2) = generic(validator = refusing)
        client2.exchangeResult = { issued(accessToken = "at", refreshToken = "rt", idToken = "h.p.s") }
        val error = runCatching { second.login(setOf("openid")) }.exceptionOrNull() as VersolaError.Configuration
        assertEquals(IdTokenRejection.Nonce, (error.detail as VersolaError.Configuration.Detail.IdTokenRejected).reason)
        assertNull(store2.refreshToken)
        assertNull(second.claims)
        assertEquals(SessionState.Unauthenticated, second.sessionState.first())
    }

    @Test
    fun `a missing ID token is refused when a validator is present`() = runTest {
        val (coordinator, tokenClient, credentialStore) = generic(validator = RecordingValidator())
        tokenClient.exchangeResult = { issued(accessToken = "at", refreshToken = "rt", idToken = null) }

        val error = runCatching { coordinator.login(setOf("openid")) }.exceptionOrNull() as VersolaError.Configuration

        assertEquals(IdTokenRejection.Malformed, (error.detail as VersolaError.Configuration.Detail.IdTokenRejected).reason)
        assertNull(credentialStore.refreshToken)
    }

    @Test
    fun `an ID token on a refresh is validated against the claims it replaces, and a refusal keeps the grant`() = runTest {
        val validator = RecordingValidator()
        val (coordinator, tokenClient, credentialStore) = generic(validator = validator)
        tokenClient.exchangeResult = { issued(accessToken = "at", refreshToken = "rt", idToken = "first") }
        coordinator.login(setOf("openid"))
        val first = coordinator.claims

        tokenClient.refreshActions = mutableListOf({ issued(accessToken = "at-2", refreshToken = "rt-2", idToken = "second") })
        coordinator.refresh()

        val call = validator.calls.last()
        assertEquals("second", call[0])
        assertNull(call[1])
        assertSame(first, call[4])
        assertEquals("rt-2", credentialStore.refreshToken?.toString(Charsets.UTF_8))
        assertEquals("second", credentialStore.rawIdToken)

        validator.refusal = IdTokenRejection.AuthTime
        val claimsBefore = coordinator.claims
        tokenClient.refreshActions = mutableListOf({ issued(accessToken = "at-3", refreshToken = "rt-3", idToken = "third") })
        val error = runCatching { coordinator.refresh() }.exceptionOrNull()
        assertTrue(error is VersolaError.Configuration)
        // The provider rotated, so the rotated token is the only live one and is kept; only
        // what the rejected ID token vouches for is dropped.
        assertEquals("rt-3", credentialStore.refreshToken?.toString(Charsets.UTF_8))
        assertNull(credentialStore.pendingRotationSlot)
        assertEquals("the rejected ID token is not kept as the logout hint", "second", credentialStore.rawIdToken)
        assertSame(claimsBefore, coordinator.claims)
        assertEquals("access-token of the rejected response is not served", "at-2", coordinator.currentAccessToken()?.accessToken)
        assertEquals(SessionState.Authenticated, coordinator.sessionState.first())
    }

    @Test
    fun `a refresh persists the rotated token before the ID token is validated`() = runTest {
        val credentialStore = FakeCredentialStore()
        var storedWhenValidating: String? = null
        var slotWhenValidating: String? = "unset"
        val validator = object : IdTokenValidator {
            override suspend fun validate(idToken: String, expectedNonce: String?, accessToken: String?, maxAge: Long?, previous: IdTokenClaims?, serverTime: java.time.Instant?): IdTokenClaims {
                storedWhenValidating = credentialStore.refreshToken?.toString(Charsets.UTF_8)
                slotWhenValidating = credentialStore.pendingRotationSlot
                throw VersolaError.Configuration(VersolaError.Configuration.Detail.IdTokenRejected(IdTokenRejection.Signature))
            }
        }
        val (coordinator, tokenClient, _) = generic(credentialStore = credentialStore, validator = validator)
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        tokenClient.refreshActions = mutableListOf({ issued(refreshToken = "rotated", idToken = "h.p.s") })

        failure { coordinator.refresh() }

        assertEquals("rotated", storedWhenValidating)
        assertNull("the slot of the spent generation is already cleared", slotWhenValidating)
    }

    @Test
    fun `a key set that cannot be fetched during a refresh keeps the rotated token and fails as Recoverable`() = runTest {
        val credentialStore = FakeCredentialStore()
        var blip = true
        val validator = object : IdTokenValidator {
            override suspend fun validate(idToken: String, expectedNonce: String?, accessToken: String?, maxAge: Long?, previous: IdTokenClaims?, serverTime: java.time.Instant?): IdTokenClaims {
                if (blip) throw VersolaError.Recoverable(VersolaError.Recoverable.Cause.Network("jwks request failed"))
                return IdTokenClaims(
                    subject = "alice", issuer = "https://id.example.com", audience = listOf("mobile-app"),
                    issuedAt = java.time.Instant.EPOCH, expiresAt = java.time.Instant.EPOCH.plusSeconds(3600),
                )
            }
        }
        val (coordinator, tokenClient, _) = generic(credentialStore = credentialStore, validator = validator)
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        tokenClient.refreshActions = mutableListOf(
            { issued(accessToken = "at-1", refreshToken = "rotated-1", idToken = "id-1") },
            { issued(accessToken = "at-2", refreshToken = "rotated-2", idToken = "id-2") },
        )

        val error = failure { coordinator.refresh() }

        assertTrue(error is VersolaError.Recoverable)
        // Nothing was dropped: the rotated token is stored, and the next refresh spends it
        // instead of the spent seed (which would be `invalid_grant` and a wipe).
        assertEquals("rotated-1", credentialStore.refreshToken?.toString(Charsets.UTF_8))
        assertEquals(0, credentialStore.clears)
        assertEquals(0, teardowns)
        assertNull(coordinator.currentAccessToken())
        assertEquals(SessionState.Authenticated, coordinator.sessionState.first())

        blip = false
        coordinator.refresh()

        assertEquals("rotated-1", tokenClient.refreshCalls.last().first.toString(Charsets.UTF_8))
        assertEquals("rotated-2", credentialStore.refreshToken?.toString(Charsets.UTF_8))
        assertEquals("id-2", credentialStore.rawIdToken)
    }

    @Test
    fun `a refresh cancelled while its ID token is being validated has already kept the rotated token`() = runTest {
        val credentialStore = FakeCredentialStore()
        val validating = CompletableDeferred<Unit>()
        val validator = object : IdTokenValidator {
            override suspend fun validate(idToken: String, expectedNonce: String?, accessToken: String?, maxAge: Long?, previous: IdTokenClaims?, serverTime: java.time.Instant?): IdTokenClaims {
                validating.complete(Unit)
                awaitCancellation()
            }
        }
        val (coordinator, tokenClient, _) = generic(credentialStore = credentialStore, validator = validator)
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        tokenClient.refreshActions = mutableListOf({ issued(refreshToken = "rotated", idToken = "h.p.s") })

        val job = launch(start = CoroutineStart.UNDISPATCHED) { coordinator.refresh() }
        validating.await()
        job.cancelAndJoin()

        assertEquals("rotated", credentialStore.refreshToken?.toString(Charsets.UTF_8))
        assertNull(credentialStore.pendingRotationSlot)
        assertEquals(SessionState.Authenticated, coordinator.sessionState.first())
    }

    @Test
    fun `a login over a stored grant that yields no refresh token wipes the stored grant`() = runTest {
        val credentialStore = FakeCredentialStore()
        val (coordinator, tokenClient, _) = generic(credentialStore = credentialStore)
        tokenClient.exchangeResult = { issued(accessToken = "at-a", refreshToken = "rt-a") }
        coordinator.login(setOf("openid"))
        assertEquals("rt-a", credentialStore.refreshToken?.toString(Charsets.UTF_8))
        val teardownsBefore = teardowns

        tokenClient.exchangeResult = { issued(accessToken = "at-b", refreshToken = null) }
        coordinator.login(setOf("openid"))

        // B's session is in memory; A's grant is gone, key teardown included, so a cold start
        // cannot come back as A.
        assertNull(credentialStore.refreshToken)
        assertEquals(teardownsBefore + 1, teardowns)
        assertEquals("at-b", coordinator.accessToken().value)
        val (restarted, _, _) = generic(credentialStore = credentialStore)
        assertEquals(SessionState.Unauthenticated, restarted.sessionState.first())
    }

    @Test
    fun `after a cold start the claims come back from the stored ID token and feed the refresh check`() = runTest {
        val credentialStore = FakeCredentialStore()
        val validator = RecordingValidator()
        val (coordinator, tokenClient, _) = generic(credentialStore = credentialStore, validator = validator)
        val header = Base64Url.encode("""{"alg":"RS256"}""".toByteArray())
        val payload = Base64Url.encode("""{"iss":"https://id.example.com","sub":"alice","aud":"mobile-app","exp":1700003600,"iat":1700000000,"nonce":"n","acr":"urn:mfa"}""".toByteArray())
        tokenClient.exchangeResult = { issued(accessToken = "at", refreshToken = "rt", idToken = "$header.$payload.sig") }
        coordinator.login(setOf("openid"))

        val (restarted, client2, _) = generic(credentialStore = credentialStore, validator = RecordingValidator().also { validator.calls.clear() })
        assertNull(restarted.claims)

        val restored = restarted.restoreClaims()

        assertEquals("alice", restored?.subject)
        assertEquals("urn:mfa", restored?.acr)
        assertEquals(restored, restarted.claims)
        assertFalse(restored!!.all.containsKey("nonce"))
        // The refresh check against the previous `sub` has what it needs after the restart.
        client2.refreshActions = mutableListOf({ issued(accessToken = "at-2", refreshToken = "rt-2", idToken = "$header.$payload.sig") })
        restarted.refresh()
    }

    @Test
    fun `the token response's Date reaches the validator as the provider's clock`() = runTest {
        val validator = RecordingValidator()
        val (coordinator, tokenClient, _) = generic(validator = validator)
        val serverDate = java.time.Instant.parse("2026-10-29T10:00:00Z")
        tokenClient.exchangeResult = {
            TokenResponse.from(TokenResponsePayload(accessToken = "at", tokenType = "Bearer", expiresIn = 3600, refreshToken = "rt", idToken = "h.p.s"), serverDate)
        }

        coordinator.login(setOf("openid"))

        assertEquals(serverDate, validator.calls.single()[5])
    }

    @Test
    fun `the optional policy warns once when offline_access is offered but not asked for, and once on a response without expires_in`() = runTest {
        val logger = WarningLogger()
        val (coordinator, tokenClient, _) = generic(logger = logger)
        tokenClient.exchangeResult = { issued(accessToken = "at", refreshToken = "rt", expiresIn = 0) }

        coordinator.login(setOf("openid"))
        tokenClient.refreshActions = mutableListOf({ issued(accessToken = "at-2", refreshToken = "rt-2", expiresIn = 0) })
        coordinator.refresh()

        assertEquals(1, logger.warnings.count { it.contains("offline_access") })
        assertEquals(1, logger.warnings.count { it.contains("expires_in") })
    }

    @Test
    fun `logout's switches skip revocation or the browser leg, and the wipe runs regardless`() = runTest {
        val pendingStore = RecordingPendingStore()
        val (coordinator, tokenClient, credentialStore) = generic(pendingStore)
        tokenClient.exchangeResult = { issued(accessToken = "at", refreshToken = "rt") }
        coordinator.login(setOf("openid"))

        val outcome = coordinator.logout(revoke = false, endSession = false)

        assertFalse(outcome.tokenRevoked)
        assertFalse(outcome.sessionEnded)
        assertTrue(tokenClient.revokeCalls.isEmpty())
        assertNull(credentialStore.refreshToken)
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
    }

    // ---- resumePendingLogin(): a redirect delivered to a cold-started process --------------

    /** What a previous process persisted before it was killed with the browser open. */
    private fun restoredPending(
        maxAge: Long? = null,
        ageMillis: Long = 60_000,
    ) = PendingAuthorizationRequest(
        state = "restored-state",
        nonce = "restored-nonce",
        codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        scopes = listOf("openid"),
        redirectUri = "https://app.example.com/oauth",
        acrValues = emptyList(),
        maxAge = maxAge,
        createdAtEpochMillis = System.currentTimeMillis() - ageMillis,
    )

    private fun redirect(state: String = "restored-state", iss: String? = ISSUER) = BrowserOutcome.Redirect(
        "https://app.example.com/oauth?code=the-code&state=$state" + (iss?.let { "&iss=$it" } ?: ""),
    )

    private class ColdStart(val pending: RecordingPendingStore, val browser: FixedRedirectBrowser)

    private fun coldStart(
        pending: PendingAuthorizationRequest? = restoredPending(),
        outcome: BrowserOutcome = redirect(),
    ): ColdStart {
        val store = RecordingPendingStore().apply { stored = pending }
        val browser = FixedRedirectBrowser(store).apply { pendingRedirect = { outcome } }
        return ColdStart(store, browser)
    }

    @Test
    fun `a redirect delivered to a cold-started process completes the sign-in from the restored request`() = runTest {
        val start = coldStart(restoredPending(maxAge = 300))
        val validator = RecordingValidator()
        val (coordinator, tokenClient, credentialStore) = generic(start.pending, validator = validator, browser = start.browser)
        tokenClient.exchangeResult = { issued(accessToken = "at", refreshToken = "rt", idToken = "h.p.s") }

        // The app observes Authorizing on cold start, never Unauthenticated (scenario 12).
        assertEquals(SessionState.Authorizing, coordinator.sessionState.first())
        val response = coordinator.resumePendingLogin()

        assertEquals("at", checkNotNull(response).accessToken)
        val grant = tokenClient.exchangeCalls.single()
        assertEquals("restored-nonce", grant.nonce)
        // The restored `max_age` reaches the ID-token check: no caller is left to supply it, and
        // a login finished here must not be exempt from what one finished in the old process faced.
        assertEquals("restored-nonce", validator.calls.single()[1])
        assertEquals(300L, validator.calls.single()[3])
        assertEquals("rt", credentialStore.refreshToken?.toString(Charsets.UTF_8))
        assertNull(start.pending.stored)
        assertEquals("alice", coordinator.claims?.subject)
        assertEquals(SessionState.Authenticated, coordinator.sessionState.first())
    }

    @Test
    fun `a resumed sign-in clears the pending request only after the grant is stored`() = runTest {
        val start = coldStart()
        val (coordinator, tokenClient, credentialStore) = generic(start.pending, validator = RecordingValidator(), browser = start.browser)
        tokenClient.exchangeResult = { issued(refreshToken = "rt", idToken = "h.p.s") }
        credentialStore.saveFailure = { VersolaError.Recoverable(VersolaError.Recoverable.Cause.UnlockRequired) }

        failure { coordinator.resumePendingLogin() }

        // A process killed (or a key locked) between the exchange and the write finds the
        // request still in place, not a session that looks as if it never started.
        assertNotNull(start.pending.stored)
        assertNull(credentialStore.refreshToken)
        assertEquals(0, start.pending.clears)
    }

    @Test
    fun `resuming with nothing pending is a no-op, with no token request`() = runTest {
        val start = coldStart(pending = null)
        val (coordinator, tokenClient, _) = generic(start.pending, validator = RecordingValidator(), browser = start.browser)

        assertNull(coordinator.resumePendingLogin())

        assertTrue(tokenClient.exchangeCalls.isEmpty())
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
    }

    @Test
    fun `a resumed redirect carrying another state is refused before any token request`() = runTest {
        val start = coldStart(outcome = redirect(state = "forged"))
        val (coordinator, tokenClient, credentialStore) = generic(start.pending, validator = RecordingValidator(), browser = start.browser)

        val error = failure { coordinator.resumePendingLogin() } as VersolaError.Configuration

        assertEquals(VersolaError.Configuration.Detail.StateMismatch, error.detail)
        assertTrue(tokenClient.exchangeCalls.isEmpty())
        assertNull(credentialStore.refreshToken)
        assertNull(start.pending.stored)
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
    }

    @Test
    fun `a resumed redirect carrying another issuer is refused before any token request`() = runTest {
        val start = coldStart(outcome = redirect(iss = "https://evil.example.com"))
        val (coordinator, tokenClient, credentialStore) = generic(start.pending, validator = RecordingValidator(), browser = start.browser)

        val error = failure { coordinator.resumePendingLogin() } as VersolaError.Configuration

        assertTrue(error.detail is VersolaError.Configuration.Detail.IssuerMismatch)
        assertTrue(tokenClient.exchangeCalls.isEmpty())
        assertNull(credentialStore.refreshToken)
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
    }

    @Test
    fun `a resumed redirect without the issuer is refused when the provider advertises it`() = runTest {
        val start = coldStart(outcome = redirect(iss = null))
        val (coordinator, tokenClient, _) = generic(start.pending, validator = RecordingValidator(), browser = start.browser)

        val error = failure { coordinator.resumePendingLogin() } as VersolaError.Configuration

        assertTrue(error.detail is VersolaError.Configuration.Detail.IssuerMismatch)
        assertTrue(tokenClient.exchangeCalls.isEmpty())
    }

    @Test
    fun `a resumed sign-in whose ID token is refused persists nothing and clears the request`() = runTest {
        val start = coldStart()
        val validator = RecordingValidator().apply { refusal = IdTokenRejection.Nonce }
        val (coordinator, tokenClient, credentialStore) = generic(start.pending, validator = validator, browser = start.browser)
        tokenClient.exchangeResult = { issued(refreshToken = "rt", idToken = "h.p.s") }

        val error = failure { coordinator.resumePendingLogin() } as VersolaError.Configuration

        assertEquals(IdTokenRejection.Nonce, (error.detail as VersolaError.Configuration.Detail.IdTokenRejected).reason)
        assertNull(credentialStore.refreshToken)
        assertNull(coordinator.claims)
        // The code is spent: a slot kept here could only be resumed into `invalid_grant`.
        assertNull(start.pending.stored)
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
    }

    @Test
    fun `a resumed sign-in with no ID token is refused when a validator is present`() = runTest {
        val start = coldStart()
        val (coordinator, tokenClient, credentialStore) = generic(start.pending, validator = RecordingValidator(), browser = start.browser)
        tokenClient.exchangeResult = { issued(refreshToken = "rt", idToken = null) }

        val error = failure { coordinator.resumePendingLogin() } as VersolaError.Configuration

        assertEquals(IdTokenRejection.Malformed, (error.detail as VersolaError.Configuration.Detail.IdTokenRejected).reason)
        assertNull(credentialStore.refreshToken)
    }

    @Test
    fun `a pending request older than ten minutes is discarded on cold start and never resumed`() = runTest {
        val start = coldStart(restoredPending(ageMillis = PendingAuthorizationRequest.MAX_AGE_MILLIS + 1_000))
        val (coordinator, tokenClient, _) = generic(start.pending, validator = RecordingValidator(), browser = start.browser)

        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
        val error = failure { coordinator.resumePendingLogin() } as VersolaError.Recoverable

        assertEquals(VersolaError.Recoverable.Cause.PendingRequestExpired, error.reason)
        assertTrue(tokenClient.exchangeCalls.isEmpty())
        assertNull(start.pending.stored)
    }

    @Test
    fun `a resumed browser that reports the user cancelled wipes the request`() = runTest {
        val start = coldStart(outcome = BrowserOutcome.UserCancelled)
        val (coordinator, tokenClient, _) = generic(start.pending, validator = RecordingValidator(), browser = start.browser)

        val error = failure { coordinator.resumePendingLogin() } as VersolaError.Recoverable

        assertEquals(VersolaError.Recoverable.Cause.UserCancelled, error.reason)
        assertTrue(tokenClient.exchangeCalls.isEmpty())
        assertNull(start.pending.stored)
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
    }

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
    fun `a failed exchange abandons the login rather than leaving a slot nothing can resume`() = runTest {
        val pendingStore = RecordingPendingStore()
        val (coordinator, tokenClient, _) = coordinator(pendingStore)
        tokenClient.exchangeResult = {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.TokenRequestRejected("invalid_client", null),
            )
        }

        failure { coordinator.login(setOf("openid")) }

        // The redirect was consumed and the code spent: a slot kept here would make the next
        // cold start report Authorizing and resumePendingAuthorization() wait for a redirect
        // that can never come, holding the authorize lock against every later login().
        assertNull(pendingStore.stored)
        assertEquals(1, pendingStore.clears)
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
    }

    @Test
    fun `a failed step-up exchange settles back on Authenticated, not on a login screen`() = runTest {
        val pendingStore = RecordingPendingStore()
        val (coordinator, tokenClient, credentialStore) = coordinator(pendingStore)
        credentialStore.refreshToken = stored()
        tokenClient.exchangeResult = {
            throw VersolaError.Recoverable(VersolaError.Recoverable.Cause.Network("dropped"))
        }

        failure { coordinator.login(setOf("openid"), acrValues = listOf("mfa")) }

        assertNull(pendingStore.stored)
        assertEquals(SessionState.Authenticated, coordinator.sessionState.first())
        assertNotNull(credentialStore.refreshToken)
    }

    @Test
    fun `login refuses a response with no refresh token rather than starting an unrecoverable session`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        tokenClient.exchangeResult = { issued(refreshToken = null) }

        val error = failure { coordinator.login(setOf("openid")) } as VersolaError.Configuration
        assertTrue(error.detail is VersolaError.Configuration.Detail.TokenResponseMalformed)
        assertNull(credentialStore.refreshToken)
    }

    @Test
    fun `a dropped response does not make login replay a single-use authorization code`() = runTest {
        val (coordinator, tokenClient, _) = coordinator(retryPolicy = RetryPolicy.Patient)
        tokenClient.exchangeResult = {
            throw VersolaError.Recoverable(VersolaError.Recoverable.Cause.Network("response dropped"))
        }

        failure { coordinator.login(setOf("openid")) }

        // Even under the most patient budget the SDK offers. The token endpoint has no
        // idempotency for `authorization_code`, so a second attempt is a replay of a spent
        // code, which the server may answer by revoking what it already issued from it.
        assertEquals(1, tokenClient.exchangeCalls.size)
    }

    // ---- refresh(): single-flight -------------------------------------------------------

    @Test
    fun `fifty concurrent refreshes produce exactly one token request`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        // The winner has to genuinely be in flight when the rest arrive: a scripted action
        // that returns without ever suspending would let the winner finish and clear
        // `pendingRefresh` before caller two is even started, and all fifty would then run
        // their own request rather than coalescing onto one.
        tokenClient.refreshActions = mutableListOf({
            yield()
            issued(accessToken = "the-one-response")
        })

        val callers = List(50) { async(start = CoroutineStart.UNDISPATCHED) { coordinator.refresh() } }
        val results = callers.map { it.await() }

        // Forty-nine of these would each be a replay of a token the previous one rotated,
        // and `detectReplay` revokes the family rather than the request.
        assertEquals(1, tokenClient.refreshCalls.size)
        assertEquals(50, results.size)
        assertTrue(results.all { it.accessToken == "the-one-response" })
        assertEquals(1, credentialStore.events.count { it == "replaceRefreshToken" })
    }

    @Test
    fun `two coordinators built on the same store still coalesce onto a single request`() = runTest {
        // A `SessionCoordinator`'s own `Mutex` only ever sees its own callers. Two instances
        // wrongly built on top of the same `CredentialStore` — the only way that store's
        // "one refresh in flight" invariant can be observed from outside — must still
        // coalesce onto one request between them, or a bearer-bound token gets rotated twice
        // and `detectReplay` revokes the family.
        val credentialStore = FakeCredentialStore().apply {
            refreshToken = "seed".toByteArray(Charsets.UTF_8)
        }
        val tokenClient = FakeTokenClient()
        val neverAnswers = CompletableDeferred<Unit>()
        tokenClient.refreshActions = mutableListOf({ neverAnswers.await(); issued() })
        val coordinatorA = SessionCoordinator(authFlow(RecordingPendingStore(), credentialStore), tokenClient, credentialStore)
        val coordinatorB = SessionCoordinator(authFlow(RecordingPendingStore(), credentialStore), tokenClient, credentialStore)

        val callers = listOf(
            async(start = CoroutineStart.UNDISPATCHED) { coordinatorA.refresh() },
            async(start = CoroutineStart.UNDISPATCHED) { coordinatorB.refresh() },
        )
        neverAnswers.complete(Unit)
        callers.forEach { it.await() }

        assertEquals(1, tokenClient.refreshCalls.size)
    }

    @Test
    fun `a stale-cache read that a concurrent refresh has already outrun does not force a second rotation`() {
        // accessToken()'s staleness verdict is taken outside the lock that hands out a
        // refresh flight. Between that read and this caller reaching the lock, a flight
        // started by somebody else can resolve and retire itself -- its successor would then
        // find no flight to join and win one of its own, rotating a grant that was refreshed
        // moments earlier. Reproducing the gap needs real thread parallelism, since a
        // coroutine test dispatcher has no suspension point between the two steps; the
        // injected `elapsedMillis` clock is the seam used to park caller A exactly there.
        val credentialStore = FakeCredentialStore().apply {
            refreshToken = "seed".toByteArray(Charsets.UTF_8)
        }
        val tokenClient = FakeTokenClient()
        tokenClient.refreshActions = mutableListOf(
            { issued(accessToken = "first") },
            { issued(accessToken = "second") },
            // Must stay unconsumed: a third call here is exactly the redundant rotation
            // this test exists to rule out.
            { issued(accessToken = "third") },
        )

        var clock = 0L
        val aParked = CountDownLatch(1)
        val resumeA = CountDownLatch(1)
        val armedOnce = AtomicBoolean(true)
        val coordinator = SessionCoordinator(
            authFlow(RecordingPendingStore(), credentialStore),
            tokenClient,
            credentialStore,
            elapsedMillis = {
                // kotlinx.coroutines' debug agent suffixes the thread name with the running
                // coroutine (" @coroutine#N"), so this matches on a prefix rather than equality.
                if (Thread.currentThread().name.startsWith("caller-A") && armedOnce.compareAndSet(true, false)) {
                    aParked.countDown()
                    resumeA.await(10, TimeUnit.SECONDS)
                }
                clock
            },
        )

        // Primes the cache with "first", then advances the clock past its refresh skew so
        // caller A's next read judges it stale.
        runBlocking { coordinator.refresh() }
        clock = 3_600_000L

        var aResult: AccessToken? = null
        val callerA = Thread({ aResult = runBlocking { coordinator.accessToken() } }, "caller-A")
        callerA.start()
        assertTrue(aParked.await(10, TimeUnit.SECONDS))

        // Runs to completion, on this thread, while caller A sits parked between reading the
        // stale "first" entry and reaching the flight lock -- exactly the gap the fix closes.
        val second = runBlocking { coordinator.refresh() }
        resumeA.countDown()
        callerA.join(10_000)

        assertEquals("second", second.accessToken)
        assertEquals("second", aResult?.value)
        assertEquals(2, tokenClient.refreshCalls.size)
    }

    @Test
    fun `cancelling the caller that won the flight does not fail the callers waiting on it`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        val neverAnswers = CompletableDeferred<Unit>()
        tokenClient.refreshActions = mutableListOf(
            { neverAnswers.await(); issued() },
            { issued(accessToken = "after-the-takeover") },
        )

        val abandoned = async(start = CoroutineStart.UNDISPATCHED) { coordinator.refresh() }
        val waiting = async(start = CoroutineStart.UNDISPATCHED) { coordinator.refresh() }
        abandoned.cancel()

        // The second caller's own job was never cancelled, so it takes the flight over
        // instead of inheriting a `CancellationException` from a coroutine it has nothing to
        // do with.
        assertEquals("after-the-takeover", waiting.await().accessToken)
        // And it replays with the key the abandoned attempt left in the rotation slot, which
        // is what makes the takeover a retry rather than a second spend.
        assertEquals(2, tokenClient.refreshCalls.size)
        assertEquals(tokenClient.refreshCalls[0].second, tokenClient.refreshCalls[1].second)
        assertEquals(SessionState.Authenticated, coordinator.sessionState.first())
    }

    @Test
    fun `an abandoned refresh with nobody waiting leaves no session stuck in Refreshing`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        val neverAnswers = CompletableDeferred<Unit>()
        tokenClient.refreshActions = mutableListOf({ neverAnswers.await(); issued() })

        val abandoned = async(start = CoroutineStart.UNDISPATCHED) { coordinator.refresh() }
        abandoned.cancelAndJoin()

        assertEquals(SessionState.Authenticated, coordinator.sessionState.first())
    }

    @Test
    fun `cancelling a refresh that finds no grant does not resurrect a session that never existed`() = runTest {
        // No refresh token seeded: this call can only ever discover `noGrantStored`. A
        // cancellation that lands before that discovery must not publish `Authenticated` —
        // there is nothing authenticated to revert to, and the state entered from was
        // `Unauthenticated`, not `Authenticated`.
        val (coordinator, tokenClient, credentialStore) = coordinator()
        val gate = CompletableDeferred<Unit>()
        credentialStore.pendingRotationDelay = gate
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())

        val abandoned = async(start = CoroutineStart.UNDISPATCHED) { coordinator.refresh() }
        assertEquals(SessionState.Refreshing, coordinator.sessionState.first())
        abandoned.cancelAndJoin()

        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
        assertEquals(0, tokenClient.refreshCalls.size)
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

        // savePendingRotation(key) before the request, then the new value and the cleared slot
        // in one write — never the slot cleared first, and never two writes a kill can land between.
        val order = credentialStore.events
        val keySave = order.indexOfFirst { it.startsWith("savePendingRotation") }
        val persist = order.indexOf("replaceRefreshToken")
        assertTrue("$order", keySave in 0 until persist)
        assertEquals("the slot is cleared by the same write, not a second one", listOf("savePendingRotation"), order.filter { it.startsWith("savePendingRotation") }.map { it.substringBefore('(') })
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

    // ---- scenarios 34 to 36, unit tier: server errors, Retry-After and the cooldown --------------

    private fun serverFailure(status: Int, retryAfterMillis: Long? = null) =
        VersolaError.Recoverable(VersolaError.Recoverable.Cause.Server(status, retryAfterMillis))

    @Test
    fun `a 429 with Retry-After is waited out and the refresh then replays with the same key`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator(
            retryPolicy = RetryPolicy(),
            retryClock = { testScheduler.currentTime },
        )
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        tokenClient.refreshActions = mutableListOf(
            { throw serverFailure(429, 2_000) },
            { issued(refreshToken = "rotated") },
        )

        coordinator.refresh()

        assertEquals(2, tokenClient.refreshCalls.size)
        // The same key: the second request is a repeat of the first, not a second rotation.
        assertEquals(tokenClient.refreshCalls[0].second, tokenClient.refreshCalls[1].second)
        assertTrue("waited ${testScheduler.currentTime}ms", testScheduler.currentTime in 2_000..2_200)
        assertEquals(SessionState.Authenticated, coordinator.sessionState.first())
    }

    @Test
    fun `a Retry-After past the budget fails the refresh at once and leaves the session Authenticated`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator(
            retryPolicy = RetryPolicy(),
            retryClock = { testScheduler.currentTime },
        )
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        tokenClient.refreshActions = mutableListOf({ throw serverFailure(503, 30_000) })

        val error = failure { coordinator.refresh() } as VersolaError.Recoverable

        val cause = error.reason as VersolaError.Recoverable.Cause.Server
        assertEquals(503, cause.status)
        assertEquals(30_000L, cause.retryAfterMillis)
        assertEquals(1, tokenClient.refreshCalls.size)
        assertEquals(0L, testScheduler.currentTime)
        assertEquals("seed", credentialStore.refreshToken?.toString(Charsets.UTF_8))
        assertEquals(SessionState.Authenticated, coordinator.sessionState.first())
    }

    @Test
    fun `after a Retry-After no token request is made until it has passed`() = runTest {
        var retryNow = 0L
        val (coordinator, tokenClient, credentialStore) = coordinator(
            retryPolicy = RetryPolicy(),
            retryClock = { retryNow },
        )
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        tokenClient.refreshActions = mutableListOf(
            { throw serverFailure(429, 30_000) },
            { issued(refreshToken = "rotated") },
        )
        failure { coordinator.refresh() }

        retryNow = 10_000
        val refused = failure { coordinator.refresh() } as VersolaError.Recoverable
        val again = failure { coordinator.accessToken() } as VersolaError.Recoverable

        // Nothing went out: the one request is the first one. What is left of the wait is
        // reported, and attempts is zero because nothing was sent.
        assertEquals(1, tokenClient.refreshCalls.size)
        for (error in listOf(refused, again)) {
            val cause = error.reason as VersolaError.Recoverable.Cause.Server
            assertEquals(429, cause.status)
            assertEquals(20_000L, cause.retryAfterMillis)
            assertEquals(0, cause.attempts)
        }
        assertEquals(SessionState.Authenticated, coordinator.sessionState.first())

        retryNow = 30_000
        coordinator.refresh()
        assertEquals(2, tokenClient.refreshCalls.size)
    }

    @Test
    fun `a cooldown is held per coordinator and forgotten by a new one`() = runTest {
        val (first, firstClient, firstStore) = coordinator(retryPolicy = RetryPolicy(), retryClock = { 0L })
        firstStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        firstClient.refreshActions = mutableListOf({ throw serverFailure(429, 30_000) })
        failure { first.refresh() }

        // A cold start: new objects, nothing remembered. One request goes out.
        val (second, secondClient, secondStore) = coordinator(retryPolicy = RetryPolicy(), retryClock = { 0L })
        secondStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        secondClient.refreshActions = mutableListOf({ issued() })
        second.refresh()

        assertEquals(1, secondClient.refreshCalls.size)
    }

    @Test
    fun `a 501 on refresh is surfaced after one request`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator(retryPolicy = RetryPolicy())
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        tokenClient.refreshActions = mutableListOf({ throw serverFailure(501) })

        val error = failure { coordinator.refresh() } as VersolaError.Recoverable

        assertEquals(501, (error.reason as VersolaError.Recoverable.Cause.Server).status)
        assertEquals(1, tokenClient.refreshCalls.size)
    }

    @Test
    fun `revocation is repeated under the budget when the provider answers 503, and logout still wipes`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator(retryPolicy = RetryPolicy())
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        tokenClient.revokeFailure = { serverFailure(503) }

        val outcome = coordinator.logout(endSession = false)

        // maxAttemptsPerOrigin, no more, with a fresh unwrap of the token for each.
        assertEquals(3, tokenClient.revokeCalls.size)
        assertTrue(tokenClient.revokeCalls.all { it.toString(Charsets.UTF_8) == "seed" })
        assertFalse(outcome.tokenRevoked)
        assertNull(credentialStore.refreshToken)
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
    }

    @Test
    fun `a login's code exchange is not repeated on a 503 with Retry-After`() = runTest {
        val (coordinator, tokenClient, _) = coordinator(retryPolicy = RetryPolicy.Patient)
        tokenClient.exchangeResult = { throw serverFailure(503, 1_000) }

        val error = failure { coordinator.login(setOf("openid")) } as VersolaError.Recoverable

        assertEquals(1, tokenClient.exchangeCalls.size)
        assertEquals(503, (error.reason as VersolaError.Recoverable.Cause.Server).status)
    }

    // ---- a refresh without an Idempotency-Key is repeated only when it was not processed ----------

    private fun ambiguous(cause: Throwable) =
        VersolaError.Recoverable(VersolaError.Recoverable.Cause.Network("failed: ${cause.message}"), cause)

    @Test
    fun `the generic facade repeats a refresh only when it provably was not processed`() = runTest {
        val notProcessed: List<VersolaError.Recoverable> = listOf(
            serverFailure(503), serverFailure(429), serverFailure(408),
            ambiguous(java.net.UnknownHostException("id.example.com")),
            ambiguous(java.net.ConnectException("Connection refused")),
            ambiguous(javax.net.ssl.SSLHandshakeException("handshake")),
        )
        for (failure in notProcessed) {
            val (coordinator, tokenClient, credentialStore) = generic(retryPolicy = RetryPolicy())
            credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
            tokenClient.refreshActions = mutableListOf({ throw failure })

            failure { coordinator.refresh() }

            assertEquals("${failure.reason}", 3, tokenClient.refreshCalls.size)
        }
    }

    @Test
    fun `the generic facade surfaces an ambiguous refresh failure after one request, grant and rotation slot intact`() = runTest {
        // These may each have come after the provider rotated the token: a repeat would replay it,
        // and a rotating provider can answer by revoking the family.
        val ambiguousFailures: List<VersolaError.Recoverable> = listOf(
            serverFailure(500), serverFailure(502), serverFailure(504),
            ambiguous(java.net.SocketTimeoutException("timeout")),
            ambiguous(java.net.SocketException("Connection reset")),
            ambiguous(java.io.IOException("unexpected end of stream")),
        )
        for (failure in ambiguousFailures) {
            val (coordinator, tokenClient, credentialStore) = generic(retryPolicy = RetryPolicy())
            credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
            tokenClient.refreshActions = mutableListOf({ throw failure })

            val error = failure { coordinator.refresh() } as VersolaError.Recoverable

            assertEquals("${failure.reason}", 1, tokenClient.refreshCalls.size)
            assertEquals(1, when (val r = error.reason) {
                is VersolaError.Recoverable.Cause.Server -> r.attempts
                is VersolaError.Recoverable.Cause.Network -> r.attempts
                else -> -1
            })
            assertEquals("seed", credentialStore.refreshToken?.toString(Charsets.UTF_8))
            assertEquals(0, credentialStore.clears)
            assertEquals(SessionState.Authenticated, coordinator.sessionState.first())
        }
    }

    @Test
    fun `the facade that sends an Idempotency-Key still repeats an ambiguous refresh failure`() = runTest {
        // The Versola facade: a repeat resolves to the same rotation, so the old behaviour stands.
        val (coordinator, tokenClient, credentialStore) = coordinator(retryPolicy = RetryPolicy())
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        tokenClient.refreshActions = mutableListOf({ throw serverFailure(500) })

        failure { coordinator.refresh() }

        assertEquals(3, tokenClient.refreshCalls.size)
    }

    @Test
    fun `revocation is still repeated by the generic facade, since revoking a revoked token succeeds`() = runTest {
        val (coordinator, tokenClient, credentialStore) = generic(retryPolicy = RetryPolicy())
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        tokenClient.revokeFailure = { serverFailure(500) }

        coordinator.logout(endSession = false)

        assertEquals(3, tokenClient.revokeCalls.size)
    }

    @Test
    fun `login is refused before the browser opens while a Retry-After holds the token origin`() = runTest {
        var retryNow = 0L
        val (coordinator, tokenClient, credentialStore) = coordinator(retryPolicy = RetryPolicy(), retryClock = { retryNow })
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        tokenClient.refreshActions = mutableListOf({ throw serverFailure(429, 30_000) })
        failure { coordinator.refresh() }
        val opened = coordinator.sessionState.first()

        val error = failure { coordinator.login(setOf("openid")) } as VersolaError.Recoverable

        // A refusal here costs the user nothing: no browser, no pending request, nothing sent.
        val cause = error.reason as VersolaError.Recoverable.Cause.Server
        assertEquals(0, cause.attempts)
        assertEquals(30_000L, cause.retryAfterMillis)
        assertEquals(0, tokenClient.exchangeCalls.size)
        assertEquals(opened, coordinator.sessionState.first())
    }

    @Test
    fun `a code exchange is sent while a cooldown runs, and its Retry-After starts one`() = runTest {
        var retryNow = 0L
        val (coordinator, tokenClient, _) = coordinator(retryPolicy = RetryPolicy(), retryClock = { retryNow })
        tokenClient.exchangeResult = { throw serverFailure(429, 30_000) }

        // The code just obtained is not refused: the request goes out and the provider answers.
        val first = failure { coordinator.login(setOf("openid")) } as VersolaError.Recoverable
        assertEquals(1, tokenClient.exchangeCalls.size)
        assertEquals(30_000L, (first.reason as VersolaError.Recoverable.Cause.Server).retryAfterMillis)

        // The Retry-After on the exchange quiets the origin for the next login before its browser.
        val second = failure { coordinator.login(setOf("openid")) } as VersolaError.Recoverable
        assertEquals(0, (second.reason as VersolaError.Recoverable.Cause.Server).attempts)
        assertEquals(1, tokenClient.exchangeCalls.size)
    }

    @Test
    fun `a revocation endpoint on another host has its own allowance and its own cooldown`() = runTest {
        var retryNow = 0L
        val separate = metadata.copy(revocationEndpoint = "https://revoke.example.com/revoke")
        val (coordinator, tokenClient, credentialStore) = coordinator(
            retryPolicy = RetryPolicy(),
            retryClock = { retryNow },
            providerMetadata = separate,
        )
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        // A 429 with Retry-After from the token host holds the token origin only.
        tokenClient.refreshActions = mutableListOf({ throw serverFailure(429, 30_000) })
        failure { coordinator.refresh() }

        val outcome = coordinator.logout(endSession = false)

        assertEquals(1, tokenClient.revokeCalls.size)
        assertTrue(outcome.tokenRevoked)
    }

    @Test
    fun `a key that locks while persisting the refreshed response enters Locked rather than leaving Refreshing stuck`() = runTest {
        // The server already rotated the token by the time this throws — persistence itself
        // is what fails, not the request — so this must map onto the same catch the request's
        // own `UnlockRequired` does, or the flow is left in `Refreshing` with no exception any
        // caller can attribute to a known cause.
        val (coordinator, tokenClient, credentialStore) = coordinator()
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        credentialStore.saveFailure = { VersolaError.Recoverable(VersolaError.Recoverable.Cause.UnlockRequired) }
        tokenClient.refreshActions = mutableListOf({ issued(refreshToken = "rotated") })

        failure { coordinator.refresh() }

        assertEquals(SessionState.Locked, coordinator.sessionState.first())
    }

    @Test
    fun `a key invalidated while clearing the rotation slot after persistence still wipes and signs out`() = runTest {
        // The response is already durably stored when step 3 throws: the grant is gone in
        // substance regardless, so this must wipe and settle `Unauthenticated` exactly as a
        // failure during the request itself does — not leave the session in `Refreshing`
        // with a rotation slot pointing at a key from a generation that no longer exists.
        val (coordinator, tokenClient, credentialStore) = coordinator()
        credentialStore.refreshToken = "seed".toByteArray(Charsets.UTF_8)
        credentialStore.savePendingRotationClearFailure = {
            VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.CredentialsInvalidated)
        }
        tokenClient.refreshActions = mutableListOf({ issued(refreshToken = "rotated") })

        failure { coordinator.refresh() }

        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
        assertEquals(1, credentialStore.clears)
        assertNull(coordinator.currentAccessToken())
    }

    @Test
    fun `a BoundRenewal response with no refresh_token leaves the stored token untouched`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        credentialStore.refreshToken = "unchanged".toByteArray(Charsets.UTF_8)
        tokenClient.refreshActions = mutableListOf({ issued(accessToken = "fresh-access", refreshToken = null) })

        val response = coordinator.refresh()

        assertEquals("fresh-access", response.accessToken)
        assertEquals("unchanged", credentialStore.refreshToken?.toString(Charsets.UTF_8))
        assertEquals("save() must not run when there is nothing new to persist", 0, credentialStore.events.count { it == "replaceRefreshToken" })
        assertNull(credentialStore.pendingRotationSlot)
        assertNotNull(coordinator.currentAccessToken())
    }

    @Test
    fun `a replay revoking the family signs the session out and leaves login usable again`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        credentialStore.refreshToken = "replayed".toByteArray(Charsets.UTF_8)
        // What `detectReplay` answers once a bearer refresh token is spent twice: the whole
        // family is revoked, so the grant this client holds is gone rather than rejected.
        tokenClient.refreshActions = mutableListOf({
            throw VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.GrantRejected)
        })

        val error = failure { coordinator.refresh() }

        assertTrue(error is VersolaError.Reauthenticate)
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())

        // Not a stuck session: signing back in on the same coordinator goes through, which
        // is the whole difference between `Reauthenticate` and a session that can only be
        // fixed by reinstalling the app.
        tokenClient.exchangeResult = { issued(accessToken = "after-sign-in", refreshToken = "new-family") }
        val response = coordinator.login(setOf("openid"))

        assertEquals("after-sign-in", response.accessToken)
        assertEquals("new-family", credentialStore.refreshToken?.toString(Charsets.UTF_8))
        assertEquals(SessionState.Authenticated, coordinator.sessionState.first())
    }

    @Test
    fun `refreshing with no grant stored settles Unauthenticated instead of calling the token endpoint`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        // No refreshToken seeded.

        failure { coordinator.refresh() }

        assertEquals(0, tokenClient.refreshCalls.size)
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
    }

    // ---- cold start ------------------------------------------------------------------------

    @Test
    fun `a cold start with a stored grant restores Authenticated, not signed out`() = runTest {
        val credentialStore = FakeCredentialStore().apply {
            refreshToken = "from-a-previous-run".toByteArray(Charsets.UTF_8)
        }
        val (coordinator, _, _) = coordinator(credentialStore = credentialStore)

        assertEquals(SessionState.Authenticated, coordinator.sessionState.first())
    }

    @Test
    fun `a login killed between persisting the token and clearing the slot restores Authenticated`() = runTest {
        val pendingStore = RecordingPendingStore()
        pendingStore.stored = PendingAuthorizationRequest(
            state = "already-answered",
            nonce = "already-answered-nonce",
            codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            scopes = listOf("openid"),
            redirectUri = "https://app.example.com/oauth",
            acrValues = emptyList(),
            maxAge = null,
            createdAtEpochMillis = System.currentTimeMillis(),
        )
        val credentialStore = FakeCredentialStore().apply {
            refreshToken = "persisted-just-before-the-kill".toByteArray(Charsets.UTF_8)
        }
        val (coordinator, _, _) = coordinator(pendingStore, credentialStore = credentialStore)

        // The code behind that pending request was already redeemed — the stored grant is
        // the proof — so resuming it could only fail as `invalid_grant`. It is residue, and
        // it is cleared rather than believed.
        assertEquals(SessionState.Authenticated, coordinator.sessionState.first())
        assertNull(pendingStore.stored)
    }

    @Test
    fun `a coordinator refuses a flow that cannot restore a stored session`() {
        val pendingStore = RecordingPendingStore()
        val unwired = AuthorizationFlow(
            configuration = configuration,
            discovery = DiscoveryService(ISSUER, StaticDiscoveryClient(metadata), NoopMetadataCache()),
            pendingStore = pendingStore,
            browser = FixedRedirectBrowser(pendingStore),
            tokenBinding = TokenBinding.Bearer,
        )

        val error = try {
            SessionCoordinator(unwired, FakeTokenClient(), FakeCredentialStore())
            throw AssertionError("expected a Configuration error")
        } catch (e: VersolaError.Configuration) {
            e
        }

        assertTrue(error.detail is VersolaError.Configuration.Detail.InvalidConfiguration)
    }

    // ---- accessToken() and the refresh skew --------------------------------------------

    @Test
    fun `a token outside its refresh skew is served from the cache, with no token request`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        credentialStore.refreshToken = stored()
        tokenClient.refreshActions = mutableListOf({ issued(accessToken = "cached", expiresIn = 3600) })
        coordinator.refresh()

        // 3600 s less the 30 s cap leaves 3570 s of use; a second short of that is inside it.
        elapsed += 3_569_000
        val token = coordinator.accessToken()

        assertEquals("cached", token.value)
        assertEquals(1, tokenClient.refreshCalls.size)
    }

    @Test
    fun `a token within its refresh skew is refreshed before it is handed out`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        credentialStore.refreshToken = stored()
        tokenClient.refreshActions = mutableListOf(
            { issued(accessToken = "first", expiresIn = 3600) },
            { issued(accessToken = "second", expiresIn = 3600) },
        )
        coordinator.refresh()

        elapsed += 3_570_000
        val token = coordinator.accessToken()

        assertEquals("second", token.value)
        assertEquals(2, tokenClient.refreshCalls.size)
    }

    @Test
    fun `a short lifetime gets a tenth of itself, not a cap that would expire it on arrival`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        credentialStore.refreshToken = stored()
        tokenClient.refreshActions = mutableListOf({ issued(expiresIn = 20) })
        coordinator.refresh()

        // A flat 30 s skew against a 20 s token refreshes here, and before every call after.
        elapsed += 17_999
        coordinator.accessToken()
        assertEquals(1, tokenClient.refreshCalls.size)

        elapsed += 1
        coordinator.accessToken()
        assertEquals(2, tokenClient.refreshCalls.size)
    }

    @Test
    fun `a response without expires_in is unknown rather than expired`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        credentialStore.refreshToken = stored()
        tokenClient.refreshActions = mutableListOf({ issued(accessToken = "undated", expiresIn = 0) })
        coordinator.refresh()

        elapsed += 365L * 24 * 60 * 60 * 1000
        val token = coordinator.accessToken()

        assertEquals("undated", token.value)
        assertEquals(1, tokenClient.refreshCalls.size)
    }

    @Test
    fun `accessToken on a cold cache refreshes rather than answering with nothing`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        credentialStore.refreshToken = stored()
        tokenClient.refreshActions = mutableListOf({ issued(accessToken = "restored") })

        assertEquals("restored", coordinator.accessToken().value)
        assertEquals(1, tokenClient.refreshCalls.size)
    }

    @Test
    fun `the skew is a tenth of the lifetime until the thirty-second cap takes over`() {
        assertEquals(18_000, RefreshSkew.usableForMillis(issued(expiresIn = 20)))
        // 300 s is the crossover: a tenth of it is exactly the cap.
        assertEquals(270_000, RefreshSkew.usableForMillis(issued(expiresIn = 300)))
        assertEquals(570_000, RefreshSkew.usableForMillis(issued(expiresIn = 600)))
        assertEquals(3_570_000, RefreshSkew.usableForMillis(issued(expiresIn = 3600)))
    }

    @Test
    fun `a lifetime past what milliseconds can express does not wrap into an expired token`() {
        assertEquals(Long.MAX_VALUE, RefreshSkew.usableForMillis(issued(expiresIn = Long.MAX_VALUE)))
        assertEquals(Long.MAX_VALUE, RefreshSkew.usableForMillis(issued(expiresIn = -1)))
    }

    @Test
    fun `login asks for offline_access, which the refresh token depends on`() = runTest {
        val pendingStore = RecordingPendingStore()
        val (coordinator, tokenClient, _) = coordinator(pendingStore)

        coordinator.login(setOf("openid", "profile"))

        assertEquals(setOf("openid", "profile", "offline_access"), tokenClient.exchangeCalls.single().scopes)
    }

    // ---- review findings H1 / H2 / M4 ---------------------------------------------------

    @Test
    fun `a winner cancelled during the lazy restore does not wedge every later refresh`() = runTest {
        val credentialStore = FakeCredentialStore().apply { refreshToken = stored() }
        val gate = CompletableDeferred<Unit>()
        credentialStore.hasGrantGate = gate
        val tokenClient = FakeTokenClient().apply { refreshActions = mutableListOf({ issued(accessToken = "after") }) }
        val coordinator = SessionCoordinator(
            authFlow(RecordingPendingStore(), credentialStore), tokenClient, credentialStore,
            elapsedMillis = { elapsed },
        )

        // The first refresh of a process performs the restore; a lifecycleScope torn down on
        // rotation is a routine way to cancel it exactly there.
        val first = async(start = CoroutineStart.UNDISPATCHED) { coordinator.refresh() }
        first.cancelAndJoin()
        gate.complete(Unit)

        val second = withTimeoutOrNull(5_000) { coordinator.refresh() }

        assertNotNull("the abandoned flight was never retired", second)
        assertEquals("after", second!!.accessToken)
        assertEquals(1, tokenClient.refreshCalls.size)
    }

    @Test
    fun `a refresh in flight during logout cannot re-persist the grant after the wipe`() = runTest {
        val pendingStore = RecordingPendingStore()
        val browser = FixedRedirectBrowser(pendingStore)
        val credentialStore = FakeCredentialStore().apply { refreshToken = stored() }
        val responseGate = CompletableDeferred<Unit>()
        val tokenClient = FakeTokenClient().apply {
            refreshActions = mutableListOf({ responseGate.await(); issued(accessToken = "late") })
        }
        val coordinator = SessionCoordinator(
            authFlow(pendingStore, credentialStore, browser), tokenClient, credentialStore,
            elapsedMillis = { elapsed },
            onCredentialsWiped = { teardowns++ },
        )
        val refreshing = async(start = CoroutineStart.UNDISPATCHED) { runCatching { coordinator.refresh() } }
        // logout() lets the flight finish before it revokes, so the server's answer is in
        // before the wipe — and whatever it answered is wiped with everything else.
        val loggingOut = async(start = CoroutineStart.UNDISPATCHED) { coordinator.logout() }
        responseGate.complete(Unit)
        loggingOut.await()
        refreshing.await()

        assertNull("grant re-persisted after logout", credentialStore.refreshToken)
        assertNull(coordinator.currentAccessToken())
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
        // The late answer was persisted (the flight finished first) and then wiped — never
        // the other way round.
        assertEquals(1, credentialStore.clears)
        assertTrue(credentialStore.events.contains("replaceRefreshToken"))
        assertTrue(refreshing.await().isSuccess)
    }

    @Test
    fun `stepUpRequired publishes StepUpRequired over the live grant, and a cancelled step-up settles on Authenticated`() = runTest {
        val pendingStore = RecordingPendingStore()
        val browser = FixedRedirectBrowser(pendingStore)
        val (coordinator, _, credentialStore) = coordinator(pendingStore, browser = browser)
        credentialStore.refreshToken = stored()
        assertEquals(SessionState.Authenticated, coordinator.sessionState.first())

        coordinator.stepUpRequired()
        assertEquals(SessionState.StepUpRequired, coordinator.sessionState.first())

        browser.loginOutcome = { BrowserOutcome.UserCancelled }
        failure { coordinator.login(setOf("openid"), acrValues = listOf("mfa")) }

        // The grant is intact; UI bound to the state must not show a login screen over it.
        assertEquals(SessionState.Authenticated, coordinator.sessionState.first())
        assertNotNull(credentialStore.refreshToken)
        assertNull(pendingStore.stored)
    }

    // ---- logout() ----------------------------------------------------------------------

    @Test
    fun `logout revokes, ends the server session, wipes, and settles Unauthenticated`() = runTest {
        val pendingStore = RecordingPendingStore()
        val browser = FixedRedirectBrowser(pendingStore)
        val (coordinator, tokenClient, credentialStore) = coordinator(pendingStore, browser = browser)
        credentialStore.refreshToken = stored()
        credentialStore.rawIdToken = "the.id.token"
        // `MutableStateFlow` conflates, so the transition into `LoggingOut` is observed from
        // inside the browser leg — the one moment it is guaranteed to be the current state —
        // rather than from a collector racing the transitions out of it.
        var stateWhileBrowserOpen: SessionState? = null
        var revokedBeforeBrowser = false
        val defaultOutcome = browser.logoutOutcome
        browser.logoutOutcome = { uri ->
            stateWhileBrowserOpen = coordinator.sessionState.first()
            revokedBeforeBrowser = tokenClient.revokeCalls.size == 1
            defaultOutcome(uri)
        }
        assertEquals(SessionState.Authenticated, coordinator.sessionState.first())

        val acknowledged = coordinator.logout().sessionEnded

        assertTrue(acknowledged)
        // Scenario 18, in order: the refresh token is revoked before the browser opens, so a
        // dismissed signed-out page still leaves a dead grant behind at the server.
        assertTrue(revokedBeforeBrowser)
        assertEquals("grant", tokenClient.revokeCalls.single().toString(Charsets.UTF_8))
        val logoutUri = browser.launched.single()
        assertTrue(logoutUri.startsWith("$ISSUER/logout?"))
        assertTrue(logoutUri.contains("id_token_hint=the.id.token"))
        assertTrue(logoutUri.contains("&state="))
        assertEquals(SessionState.LoggingOut, stateWhileBrowserOpen)
        // Everything credential-shaped is gone, including what lives outside this module.
        assertNull(credentialStore.refreshToken)
        assertNull(credentialStore.rawIdToken)
        assertNull(credentialStore.pendingRotationSlot)
        assertEquals(1, credentialStore.clears)
        assertEquals(1, pendingStore.clears)
        assertEquals(1, teardowns)
        assertNull(coordinator.currentAccessToken())
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
    }

    @Test
    fun `logout wipes locally even when revocation fails`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        credentialStore.refreshToken = stored()
        tokenClient.revokeFailure = {
            VersolaError.Recoverable(VersolaError.Recoverable.Cause.Network("revocation endpoint returned HTTP 503"))
        }

        coordinator.logout()

        assertNull(credentialStore.refreshToken)
        assertEquals(1, teardowns)
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
    }

    @Test
    fun `logout wipes locally even when the browser is dismissed mid-flow`() = runTest {
        val pendingStore = RecordingPendingStore()
        val browser = FixedRedirectBrowser(pendingStore).apply {
            logoutOutcome = { BrowserOutcome.UserCancelled }
        }
        val (coordinator, _, credentialStore) = coordinator(pendingStore, browser = browser)
        credentialStore.refreshToken = stored()

        val acknowledged = coordinator.logout().sessionEnded

        // Scenario 18's last assertion: dismissing the browser mid-logout still leaves the
        // app Unauthenticated locally. Only the server-side teardown is best effort, and the
        // return value is how that is reported.
        assertFalse(acknowledged)
        assertNull(credentialStore.refreshToken)
        assertEquals(1, teardowns)
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
    }

    @Test
    fun `logout wipes locally even when the browser cannot be opened at all`() = runTest {
        val pendingStore = RecordingPendingStore()
        val browser = FixedRedirectBrowser(pendingStore).apply {
            logoutOutcome = {
                throw VersolaError.Configuration(VersolaError.Configuration.Detail.NoBrowserAvailable)
            }
        }
        val (coordinator, _, credentialStore) = coordinator(pendingStore, browser = browser)
        credentialStore.refreshToken = stored()

        assertFalse(coordinator.logout().sessionEnded)

        assertNull(credentialStore.refreshToken)
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
    }

    @Test
    fun `a redirect carrying another state does not count as the server acknowledging`() = runTest {
        val pendingStore = RecordingPendingStore()
        val browser = FixedRedirectBrowser(pendingStore).apply {
            logoutOutcome = { BrowserOutcome.Redirect("https://app.example.com/signed-out?state=stale") }
        }
        val (coordinator, _, credentialStore) = coordinator(pendingStore, browser = browser)
        credentialStore.refreshToken = stored()

        assertFalse(coordinator.logout().sessionEnded)
        assertNull(credentialStore.refreshToken)
    }

    @Test
    fun `logout without a readable id token still ends the session, without the hint`() = runTest {
        val pendingStore = RecordingPendingStore()
        val browser = FixedRedirectBrowser(pendingStore)
        val (coordinator, _, credentialStore) = coordinator(pendingStore, browser = browser)
        credentialStore.refreshToken = stored()
        credentialStore.rawIdToken = null

        coordinator.logout()

        assertFalse(browser.launched.single().contains("id_token_hint"))
        assertNull(credentialStore.refreshToken)
    }

    @Test
    fun `a failing teardown does not stop the sign-out`() = runTest {
        val (coordinator, _, credentialStore) = coordinator()
        credentialStore.refreshToken = stored()
        teardownFailure = { IllegalStateException("Keystore refused to delete the key") }

        coordinator.logout()

        assertNull(credentialStore.refreshToken)
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
    }

    @Test
    fun `logout cancelled mid-flight still wipes`() = runTest {
        val pendingStore = RecordingPendingStore()
        val browserOpened = CompletableDeferred<Unit>()
        val browser = FixedRedirectBrowser(pendingStore).apply {
            // The browser leg is where a logout spends its time, and where the caller's
            // scope is most likely to go away: a screen torn down while the Custom Tab is up.
            logoutOutcome = { browserOpened.complete(Unit); awaitCancellation() }
        }
        val (coordinator, tokenClient, credentialStore) = coordinator(pendingStore, browser = browser)
        credentialStore.refreshToken = stored()

        val job = launch(start = CoroutineStart.UNDISPATCHED) { coordinator.logout() }
        browserOpened.await()
        job.cancelAndJoin()

        assertEquals(1, tokenClient.revokeCalls.size)
        assertNull(credentialStore.refreshToken)
        assertEquals(1, teardowns)
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
    }

    @Test
    fun `invalid_grant on refresh tears the DPoP key down like a logout`() = runTest {
        val (coordinator, tokenClient, credentialStore) = coordinator()
        credentialStore.refreshToken = stored()
        tokenClient.refreshActions = mutableListOf({
            throw VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.GrantRejected)
        })

        failure { coordinator.refresh() }

        // `Refreshing → Unauthenticated` in spec/state-machine.md: "the DPoP key follows the
        // logout rule". Same wipe, same hook, no separate path to drift.
        assertNull(credentialStore.refreshToken)
        assertEquals(1, teardowns)
        assertEquals(SessionState.Unauthenticated, coordinator.sessionState.first())
    }

    private suspend fun failure(block: suspend () -> Unit): VersolaError = try {
        block()
        throw AssertionError("expected a VersolaError")
    } catch (e: VersolaError) {
        e
    }
}
