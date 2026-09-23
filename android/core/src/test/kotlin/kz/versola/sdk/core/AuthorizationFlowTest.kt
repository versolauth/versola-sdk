package kz.versola.sdk.core

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

private const val ISSUER = "https://id.versola.kz"

private class RecordingStore(var stored: PendingAuthorizationRequest? = null) : PendingAuthorizationStore {
    var saves = 0
    var clears = 0

    override suspend fun save(request: PendingAuthorizationRequest) {
        saves++
        stored = request
    }

    override suspend fun load(): PendingAuthorizationRequest? = stored

    override suspend fun clear() {
        clears++
        stored = null
    }
}

/**
 * Answers with whatever the test queued, and records the URI it was asked to open — which is
 * how "the pending request was persisted before the browser opened" becomes assertable.
 */
private class FakeBrowser(
    private val outcome: (String) -> BrowserOutcome,
    private val store: RecordingStore,
) : BrowserAuthorizationSession {
    var launchedUri: String? = null
    var savesAtLaunch: Int = -1
    var awaitedPendingRedirect = false

    override suspend fun authorize(uri: String): BrowserOutcome {
        launchedUri = uri
        savesAtLaunch = store.saves
        return outcome(uri)
    }

    override suspend fun awaitPendingRedirect(): BrowserOutcome {
        awaitedPendingRedirect = true
        return outcome("")
    }
}

/**
 * Stands in for the Keystore key of `:dpop`, which this module deliberately cannot see: the
 * only thing the protocol core needs from it is a thumbprint.
 */
private object StaticDpopKey : DpopKeyBinding {
    const val thumbprint: String = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
    override suspend fun jkt(): String = thumbprint
}

private class StaticDiscovery(private val metadata: ProviderMetadata) : DiscoveryClient {
    override suspend fun fetch(issuer: String): ProviderMetadata = metadata
}

private class MemoryMetadataCache : ProviderMetadataCache {
    private var metadata: ProviderMetadata? = null
    override suspend fun load(): ProviderMetadata? = metadata
    override suspend fun save(metadata: ProviderMetadata) {
        this.metadata = metadata
    }
    override suspend fun clear() {
        metadata = null
    }
}

class AuthorizationFlowTest {

    private val metadata = ProviderMetadata(
        issuer = ISSUER,
        authorizationEndpoint = "$ISSUER/authorize",
        tokenEndpoint = "$ISSUER/token",
        dpopSigningAlgValuesSupported = listOf("ES256"),
        authorizationResponseIssParameterSupported = true,
    )

    private val configuration = VersolaConfiguration.create(
        issuer = ISSUER,
        clientId = "mobile-app",
        redirectUri = "https://app.example.com/oauth",
    )

    private fun flow(
        store: RecordingStore,
        browser: BrowserAuthorizationSession,
        now: Long = 0,
        metadata: ProviderMetadata = this.metadata,
        tokenBinding: TokenBinding = TokenBinding.Dpop(),
        dpopKey: DpopKeyBinding? = StaticDpopKey,
    ) = AuthorizationFlow(
        configuration = configuration,
        discovery = DiscoveryService(ISSUER, StaticDiscovery(metadata), MemoryMetadataCache()),
        pendingStore = store,
        browser = browser,
        tokenBinding = tokenBinding,
        dpopKey = dpopKey,
        clock = { now },
    )

    /** A provider of the previous generation: everything but `dpop_signing_alg_values_supported`. */
    private fun withoutDpop() = metadata.copy(dpopSigningAlgValuesSupported = emptyList())

    private fun redirectFor(store: RecordingStore, extra: String = "&iss=$ISSUER"): (String) -> BrowserOutcome =
        { BrowserOutcome.Redirect("https://app.example.com/oauth?code=the-code&state=${store.stored!!.state}$extra") }

    @Test
    fun `a validated redirect yields a grant carrying the verifier that was persisted`() = runTest {
        val store = RecordingStore()
        val browser = FakeBrowser(redirectFor(store), store)

        val grant = flow(store, browser).authorize(setOf("openid", "profile"))

        assertEquals("the-code", grant.code)
        assertEquals(store.stored!!.codeVerifier, grant.codeVerifier.value)
        assertEquals(setOf("openid", "profile"), grant.scopes)
    }

    @Test
    fun `the pending request is persisted before the browser opens`() = runTest {
        // The kill lands between the two often enough that AppAuth's in-memory version is the
        // documented reason mobile-demo rejected flutter_appauth. Order, not presence.
        val store = RecordingStore()
        val browser = FakeBrowser(redirectFor(store), store)

        flow(store, browser).authorize(setOf("openid"))

        assertEquals(1, browser.savesAtLaunch)
    }

    @Test
    fun `the pending request outlives a successful validation`() = runTest {
        // The slot is wiped only after a refresh token is durably stored, which is #8's
        // business. Wiping it here would lose the flow if the exchange never completed.
        val store = RecordingStore()
        val browser = FakeBrowser(redirectFor(store), store)

        flow(store, browser).authorize(setOf("openid"))

        assertEquals(0, store.clears)
    }

    @Test
    fun `a user cancel wipes the pending request and settles Unauthenticated`() = runTest {
        val store = RecordingStore()
        val browser = FakeBrowser({ BrowserOutcome.UserCancelled }, store)
        val flow = flow(store, browser)

        val error = failure { flow.authorize(setOf("openid")) } as VersolaError.Recoverable

        assertEquals(VersolaError.Recoverable.Cause.UserCancelled, error.reason)
        assertNull(store.stored)
        assertSame(SessionState.Unauthenticated, flow.sessionState.first())
    }

    @Test
    fun `a state mismatch reaches no token endpoint and discards the pending request`() = runTest {
        // Scenario 15. There is no token client here to reach, which is the point: the
        // failure is raised by validation, before any exchange could be attempted.
        val store = RecordingStore()
        val browser = FakeBrowser(
            { BrowserOutcome.Redirect("https://app.example.com/oauth?code=c&state=not-the-state") },
            store,
        )
        val flow = flow(store, browser)

        val error = failure { flow.authorize(setOf("openid")) } as VersolaError.Configuration

        assertEquals(VersolaError.Configuration.Detail.StateMismatch, error.detail)
        assertNull(store.stored)
        assertSame(SessionState.Unauthenticated, flow.sessionState.first())
    }

    @Test
    fun `an iss mismatch is treated the same way`() = runTest {
        // Scenario 16.
        val store = RecordingStore()
        val browser = FakeBrowser(redirectFor(store, extra = "&iss=https://evil.example"), store)
        val flow = flow(store, browser)

        val error = failure { flow.authorize(setOf("openid")) } as VersolaError.Configuration

        assertTrue(error.detail is VersolaError.Configuration.Detail.IssuerMismatch)
        assertNull(store.stored)
    }

    @Test
    fun `a cold start with a pending request observes Authorizing, never Unauthenticated`() = runTest {
        // Scenario 12: the app was killed while the browser was foreground. The first value
        // the app sees must already be Authorizing.
        val store = RecordingStore(
            PendingAuthorizationRequest(
                state = "restored-state",
                nonce = "restored-nonce",
                codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                scopes = listOf("openid"),
                redirectUri = "https://app.example.com/oauth",
                acrValues = emptyList(),
                maxAge = null,
                createdAtEpochMillis = 0,
            ),
        )
        val browser = FakeBrowser({ BrowserOutcome.UserCancelled }, store)

        val first = flow(store, browser, now = 1_000).sessionState.first()

        assertSame(SessionState.Authorizing, first)
    }

    @Test
    fun `a redirect delivered to a cold-started process completes against the restored request`() = runTest {
        // The state is validated against the restored value and the restored verifier comes
        // back in the grant — the two assertions scenario 12 makes about the exchange.
        val restored = PendingAuthorizationRequest(
            state = "restored-state",
            nonce = "restored-nonce",
            codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            scopes = listOf("openid"),
            redirectUri = "https://app.example.com/oauth",
            acrValues = emptyList(),
            maxAge = null,
            createdAtEpochMillis = 0,
        )
        val store = RecordingStore(restored)
        val browser = FakeBrowser(
            { BrowserOutcome.Redirect("https://app.example.com/oauth?code=c&state=restored-state&iss=$ISSUER") },
            store,
        )

        val grant = flow(store, browser, now = 1_000).resumePendingAuthorization()

        assertTrue(browser.awaitedPendingRedirect)
        assertEquals("c", grant!!.code)
        assertEquals(restored.codeVerifier, grant.codeVerifier.value)
    }

    @Test
    fun `resuming with nothing pending returns null rather than opening a browser`() = runTest {
        val store = RecordingStore()
        val browser = FakeBrowser({ BrowserOutcome.UserCancelled }, store)

        assertNull(flow(store, browser).resumePendingAuthorization())
        assertNull(browser.launchedUri)
    }

    @Test
    fun `a pending request older than ten minutes is discarded instead of resumed`() = runTest {
        val store = RecordingStore(
            PendingAuthorizationRequest(
                state = "old",
                nonce = "old",
                codeVerifier = "old",
                scopes = listOf("openid"),
                redirectUri = "https://app.example.com/oauth",
                acrValues = emptyList(),
                maxAge = null,
                createdAtEpochMillis = 0,
            ),
        )
        val browser = FakeBrowser({ BrowserOutcome.UserCancelled }, store)
        val flow = flow(store, browser, now = PendingAuthorizationRequest.MAX_AGE_MILLIS)

        val error = failure { flow.resumePendingAuthorization() } as VersolaError.Recoverable

        assertEquals(VersolaError.Recoverable.Cause.PendingRequestExpired, error.reason)
        assertNull(store.stored)
        assertSame(SessionState.Unauthenticated, flow.sessionState.first())
    }

    @Test
    fun `an expired pending request leaves a cold start Unauthenticated`() = runTest {
        val store = RecordingStore(
            PendingAuthorizationRequest(
                state = "old",
                nonce = "old",
                codeVerifier = "old",
                scopes = listOf("openid"),
                redirectUri = "https://app.example.com/oauth",
                acrValues = emptyList(),
                maxAge = null,
                createdAtEpochMillis = 0,
            ),
        )
        val browser = FakeBrowser({ BrowserOutcome.UserCancelled }, store)

        val first = flow(store, browser, now = PendingAuthorizationRequest.MAX_AGE_MILLIS).sessionState.first()

        assertSame(SessionState.Unauthenticated, first)
    }

    @Test
    fun `the browser is opened at the endpoint discovery advertised`() = runTest {
        val store = RecordingStore()
        val browser = FakeBrowser(redirectFor(store), store)

        flow(store, browser).authorize(setOf("openid"))

        assertTrue(browser.launchedUri!!.startsWith("$ISSUER/authorize?"))
    }

    @Test
    fun `dpop_jkt commits the request to the key the code will be redeemed against`() = runTest {
        // RFC 9449 §10. Without it the commitment happens only at redemption, so a stolen
        // code can be redeemed against the thief's key instead of this device's.
        val store = RecordingStore()
        val browser = FakeBrowser(redirectFor(store), store)

        flow(store, browser).authorize(setOf("openid"))

        assertTrue(browser.launchedUri!!.contains("dpop_jkt=${StaticDpopKey.thumbprint}"))
    }

    @Test
    fun `a provider that does not advertise DPoP gets no dpop_jkt`() = runTest {
        // Scenario 07. Committing to a key the token endpoint will then redeem without a
        // proof binds nothing, and `AuthorizeRequestParser` is entitled to refuse the
        // parameter outright.
        val store = RecordingStore()
        val browser = FakeBrowser(redirectFor(store), store)

        flow(store, browser, metadata = withoutDpop()).authorize(setOf("openid"))

        assertFalse(browser.launchedUri!!.contains("dpop_jkt"))
    }

    @Test
    fun `Bearer sends no dpop_jkt even where the provider supports DPoP`() = runTest {
        val store = RecordingStore()
        val browser = FakeBrowser(redirectFor(store), store)

        flow(store, browser, tokenBinding = TokenBinding.Bearer).authorize(setOf("openid"))

        assertFalse(browser.launchedUri!!.contains("dpop_jkt"))
    }

    @Test
    fun `requireHardware against a provider without DPoP fails before the browser opens`() = runTest {
        // Scenario 07's last assertion. The app asked for a guarantee this deployment cannot
        // give; finding that out at the first API call instead would be worse, and finding it
        // out after a user has already signed in worse still.
        val store = RecordingStore()
        val browser = FakeBrowser(redirectFor(store), store)
        val flow = flow(
            store,
            browser,
            metadata = withoutDpop(),
            tokenBinding = TokenBinding.Dpop(requireHardware = true),
        )

        val error = failure { flow.authorize(setOf("openid")) } as VersolaError.Configuration

        assertTrue(error.detail is VersolaError.Configuration.Detail.HardwareBindingUnavailable)
        assertNull(browser.launchedUri)
        assertNull(store.stored)
    }

    @Test
    fun `a browser that fails to launch leaves nothing pending for a later cold start`() = runTest {
        // If browser.authorize() throws (notably NoBrowserAvailable) before any browser ever
        // opened, the persisted request and Authorizing state must not survive it — otherwise a
        // later cold start looks resumable and waits forever for a redirect that cannot exist.
        val store = RecordingStore()
        val launchFailure = VersolaError.Configuration(VersolaError.Configuration.Detail.NoBrowserAvailable)
        val browser = object : BrowserAuthorizationSession {
            override suspend fun authorize(uri: String): BrowserOutcome = throw launchFailure
            override suspend fun awaitPendingRedirect(): BrowserOutcome = error("not used")
        }
        val flow = flow(store, browser)

        val thrown = failure { flow.authorize(setOf("openid")) }

        assertSame(launchFailure, thrown)
        assertNull(store.stored)
        assertEquals(1, store.clears)
        assertSame(SessionState.Unauthenticated, flow.sessionState.first())
    }

    @Test
    fun `concurrent authorize calls are serialized rather than racing on the shared slot`() = runTest {
        // There is exactly one persisted slot and one process-wide redirect channel behind a
        // real BrowserAuthorizationSession. If two authorize() calls interleaved, the second's
        // save could overwrite the first's pending request before the first's redirect arrives,
        // corrupting whichever flow resolves second. Serializing is what keeps "one slot" true.
        val store = RecordingStore()
        val firstEnteredBrowser = CompletableDeferred<Unit>()
        val releaseFirst = CompletableDeferred<Unit>()
        val browser = object : BrowserAuthorizationSession {
            var calls = 0
            override suspend fun authorize(uri: String): BrowserOutcome {
                calls++
                val state = Regex("state=([^&]+)").find(uri)!!.groupValues[1]
                if (calls == 1) {
                    firstEnteredBrowser.complete(Unit)
                    releaseFirst.await()
                }
                return BrowserOutcome.Redirect(
                    "https://app.example.com/oauth?code=call-$calls&state=$state&iss=$ISSUER",
                )
            }
            override suspend fun awaitPendingRedirect(): BrowserOutcome = error("not used")
        }
        val flow = flow(store, browser)

        val firstResult = async { flow.authorize(setOf("openid")) }
        firstEnteredBrowser.await()
        // The first call now holds authorizeLock, suspended inside browser.authorize(). A
        // second call must not be able to reach pendingStore.save() while that holds.
        val secondResult = async { flow.authorize(setOf("profile")) }
        runCurrent()
        assertEquals(1, store.saves)
        assertEquals(1, browser.calls)

        releaseFirst.complete(Unit)
        val first = firstResult.await()
        val second = secondResult.await()

        assertEquals("call-1", first.code)
        assertEquals("call-2", second.code)
        assertEquals(2, store.saves)
    }
}
