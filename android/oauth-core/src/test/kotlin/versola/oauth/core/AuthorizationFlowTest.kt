package versola.oauth.core

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
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

/** A starter that keeps the verifier elsewhere, the way a facade's back channel does. */
private class FakeStarter : AuthorizationStarter {
    val requests = mutableListOf<AuthorizationRequest>()
    var failure: (() -> VersolaError)? = null

    override suspend fun start(
        request: AuthorizationRequest,
        metadata: ProviderMetadata,
        nowEpochMillis: Long,
    ): StartedAuthorization {
        requests += request
        failure?.let { throw it() }
        val pending = PendingAuthorizationRequest(
            state = "starter-state-${requests.size}",
            nonce = request.nonce,
            codeVerifier = "",
            scopes = request.scopes.toList(),
            redirectUri = "https://app.example.com/oauth",
            acrValues = request.acrValues,
            maxAge = request.maxAge,
            createdAtEpochMillis = nowEpochMillis,
            extension = mapOf("artefact" to "sealed-${requests.size}"),
            issRequired = true,
        )
        val uri = metadata.authorizationEndpoint + "?client_id=mobile-app&request_uri=urn%3Astarter%3Aabc"
        return StartedAuthorization(pending, uri)
    }
}

class AuthorizationFlowTest {

    private val metadata = ProviderMetadata(
        issuer = ISSUER,
        authorizationEndpoint = "$ISSUER/authorize",
        tokenEndpoint = "$ISSUER/token",
        endSessionEndpoint = "$ISSUER/logout",
        dpopSigningAlgValuesSupported = listOf("ES256"),
        authorizationResponseIssParameterSupported = true,
    )

    private val configuration = VersolaConfiguration.create(
        issuer = ISSUER,
        clientId = "mobile-app",
        redirectUri = "https://app.example.com/oauth",
        postLogoutRedirectUri = "https://app.example.com/signed-out",
    )

    private fun flow(
        store: RecordingStore,
        browser: BrowserAuthorizationSession,
        now: Long = 0,
        metadata: ProviderMetadata = this.metadata,
        tokenBinding: TokenBinding = TokenBinding.Dpop(),
        dpopKey: DpopKeyBinding? = StaticDpopKey,
        starter: AuthorizationStarter? = null,
        configuration: VersolaConfiguration = this.configuration,
        hasStoredGrant: (suspend () -> Boolean)? = null,
    ) = if (hasStoredGrant == null) {
        AuthorizationFlow(
            configuration = configuration,
            discovery = DiscoveryService(ISSUER, StaticDiscovery(metadata), MemoryMetadataCache()),
            pendingStore = store,
            browser = browser,
            tokenBinding = tokenBinding,
            dpopKey = dpopKey,
            clock = { now },
            starter = starter,
        )
    } else {
        AuthorizationFlow(
            configuration = configuration,
            discovery = DiscoveryService(ISSUER, StaticDiscovery(metadata), MemoryMetadataCache()),
            pendingStore = store,
            browser = browser,
            tokenBinding = tokenBinding,
            dpopKey = dpopKey,
            clock = { now },
            hasStoredGrant = hasStoredGrant,
            starter = starter,
        )
    }

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
    fun `a key-bound session wired without a key is refused at construction`() = runTest {
        // Otherwise it authorizes with no dpop_jkt and skips the requireHardware check along
        // with it: an app that asked to be bound to hardware gets an unbound code and is
        // never told. The wiring is wrong, so it fails where the wiring happens.
        val store = RecordingStore()
        val browser = FakeBrowser(redirectFor(store), store)

        val error = assertThrows(VersolaError.Configuration::class.java) {
            flow(store, browser, tokenBinding = TokenBinding.Dpop(requireHardware = true), dpopKey = null)
        }

        assertTrue(error.detail is VersolaError.Configuration.Detail.InvalidConfiguration)
    }

    @Test
    fun `a flow given no key is a Bearer flow rather than a broken DPoP one`() = runTest {
        val store = RecordingStore()
        val browser = FakeBrowser(redirectFor(store), store)
        val flow = AuthorizationFlow(
            configuration = configuration,
            discovery = DiscoveryService(ISSUER, StaticDiscovery(metadata), MemoryMetadataCache()),
            pendingStore = store,
            browser = browser,
        )

        flow.authorize(setOf("openid"))

        assertFalse(browser.launchedUri!!.contains("dpop_jkt"))
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
        // The first call now holds the authorize lock, suspended inside browser.authorize().
        // A second call must not be able to reach pendingStore.save() while that holds.
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

    @Test
    fun `two flows over one store are serialized, not only two calls on one flow`() = runTest {
        // Nothing stops an app calling Versola.configure() twice, and the second result is not
        // a second slot: the default store is one file under noBackupFilesDir and the redirect
        // arrives through one process-wide dispatcher. An instance-scoped lock would leave the
        // two free to overwrite each other's pending request and consume each other's redirect,
        // so the lock has to be as wide as the resource it protects.
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

        val firstResult = async { flow(store, browser).authorize(setOf("openid")) }
        firstEnteredBrowser.await()
        val secondResult = async { flow(store, browser).authorize(setOf("profile")) }
        runCurrent()
        assertEquals(1, store.saves)

        releaseFirst.complete(Unit)

        assertEquals("call-1", firstResult.await().code)
        assertEquals("call-2", secondResult.await().code)
    }

    @Test
    fun `a cancelled caller leaves the pending request for a later resume`() = runTest {
        // CancellationException is an Exception, so the launch-failure cleanup above would
        // otherwise run for it too. The browser is already in the foreground by then and its
        // redirect can still arrive — wiping the slot loses an authorization the user may have
        // completed, and leaves resumePendingAuthorization() nothing to finish.
        val store = RecordingStore()
        val entered = CompletableDeferred<Unit>()
        val browser = object : BrowserAuthorizationSession {
            override suspend fun authorize(uri: String): BrowserOutcome {
                entered.complete(Unit)
                awaitCancellation()
            }
            override suspend fun awaitPendingRedirect(): BrowserOutcome =
                BrowserOutcome.Redirect(
                    "https://app.example.com/oauth?code=resumed&state=${store.stored!!.state}&iss=$ISSUER",
                )
        }
        val flow = flow(store, browser)

        val caller = launch { flow.authorize(setOf("openid")) }
        entered.await()
        caller.cancelAndJoin()

        assertEquals(0, store.clears)
        assertSame(SessionState.Authorizing, flow.sessionState.first())
        assertEquals("resumed", flow.resumePendingAuthorization()!!.code)
    }

    @Test
    fun `the tab a cancelled caller abandoned cannot fail the authorization that replaced it`() = runTest {
        // Releasing the lock on cancellation lets a new authorize() start while the old tab is
        // still open, and that tab can redirect after the new call has drained whatever was
        // buffered. Its state is one this process issued, so treating it as a mismatch would
        // lose a live authorization to a tab the user had already walked away from.
        val store = RecordingStore()
        val entered = CompletableDeferred<Unit>()
        val abandonedBrowser = object : BrowserAuthorizationSession {
            override suspend fun authorize(uri: String): BrowserOutcome {
                entered.complete(Unit)
                awaitCancellation()
            }
            override suspend fun awaitPendingRedirect(): BrowserOutcome = error("not used")
        }
        val flow = flow(store, abandonedBrowser)
        val caller = launch { flow.authorize(setOf("openid")) }
        entered.await()
        caller.cancelAndJoin()
        val abandonedState = store.stored!!.state

        // The replacement opens its own tab; the abandoned one redirects into it first.
        val replacement = object : BrowserAuthorizationSession {
            var pendingRedirects = 0
            override suspend fun authorize(uri: String): BrowserOutcome = BrowserOutcome.Redirect(
                "https://app.example.com/oauth?code=stale&state=$abandonedState&iss=$ISSUER",
            )
            override suspend fun awaitPendingRedirect(): BrowserOutcome {
                pendingRedirects++
                return BrowserOutcome.Redirect(
                    "https://app.example.com/oauth?code=mine&state=${store.stored!!.state}&iss=$ISSUER",
                )
            }
        }

        val grant = flow(store, replacement).authorize(setOf("openid"))

        assertEquals("mine", grant.code)
        assertEquals(1, replacement.pendingRedirects)
    }

    @Test
    fun `a redirect for a state this process never issued is still a mismatch`() = runTest {
        // The stale-redirect skip is not a relaxation of the state check: only a state this
        // process itself abandoned is stepped over, and only once.
        val store = RecordingStore()
        val browser = FakeBrowser(
            { BrowserOutcome.Redirect("https://app.example.com/oauth?code=c&state=someone-elses&iss=$ISSUER") },
            store,
        )
        val flow = flow(store, browser)

        val error = failure { flow.authorize(setOf("openid")) } as VersolaError.Configuration

        assertSame(VersolaError.Configuration.Detail.StateMismatch, error.detail)
    }

    // ---- endSession() ------------------------------------------------------------------

    private fun stateOf(uri: String): String = Regex("[?&]state=([^&]+)").find(uri)!!.groupValues[1]

    @Test
    fun `endSession opens the end_session_endpoint with the hint, the redirect and a state`() = runTest {
        val store = RecordingStore()
        val browser = FakeBrowser({ uri -> BrowserOutcome.Redirect("https://app.example.com/signed-out?state=${stateOf(uri)}") }, store)

        val acknowledged = flow(store, browser).endSession("the.id.token")

        assertTrue(acknowledged)
        val uri = browser.launchedUri!!
        assertTrue(uri.startsWith("$ISSUER/logout?"))
        assertTrue(uri.contains("id_token_hint=the.id.token"))
        assertTrue(uri.contains("post_logout_redirect_uri=https%3A%2F%2Fapp.example.com%2Fsigned-out"))
        assertTrue(stateOf(uri).length >= 22)
    }

    @Test
    fun `endSession omits what it does not have rather than sending an empty parameter`() = runTest {
        val store = RecordingStore()
        val browser = FakeBrowser({ uri -> BrowserOutcome.Redirect("https://x?state=${stateOf(uri)}") }, store)
        val withoutRedirect = AuthorizationFlow(
            configuration = VersolaConfiguration.create(ISSUER, "mobile-app", "https://app.example.com/oauth"),
            discovery = DiscoveryService(ISSUER, StaticDiscovery(metadata), MemoryMetadataCache()),
            pendingStore = store,
            browser = browser,
            dpopKey = StaticDpopKey,
        )

        withoutRedirect.endSession(null)

        val uri = browser.launchedUri!!
        assertFalse(uri.contains("id_token_hint"))
        assertFalse(uri.contains("post_logout_redirect_uri"))
        assertTrue(uri.contains("state="))
    }

    @Test
    fun `a provider without an end_session_endpoint has no server session to end`() = runTest {
        val store = RecordingStore()
        val browser = FakeBrowser({ BrowserOutcome.UserCancelled }, store)

        val acknowledged = flow(store, browser, metadata = metadata.copy(endSessionEndpoint = null)).endSession("hint")

        assertFalse(acknowledged)
        assertNull(browser.launchedUri)
    }

    @Test
    fun `a dismissed signed-out page and a stale redirect are both not acknowledged`() = runTest {
        val store = RecordingStore()

        assertFalse(flow(store, FakeBrowser({ BrowserOutcome.UserCancelled }, store)).endSession("hint"))
        assertFalse(
            flow(store, FakeBrowser({ BrowserOutcome.Redirect("https://app.example.com/signed-out?state=stale") }, store))
                .endSession("hint"),
        )
    }

    @Test
    fun `endSession does not touch the pending request or the state machine`() = runTest {
        // The wipe is the coordinator's and happens whatever this returns; the browser leg
        // itself must not pre-empt it by clearing a slot or publishing a state of its own.
        val pending = PendingAuthorizationRequest("s", "n", "v", listOf("openid"), "https://app.example.com/oauth", emptyList(), null, 0)
        val store = RecordingStore(stored = pending)
        val browser = FakeBrowser({ BrowserOutcome.UserCancelled }, store)
        val flow = flow(store, browser)

        flow.endSession("hint")

        assertSame(pending, store.stored)
        assertEquals(0, store.clears)
        assertEquals(SessionState.Authorizing, flow.sessionState.first())
    }

    // ---- AuthorizationStarter seam --------------------------------------------------------

    @Test
    fun `a starter decides what is persisted and what the browser opens`() = runTest {
        val store = RecordingStore()
        val browser = FakeBrowser(redirectFor(store), store)
        val starter = FakeStarter()

        val grant = flow(store, browser, starter = starter).authorize(setOf("openid"), listOf("mfa"), 300)

        // What the starter was asked: the request as built here, PKCE included, for it to use
        // or discard.
        val asked = starter.requests.single()
        assertEquals(setOf("openid"), asked.scopes)
        assertEquals(listOf("mfa"), asked.acrValues)
        assertEquals(300L, asked.maxAge)
        // The browser opens on what the starter returned, and nothing of this class's own
        // request leaks into it.
        val uri = browser.launchedUri!!
        assertTrue(uri.startsWith("$ISSUER/authorize?"))
        assertTrue(uri.contains("request_uri=urn%3Astarter%3Aabc"))
        assertFalse(uri.contains("code_challenge"))
        assertFalse(uri.contains("dpop_jkt"))
        // Persisted before the browser opened, and it is the starter's state the redirect is
        // held to; what it left for the exchange travels on the grant unchanged.
        assertEquals(1, browser.savesAtLaunch)
        assertEquals("starter-state-1", grant.state)
        assertEquals(mapOf("artefact" to "sealed-1"), grant.extension)
        assertEquals(ISSUER, grant.iss)
        assertEquals("", grant.codeVerifier.value)
    }

    @Test
    fun `a starter that requires iss makes a redirect without one a failure, whatever discovery advertises`() = runTest {
        val store = RecordingStore()
        val browser = FakeBrowser(redirectFor(store, extra = ""), store)
        val quiet = metadata.copy(authorizationResponseIssParameterSupported = false)

        val error = failure {
            flow(store, browser, metadata = quiet, starter = FakeStarter()).authorize(setOf("openid"))
        } as VersolaError.Configuration

        assertTrue(error.detail is VersolaError.Configuration.Detail.IssuerMismatch)
        assertEquals(1, store.clears)
    }

    @Test
    fun `a failed start leaves nothing pending and the session Unauthenticated`() = runTest {
        val store = RecordingStore()
        val browser = FakeBrowser(redirectFor(store), store)
        val starter = FakeStarter().apply {
            failure = {
                VersolaError.Configuration(VersolaError.Configuration.Detail.InvalidConfiguration("the back channel refused"))
            }
        }
        val flow = flow(store, browser, starter = starter)

        failure { flow.authorize(setOf("openid")) }

        assertNull(browser.launchedUri)
        assertNull(store.stored)
        assertEquals(SessionState.Unauthenticated, flow.sessionState.first())
    }

    @Test
    fun `a pending request persisted before the extension existed still decodes`() {
        val legacy = """{"state":"s","nonce":"n","codeVerifier":"v","scopes":["openid"],""" +
            """"redirectUri":"https://app.example.com/oauth","acrValues":[],"maxAge":null,"createdAtEpochMillis":1}"""

        val decoded = PendingAuthorizationCodec.decode(legacy.toByteArray())

        assertTrue(decoded.extension.isEmpty())
        assertFalse(decoded.issRequired)
        val extended = decoded.let {
            PendingAuthorizationRequest(
                it.state, it.nonce, "", it.scopes, it.redirectUri, it.acrValues, it.maxAge, 1,
                extension = mapOf("blob" to "b", "token_endpoint" to "t"),
                issRequired = true,
            )
        }
        val roundTrip = PendingAuthorizationCodec.decode(PendingAuthorizationCodec.encode(extended))
        assertEquals(mapOf("blob" to "b", "token_endpoint" to "t"), roundTrip.extension)
        assertTrue(roundTrip.issRequired)
    }

    // ---- review findings M3 / M4 --------------------------------------------------------

    @Test
    fun `a resumed request waits only for what is left of its ten minutes`() = runTest {
        val pending = PendingAuthorizationRequest("s", "n", "v", listOf("openid"), "https://app.example.com/oauth", emptyList(), null, 0)
        val store = RecordingStore(stored = pending)
        val browser = FakeBrowser({ BrowserOutcome.UserCancelled }, store).let {
            object : BrowserAuthorizationSession by it {
                override suspend fun awaitPendingRedirect(): BrowserOutcome = awaitCancellation()
            }
        }
        val flow = flow(store, browser, now = 9 * 60 * 1000)

        val error = failure { flow.resumePendingAuthorization() } as VersolaError.Recoverable

        // Virtual time: the one minute left on the request elapsed, nothing arrived.
        assertSame(VersolaError.Recoverable.Cause.PendingRequestExpired, error.reason)
        assertNull(store.stored)
        assertEquals(SessionState.Unauthenticated, flow.sessionState.first())
    }

    @Test
    fun `a cancelled authorization over a stored grant settles on Authenticated`() = runTest {
        val store = RecordingStore()
        val browser = FakeBrowser({ BrowserOutcome.UserCancelled }, store)
        val flow = flow(store, browser, hasStoredGrant = { true })

        failure { flow.authorize(setOf("openid"), acrValues = listOf("mfa")) }

        assertEquals(SessionState.Authenticated, flow.sessionState.first())
        assertNull(store.stored)
    }

    @Test
    fun `a rejected redirect over a stored grant settles on Authenticated too`() = runTest {
        val store = RecordingStore()
        val browser = FakeBrowser({ BrowserOutcome.Redirect("https://app.example.com/oauth?code=c&state=wrong&iss=$ISSUER") }, store)
        val flow = flow(store, browser, hasStoredGrant = { true })

        failure { flow.authorize(setOf("openid")) }

        assertEquals(SessionState.Authenticated, flow.sessionState.first())
    }
}
