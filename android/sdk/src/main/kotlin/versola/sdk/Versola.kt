package versola.sdk

import android.content.Context
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.TimeUnit
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import versola.oauth.core.AuthorizationFlow
import versola.oauth.core.BrowserAuthorizationSession
import versola.oauth.core.CredentialKeyProvider
import versola.oauth.core.DiscoveryService
import versola.oauth.core.IdTokenClaims
import versola.oauth.core.LogoutOutcome
import versola.oauth.core.SdkDispatchers
import versola.oauth.core.SessionCoordinator
import versola.oauth.core.SessionState
import versola.oauth.core.TlsTrustedIdTokenValidator
import versola.oauth.core.TokenBinding
import versola.oauth.core.TokenResponse
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaInternalApi
import versola.sdk.browser.AuthTabAuthorizationSession
import versola.sdk.core.EdgeAuthorizationStarter
import versola.sdk.core.EdgeMetadata
import versola.sdk.core.EdgeNativeTokenClient
import versola.sdk.core.FileNativeEndpointsStore
import versola.sdk.core.HttpNativeAuthorizationStarter
import versola.sdk.dpop.DpopProofFactory
import versola.sdk.dpop.KeyAttestation
import versola.sdk.dpop.KeystoreDpopKey
import versola.sdk.okhttp.VersolaHttpException
import versola.sdk.okhttp.VersolaInterceptor
import versola.sdk.okhttp.authenticated
import versola.sdk.storage.DataStoreCredentialStore
import versola.sdk.storage.FilePendingAuthorizationStore
import versola.sdk.storage.HardwareKeyProvider

/**
 * A session with a Versola deployment, for a native app (`spec/versola-sdk-api.md`): sign-in in
 * the system browser, started and finished through the edge's native endpoints, refresh and
 * revocation through the same edge, authenticated HTTP to it, and sign-out. The app sees a
 * session, observable through [sessionState], and never a token.
 *
 * The edge is the only server this class calls. It is the OAuth client towards `auth`; the device
 * holds a DPoP key, generated in the Keystore at the first sign-in and never exported, and every
 * token is bound to it. There is no discovery, no bearer mode and no direct call to `auth`: a
 * deployment with cells has an edge at its issuer's address, which serves the sign-in pages and
 * nothing a client calls. An app that talks to an `auth` directly uses `OAuthClient`.
 */
public class Versola private constructor(
    public val configuration: VersolaConfiguration,
    private val flow: AuthorizationFlow,
    private val coordinator: SessionCoordinator,
    private val proofs: DpopProofFactory,
    private val dpopKey: KeystoreDpopKey,
    private val grantedScope: GrantedScopeStore,
    private val baseHttpClient: OkHttpClient,
) : VersolaApi {

    /**
     * The state machine of `spec/state-machine.md`, observable. Cold, and its first emission is
     * the restored state: an app killed while the browser was up observes `Authorizing` on cold
     * start, and the sign-in whose redirect reaches that process is finished by the SDK itself.
     */
    override val sessionState: Flow<SessionState> get() = flow.sessionState

    /** The state now, after the restore a cold start owes; for code that must choose a screen at once. */
    override suspend fun currentSessionState(): SessionState = flow.sessionState.first()

    /**
     * The claims of this session's ID token, or null when there is no session. Its `iss`, `aud`,
     * `exp`, `nonce` and `auth_time` were checked; its signature was not, because no key set is
     * reachable from a native app (`spec/versola-sdk-api.md` section 9). Use it to show who is
     * signed in; what the user may do is the edge's decision, made from the access token.
     */
    override val claims: IdTokenClaims? get() = coordinator.claims

    /**
     * Signs in: asks the edge to start an authorization, opens the system browser on the address
     * it answers, validates the redirect, redeems the code through the edge, checks the ID token
     * and persists the grant, in that order. [SessionState.Authenticated] is published only once
     * the grant is durably stored. Returns nothing on purpose: the session is observable.
     *
     * While `Authenticated`, a successful sign-in replaces the session, as another user if that
     * is who signed in; a cancelled or failed one leaves it as it was. The same call made again
     * while one is in flight joins it; a different one is refused with
     * `Configuration(InvalidConfiguration)`.
     *
     * The sign-in has as long as the edge said (`expires_in` of its answer, at most ten minutes).
     * After that the call fails with `Recoverable(PendingRequestExpired)`: offer to start again.
     */
    override suspend fun login(options: LoginOptions) {
        authorize(options, options.acrValues, options.maxAge, expectedSubject = null)
    }

    /**
     * Answers a [VersolaError.StepUp] by signing the user in again at the authentication context
     * the edge asked for, then leaves the app to re-issue the call that was refused. Without
     * [options] the scopes are the ones the session was granted, which the SDK remembers.
     *
     * The step-up must come back as the user of the session. Nothing on the wire ties the two
     * together, so the SDK compares the subject: a person who signs in as someone else in the
     * browser gets `Recoverable(AccountMismatch)`, nothing of that sign-in is kept and the
     * session is as it was. Tell the user which account to continue with.
     */
    override suspend fun stepUp(challenge: VersolaError.StepUp, options: LoginOptions?) {
        // Read before the browser opens, and not swallowed: a step-up that cannot learn whose
        // session it strengthens (a locked store) fails here with the store's own error.
        val subject = coordinator.sessionSubject() ?: throw VersolaConfiguration.invalid(
            "stepUp() strengthens a session and there is none; call login()",
        )
        val effective = options ?: LoginOptions(scopes = grantedScope.load())
        authorize(effective, challenge.acrValues, challenge.maxAge, expectedSubject = subject)
    }

    private suspend fun authorize(
        options: LoginOptions,
        acrValues: List<String>,
        maxAge: Long?,
        expectedSubject: String?,
    ) {
        val requested = options.scopes + OPENID
        val response: TokenResponse = try {
            coordinator.login(
                scopes = requested,
                acrValues = acrValues,
                maxAge = maxAge,
                parameters = options.parameters,
                ephemeralBrowser = options.ephemeralBrowser,
                refuseWhileAuthorizing = true,
                expectedSubject = expectedSubject,
            )
        } catch (e: CancellationException) {
            finishInBackgroundIfAbandoned()
            throw e
        }
        // What the next step-up asks for again. The response's own `scope` when it has one (the
        // server may grant less than was asked), else what was requested. After the grant is
        // stored, and not fatal: a lost copy costs a step-up its remembered scopes, not a session.
        withContext(NonCancellable) { grantedScope.save(response.scopes.ifEmpty { requested }) }
    }

    /**
     * A caller cancelled while its browser was up leaves the request stored, and the tab can still
     * deliver its redirect (the screen went away, not the sign-in). The process finishes it, as it
     * does after a restart; see `OAuthClient` for the same rule.
     */
    private suspend fun finishInBackgroundIfAbandoned() {
        val abandoned = withContext(NonCancellable) { flow.sessionState.first() == SessionState.Authorizing }
        if (abandoned) resumeScope.launch { resumeQuietly() }
    }

    private suspend fun resumeQuietly() {
        try {
            coordinator.resumePendingLogin()?.let { response ->
                withContext(NonCancellable) { if (response.scopes.isNotEmpty()) grantedScope.save(response.scopes) }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            // The typed error's own text, which carries no secret, or only the class name.
            configuration.logger.warn(
                "resuming the pending authorization failed: ${if (e is VersolaError) e.toString() else e.javaClass.simpleName}",
            )
        }
    }

    /**
     * Signs out: revokes the refresh token through the edge, ends the session at the issuer in
     * the system browser, and wipes everything credential-shaped, the DPoP key included. The wipe
     * is unconditional: [SessionState.Unauthenticated] is reached whatever the two server-side
     * steps did, and the outcome says which of them the server acknowledged.
     */
    override suspend fun logout(options: LogoutOptions): LogoutOutcome =
        coordinator.logout(revoke = options.revoke, endSession = options.endSession)

    /**
     * Spends the refresh token now, once, however many callers ask. Rarely needed: [httpClient]
     * refreshes when a token is within its refresh skew or a call comes back 401.
     */
    override suspend fun refresh() {
        coordinator.refresh()
    }

    /**
     * Which Keystore tier the DPoP key reached, read back from the key and not from what was asked
     * for. Suspending because the key is generated on first use; asking this generates it.
     */
    override suspend fun keyAttestation(): KeyAttestation? = dpopKey.attestation()

    /**
     * A client that authenticates every request to the edge: the access token, a DPoP proof for
     * that request, one nonce retry, one proof retry, one refresh and replay on a 401 that is
     * neither, and the edge's step-up challenge raised as [VersolaError.StepUp]. A request to any
     * other origin passes through untouched, and the scope cannot be widened: the token is bound
     * to the device key and is presented to the edge only.
     *
     * Built over the configured client, with redirects switched off: a `Location` from anything
     * answering as the edge would repeat the request, and the proof minted for it, somewhere else.
     * Errors arrive as [VersolaHttpException], because an interceptor may raise nothing else
     * without crashing an enqueued call; [call] unwraps them. `execute()` blocks its thread while
     * a token is refreshed; use `enqueue` or [call] where a thread is dear.
     */
    public fun httpClient(): OkHttpClient = authenticated(
        baseHttpClient,
        VersolaInterceptor(coordinator, configuration.edgeOrigin.toHttpUrl(), proofs),
    )

    /** One authenticated call through [httpClient], with the error taxonomy raised as itself. */
    public suspend fun call(request: Request): Response = withContext(SdkDispatchers.blockedCalls) {
        try {
            httpClient().newCall(request).execute()
        } catch (e: VersolaHttpException) {
            throw e.error
        }
    }

    /** A redirect delivered to a cold-started process finishes its sign-in with no caller to ask. */
    private fun resumeInBackground() {
        flow.onRestoredAuthorizing = { resumeScope.launch { resumeQuietly() } }
        resumeScope.launch {
            try {
                flow.sessionState.first()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                configuration.logger.warn(
                    "restoring the session failed: ${if (e is VersolaError) e.toString() else e.javaClass.simpleName}",
                )
            }
        }
    }

    public companion object {
        private const val OPENID = "openid"

        private val clients = ConcurrentHashMap<String, Versola>()

        /** Where a cold-started process finishes the sign-in its redirect answers; a test substitutes its own. */
        @Volatile
        internal var resumeScope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

        // One for the process, so that two configurations with the default are the same client;
        // the call deadline bounds a call that connects and then drips (`AUDIT C5`).
        private val defaultHttpClient: OkHttpClient by lazy {
            OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(10, TimeUnit.SECONDS)
                .callTimeout(60, TimeUnit.SECONDS)
                .build()
        }

        /**
         * Wires the client for [configuration]. No network I/O and no key generation happen here:
         * the DPoP key is generated at the first sign-in, and there is no discovery to fetch.
         *
         * One instance per edge, issuer and client id per process: a second call with the same
         * configuration returns the first instance, so an `Activity.onCreate` may call this on
         * every rotation; one that differs in anything else is refused with
         * `Configuration(InvalidConfiguration)` rather than silently sharing the first one's
         * settings. The `httpClient` and the `logger` are compared by identity, so hoist them.
         */
        public fun create(context: Context, configuration: VersolaConfiguration): Versola =
            create(context, configuration, browser = null, keyProvider = null)

        /**
         * Wiring: [create] with the browser leg replaced, which is what the conformance driver
         * does to drive the sign-in pages over HTTP, and the wrapping key replaced, for a JVM test
         * that has no Keystore. The browser contract stays URI-only, so a web view is no more
         * representable here than anywhere else.
         */
        @VersolaInternalApi
        public fun create(
            context: Context,
            configuration: VersolaConfiguration,
            browser: BrowserAuthorizationSession?,
            keyProvider: CredentialKeyProvider? = null,
        ): Versola = synchronized(clients) {
            // Lookup, check and build under one lock: two callers racing with different
            // configurations for one key must not both pass the check on an empty map.
            clients[configuration.storageKey]?.let { existing ->
                val same = existing.configuration.fingerprint == configuration.fingerprint &&
                    existing.configuration.httpClient === configuration.httpClient &&
                    existing.configuration.logger === configuration.logger
                if (!same) {
                    throw VersolaConfiguration.invalid(
                        "create() was already called in this process for this edge and client with a different " +
                            "configuration; keep the VersolaConfiguration, its OkHttpClient and its logger, or pass the same ones",
                    )
                }
                return existing
            }
            build(context.applicationContext, configuration, browser, keyProvider)
                .also { clients[configuration.storageKey] = it }
                .also { it.resumeInBackground() }
        }

        /** TEST SEAM (internal): forgets every instance, so the next [create] builds anew. */
        internal fun forgetAll() {
            synchronized(clients) { clients.clear() }
        }

        private fun build(
            context: Context,
            configuration: VersolaConfiguration,
            browser: BrowserAuthorizationSession?,
            keyProvider: CredentialKeyProvider?,
        ): Versola {
            val core = configuration.core
            val logger = configuration.logger
            val httpClient = configuration.httpClient ?: defaultHttpClient
            val edge = configuration.edgeOrigin
            // noBackupFilesDir: neither the pending request nor the refresh token may be restored
            // onto another device out of a cloud backup. One directory per client.
            val directory = File(File(context.noBackupFilesDir, "versola"), configuration.storageKey)
            val keys = keyProvider ?: HardwareKeyProvider(
                alias = "versola-sdk-${configuration.storageKey}.storage",
                unlockPolicy = configuration.unlockPolicy,
            )
            // One instance per file per process, which is DataStore's constraint and why there is
            // one client per storage key. Opening it reads nothing.
            val credentialStore = DataStoreCredentialStore.forFile(File(directory, "credentials"), keys)

            // Constructed, not generated: nothing touches the Keystore until the first call that
            // needs a thumbprint or a proof, so create() stays a cheap main-thread call.
            val binding = TokenBinding.Dpop(requireHardware = configuration.requireHardwareKey)
            val dpopKey = KeystoreDpopKey(
                alias = "versola-sdk-${configuration.storageKey}.dpop",
                requireHardware = configuration.requireHardwareKey,
                logger = logger,
                // A proof asked for with the grant stored and the key gone is not signed by a new key.
                isGrantHeld = credentialStore::hasGrant,
            )
            // One factory for the edge and for the proofs addressed to auth's endpoints. Its nonce
            // cache and its clock offsets are keyed by origin, so the two never mix (scenario 04).
            val proofs = DpopProofFactory(dpopKey)

            // Stated, not fetched: the issuer's address serves no discovery document.
            val discovery = DiscoveryService(
                issuer = core.issuer,
                // The issuer as the app wrote it, not the core's copy, which drops a trailing
                // slash: the redirect's `iss` and the ID token's are compared with this value by
                // simple string comparison (RFC 9207), and `https://a/` and `https://a` are two
                // issuers.
                client = EdgeMetadata(configuration.issuer, edge, core.clientId),
                cache = EdgeMetadata.NoCache,
            )
            val flow = AuthorizationFlow(
                configuration = core,
                discovery = discovery,
                pendingStore = FilePendingAuthorizationStore(File(directory, "pending-authorization"), keys),
                browser = browser ?: AuthTabAuthorizationSession(context, logger),
                tokenBinding = binding,
                dpopKey = dpopKey,
                hasStoredGrant = credentialStore::hasGrant,
                starter = EdgeAuthorizationStarter(
                    core,
                    HttpNativeAuthorizationStarter(core, edge, httpClient, proofs),
                ),
                logger = logger,
            )
            val grantedScope = GrantedScopeStore(File(directory, "granted-scope"))
            val coordinator = SessionCoordinator(
                flow = flow,
                tokenClient = EdgeNativeTokenClient(
                    configuration = core,
                    edgeBaseUrl = edge,
                    httpClient = httpClient,
                    dpop = proofs,
                    // Unencrypted: two URLs the edge hands to anyone who asks.
                    endpoints = FileNativeEndpointsStore(File(directory, "native-endpoints.json")),
                    tokenBinding = binding,
                ),
                credentialStore = credentialStore,
                retryPolicy = configuration.retryPolicy,
                // What the core cannot reach and `spec/state-machine.md` wipes with the grant.
                onCredentialsWiped = {
                    proofs.nonces.clear()
                    dpopKey.destroy()
                    grantedScope.clear()
                },
                logger = logger,
                // Claims without the signature: no key set is reachable (`TlsTrustedIdTokenValidator`).
                idTokenValidator = TlsTrustedIdTokenValidator(
                    issuer = configuration.issuer,
                    clientId = core.clientId,
                    clockSkewTolerance = configuration.clockSkewTolerance,
                ),
                // The token cache ages, and a Retry-After cooldown runs, with the device's real
                // time: the default clock (System.nanoTime) stops in deep sleep (`AUDIT C4`).
                retryClock = { android.os.SystemClock.elapsedRealtime() },
                elapsedMillis = { android.os.SystemClock.elapsedRealtime() },
            )
            return Versola(configuration, flow, coordinator, proofs, dpopKey, grantedScope, httpClient)
        }
    }
}

/**
 * The scope of the stored grant, so that a step-up can ask for it again without the app having to
 * remember what it passed to `login()` in another process (`spec/versola-sdk-api.md` section 6).
 * Not credential material: scope names. A plain file beside the credentials, removed with them.
 */
internal class GrantedScopeStore(private val file: File) {

    suspend fun load(): Set<String> = withContext(SdkDispatchers.blocking) {
        try {
            if (file.exists()) file.readText().split(' ').filter { it.isNotEmpty() }.toSet() else emptySet()
        } catch (e: java.io.IOException) {
            emptySet()
        }
    }

    suspend fun save(scopes: Set<String>) {
        withContext(SdkDispatchers.blocking) {
            try {
                file.parentFile?.mkdirs()
                val temporary = File(file.parentFile, file.name + ".tmp")
                temporary.writeText(scopes.joinToString(" "))
                if (!temporary.renameTo(file)) temporary.delete()
            } catch (e: java.io.IOException) {
                // A step-up then asks for `openid` and `offline_access` alone; the session is unaffected.
            }
        }
    }

    suspend fun clear() {
        withContext(SdkDispatchers.blocking) { file.delete() }
    }
}
