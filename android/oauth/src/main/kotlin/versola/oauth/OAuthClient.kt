package versola.oauth

import android.content.Context
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import versola.oauth.core.AccessToken
import versola.oauth.core.AuthorizationFlow
import versola.oauth.core.BrowserAuthorizationSession
import versola.oauth.core.CredentialKeyProvider
import versola.oauth.core.VersolaInternalApi
import versola.oauth.core.DiscoveryClient
import versola.oauth.core.DiscoveryService
import versola.oauth.core.FileJwksCache
import versola.oauth.core.FileProviderMetadataCache
import versola.oauth.core.HttpDiscoveryClient
import versola.oauth.core.HttpTokenClient
import versola.oauth.core.HttpUserInfoClient
import versola.oauth.core.IdTokenClaims
import versola.oauth.core.LifetimeAwareDiscoveryClient
import versola.oauth.core.fetchWithLifetime
import versola.oauth.core.JwksClient
import versola.oauth.core.JwksIdTokenValidator
import versola.oauth.core.JwsVerifier
import versola.oauth.core.LogoutOutcome
import versola.oauth.core.ProviderMetadata
import versola.oauth.core.ProviderMetadataCache
import versola.oauth.core.PushedAuthorizationStarter
import versola.oauth.core.RefreshTokenPolicy
import versola.oauth.core.SessionCoordinator
import versola.oauth.core.SessionState
import versola.oauth.core.TokenBinding
import versola.oauth.core.UserInfo
import versola.oauth.core.UserInfoClient
import versola.oauth.core.VersolaError
import versola.sdk.browser.AuthTabAuthorizationSession
import versola.sdk.dpop.DpopProofFactory
import versola.sdk.dpop.KeyAttestation
import versola.sdk.dpop.KeystoreDpopKey
import versola.sdk.okhttp.RequestScope
import versola.sdk.okhttp.VersolaHttpException
import versola.sdk.okhttp.VersolaInterceptor
import versola.sdk.storage.DataStoreCredentialStore
import versola.sdk.storage.FilePendingAuthorizationStore
import versola.sdk.storage.HardwareKeyProvider

/**
 * The generic facade of `spec/oauth-sdk-api.md`: a public client for any conforming OpenID
 * Provider, owning sign-in, ID-token validation, storage, refresh, authenticated HTTP and
 * sign-out. The integrator sees a session, observable through [sessionState], and not tokens.
 *
 * The protocol is the same core the Versola facade uses; what differs are the defaults (bearer
 * tokens, no `offline_access` added, PAR when advertised, nothing sent that a standard does not
 * define) and the surface. Provider differences are capabilities read from discovery, never a
 * branch on an issuer (`spec/providers.md`).
 */
public class OAuthClient private constructor(
    public val configuration: OAuthConfiguration,
    private val flow: AuthorizationFlow,
    private val coordinator: SessionCoordinator,
    private val userInfoClient: UserInfoClient,
    private val proofs: DpopProofFactory?,
    private val dpopKey: KeystoreDpopKey?,
) {

    /**
     * The state machine of `spec/state-machine.md`, observable. Cold, and its first emission is
     * the restored state: an app killed mid-browser observes `Authorizing` on cold start, never
     * a placeholder (scenario 12). A sign-in whose redirect reaches a cold-started process is
     * finished by the SDK itself, and the result arrives here as `Authenticated` or as the
     * state the failure settles on; the app has nothing to call.
     */
    public val sessionState: Flow<SessionState> get() = flow.sessionState

    /**
     * The claims of the validated ID token of this session, or null when there is no session.
     * Memory only; the raw token and the `nonce` are not exposed.
     */
    public val claims: IdTokenClaims? get() = coordinator.claims

    /** The provider's metadata, discovered once and cached on disk across restarts and logout. */
    public suspend fun metadata(): ProviderMetadata = coordinator.retryScope.operation { flow.metadata() }

    /**
     * Opens the system browser, validates the redirect, exchanges the code, validates the ID
     * token and persists the grant, in that order; `Authenticated` is published only after the
     * grant is durably stored. Returns nothing on purpose: the session is observable, and a
     * token handed back here would make the escape hatch the first thing an integrator saw.
     *
     * While `Authenticated`, a successful login replaces the stored grant; a cancelled or failed
     * one leaves the session as it was. While `Authorizing`, it is refused: the app observes
     * [sessionState] before asking.
     */
    public suspend fun login(options: LoginOptions = LoginOptions.Default) {
        refuseWhileAuthorizing()
        coordinator.login(
            scopes = (options.scopes ?: configuration.scopes) + "openid",
            acrValues = options.acrValues,
            maxAge = options.maxAge,
            parameters = options.parameters,
            ephemeralBrowser = options.ephemeralBrowser,
        )
    }

    /**
     * Gives up an authorization whose browser is gone, so that [login] can be called again now
     * instead of being refused while [sessionState] stays `Authorizing` for the rest of the pending
     * request's ten minutes. The case is the app killed while the browser was open and the user
     * coming back to the app itself, not through the redirect: nothing else tells the SDK the
     * redirect is not coming.
     *
     * A [login] or [stepUp] that is still waiting on the browser ends with
     * `Recoverable(UserCancelled)`; the pending request is discarded and the state settles as for a
     * user cancel (`Authenticated` over a stored grant, otherwise `Unauthenticated`). A tab that is
     * still open may yet redirect, and that redirect is ignored. Does nothing when no authorization
     * is pending, so it is safe to call without checking [sessionState] first.
     */
    public suspend fun cancelPendingAuthorization() {
        flow.cancelPendingAuthorization()
    }

    /**
     * Answers a [VersolaError.StepUp] by re-authorizing at the authentication context the
     * resource server asked for, then leaves the app to re-issue the refused call. The scopes
     * are the configured ones unless [options] says otherwise.
     */
    public suspend fun stepUp(challenge: VersolaError.StepUp, options: LoginOptions = LoginOptions.Default) {
        refuseWhileAuthorizing()
        coordinator.login(
            scopes = (options.scopes ?: configuration.scopes) + "openid",
            acrValues = challenge.acrValues,
            maxAge = challenge.maxAge,
            parameters = options.parameters,
            ephemeralBrowser = options.ephemeralBrowser,
        )
    }

    /**
     * Signs out (`spec/oauth-sdk-api.md` section 12): revokes the refresh token when the
     * provider advertises a revocation endpoint and [LogoutOptions.revoke] is set, ends the
     * provider's session through the browser when an `end_session_endpoint` is known and
     * [LogoutOptions.endSession] is set, and wipes everything credential-shaped. The wipe is
     * unconditional: `Unauthenticated` is reached whatever the two server-side steps did, and
     * the outcome says which of them succeeded.
     */
    public suspend fun logout(options: LogoutOptions = LogoutOptions.Default): LogoutOutcome =
        coordinator.logout(revoke = options.revoke, endSession = options.endSession)

    /**
     * The access token, refreshed first if it is at or within its refresh skew, once however
     * many callers ask at the same time. A session the provider issued no refresh token for
     * ends here with `Reauthenticate(SessionExpired)` once the token has expired.
     *
     * **The escape hatch.** [interceptor] and [authenticatedClient] attach this token without
     * the value ever passing through application code; a token handed out here is one an
     * integrator can log.
     */
    public suspend fun accessToken(): AccessToken = coordinator.accessToken()

    /** Spends the refresh token now, once, whatever the access token's remaining lifetime. */
    public suspend fun refresh() {
        coordinator.refresh()
    }

    /**
     * `GET` on the UserInfo endpoint with the session's token. The response's `sub` must equal
     * the ID token's (OpenID Connect Core 5.3.2); a provider without the endpoint is
     * `Configuration(ProviderUnsupported)`.
     */
    public suspend fun userInfo(): UserInfo = coordinator.retryScope.operation {
        // After a cold start the claims are read back from the stored ID token first.
        val subject = coordinator.restoreClaims()?.subject
            ?: throw VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.GrantRejected)
        userInfoClient.fetch(coordinator, subject)
    }

    /**
     * Finishes a sign-in that outlived the process that began it (scenario 12). Started by
     * [create], not by the app: a process the OS starts for the redirect has no caller to ask,
     * and `spec/oauth-sdk-api.md` section 4 has the session complete on its own.
     *
     * Acts only when the restored state is `Authorizing`, so a client with nothing pending
     * costs one read of the store. The wait for the redirect is bounded by what is left of the
     * request's ten minutes ([AuthorizationFlow.resumePendingAuthorization]), and the work
     * after it is [SessionCoordinator.resumePendingLogin], the tail of `login()` itself:
     * validation, exchange, ID-token check, persistence, then `Authenticated`. A failure has
     * already settled the state, so it is logged and not rethrown into a scope nobody awaits.
     */
    private fun resumeInBackground(scope: CoroutineScope) {
        scope.launch {
            try {
                if (flow.sessionState.first() != SessionState.Authorizing) return@launch
                coordinator.resumePendingLogin()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                // The class name, and the typed error's own text, which carries no secret; an
                // exception message from a parser or a provider could.
                configuration.logger.warn("resuming the pending authorization failed: ${if (e is VersolaError) e.toString() else e.javaClass.simpleName}")
            }
        }
    }

    /**
     * `spec/oauth-sdk-api.md` section 5: a `login()` while this process is carrying an authorization
     * out — the browser is up or opening, a resume is awaiting its redirect, or a code exchange has
     * not finished — is refused rather than queued behind it or allowed to supersede a request the
     * redirect may still complete. A pending request nobody awaits (a cancelled caller left it, or
     * nothing started a resume) is a leftover, and the new login supersedes it; the state alone,
     * `Authorizing` for the leftover's ten minutes, cannot tell the two apart. A resume that is
     * awaiting a redirect which is not coming is ended with [cancelPendingAuthorization].
     */
    private fun refuseWhileAuthorizing() {
        if (flow.authorizationInFlight) {
            throw OAuthConfiguration.invalid("an authorization is already in progress; observe sessionState before asking again")
        }
    }

    /**
     * Which Keystore tier the DPoP key reached, or null under [TokenBinding.Bearer]. Suspending
     * because the key is generated on first use; asking this is what generates it.
     */
    public suspend fun keyAttestation(): KeyAttestation? = dpopKey?.attestation()

    /**
     * An OkHttp **application** interceptor that attaches the session to every request whose
     * origin is in [origins] and nothing else: `Authorization: Bearer` or `DPoP` with a proof,
     * one refresh and one replay on a 401, one nonce retry, and RFC 9470's step-up challenge
     * surfaced as [VersolaError.StepUp] (`spec/oauth-sdk-api.md` section 10). A request to any
     * other origin passes through untouched, so installing it on a client shared with the rest
     * of the app is safe. Errors arrive as [VersolaHttpException], because an interceptor may
     * raise nothing else without crashing an enqueued call; [call] unwraps them.
     *
     * It blocks the calling thread while it waits for the token, a refresh included. Use `enqueue`
     * or [call]; do not `execute()` many calls at once on `Dispatchers.IO`, whose threads the
     * refresh itself needs, or they can hold all of them and hang the process.
     */
    public fun interceptor(origins: Set<String> = configuration.protectedOrigins): Interceptor =
        VersolaInterceptor(coordinator, scopeOf(origins), proofs)

    /**
     * The configured HTTP client plus [interceptor], with redirects switched off: a `Location`
     * from a protected origin would otherwise repeat the request, token included, at another.
     */
    public fun authenticatedClient(origins: Set<String> = configuration.protectedOrigins): OkHttpClient =
        configuration.httpClient.newBuilder()
            .followRedirects(false)
            .followSslRedirects(false)
            .addInterceptor(interceptor(origins))
            .build()

    /**
     * One authenticated call through [authenticatedClient], with the error taxonomy raised as itself.
     *
     * The call blocks a thread for its whole duration (OkHttp's `execute()`, and inside it the
     * interceptor waits for the access token), and that thread is not one of `Dispatchers.IO`'s
     * default view: the refresh such a call waits for dispatches its token request and its storage
     * reads there, and 64 calls parked on `Dispatchers.IO` itself would hold every thread of it and
     * starve the refresh they wait for, hanging the process. See [BLOCKING_CALLS].
     */
    public suspend fun call(request: Request, origins: Set<String> = configuration.protectedOrigins): Response =
        withContext(BLOCKING_CALLS) {
            try {
                authenticatedClient(origins).newCall(request).execute()
            } catch (e: VersolaHttpException) {
                throw e.error
            }
        }

    private fun scopeOf(origins: Set<String>): RequestScope {
        if (origins.isEmpty()) {
            throw OAuthConfiguration.invalid("the authenticated client needs at least one protected origin; none is configured")
        }
        return try {
            RequestScope.origins(origins)
        } catch (e: IllegalArgumentException) {
            throw OAuthConfiguration.invalid(e.message ?: "invalid protected origin")
        }
    }

    public companion object {
        private val clients = ConcurrentHashMap<String, OAuthClient>()

        /**
         * Where [call] blocks. A view of `Dispatchers.IO` with a quota of its own, which `limitedParallelism`
         * makes independent of the 64 threads the default view is capped at: the calls parked here, 64 of
         * them at most, leave that view free for the refresh they are waiting on. Beyond 64 they queue,
         * and queue behind nothing that needs them.
         */
        private val BLOCKING_CALLS: CoroutineDispatcher = Dispatchers.IO.limitedParallelism(64)

        /**
         * Where a cold-started process finishes the sign-in its redirect answers. The process,
         * not a caller, owns that work: the OS started this process for the redirect and no
         * `login()` is waiting on it. Never cancelled, and a failure in one client's resume
         * does not reach another's (`SupervisorJob`). A test substitutes its own scope.
         */
        @Volatile
        internal var resumeScope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

        /**
         * Validates the configuration and wires the default implementations. No network I/O
         * and no key generation happen here: discovery runs on the first operation that needs
         * it, the DPoP key is generated on first use.
         *
         * One instance per configuration per process: a second call with the same issuer and
         * client id returns the first instance (DataStore allows one instance per file), and a
         * *different* configuration for the same issuer and client id in one process is
         * refused rather than silently shared.
         */
        public fun create(context: Context, configuration: OAuthConfiguration): OAuthClient =
            create(context, configuration, browser = null, keyProvider = null)

        /**
         * Wiring: the same as [create] with the browser leg replaced, which is what a
         * conformance driver does to drive the provider's login form over HTTP. The contract
         * stays URI-only, so a web view is no more representable here than anywhere else.
         */
        @VersolaInternalApi
        public fun create(
            context: Context,
            configuration: OAuthConfiguration,
            browser: BrowserAuthorizationSession?,
            /** Replaces the Keystore-backed wrapping key; a JVM test has no Keystore. */
            keyProvider: CredentialKeyProvider? = null,
        ): OAuthClient {
            // Lookup, check and build under one lock: two callers racing with different
            // configurations for the same key must not both pass the check on an empty map.
            return synchronized(clients) {
                clients[configuration.storageKey]?.let { existing ->
                    if (existing.configuration.fingerprint != configuration.fingerprint) {
                        throw OAuthConfiguration.invalid(
                            "a client for ${configuration.issuerIdentifier} / ${configuration.clientId} already exists in this process with a different configuration",
                        )
                    }
                    return existing
                }
                build(context.applicationContext, configuration, browser, keyProvider).also {
                    clients[configuration.storageKey] = it
                    it.resumeInBackground(resumeScope)
                }
            }
        }

        /**
         * Wiring: forgets every client this process created, so the next [create] builds anew.
         * For a conformance driver whose tests each stage a provider at the same address with
         * a different configuration; an app has no reason to call it. The instances are not
         * closed: a forgotten client over a live store must not be used again, and a test's
         * stores are its own temporary directories.
         */
        @VersolaInternalApi
        public fun forgetAll() {
            synchronized(clients) { clients.clear() }
        }

        private fun build(
            context: Context,
            configuration: OAuthConfiguration,
            browser: BrowserAuthorizationSession?,
            keyProvider: CredentialKeyProvider?,
        ): OAuthClient {
            val logger = configuration.logger
            val httpClient = configuration.httpClient
            val core = configuration.core
            core.redirectUriWarning?.let(logger::warn)

            // noBackupFilesDir: neither the pending request nor the refresh token may be
            // restored onto another device out of a cloud backup. One directory per issuer and
            // client id, so two clients in one app never share a file.
            val directory = File(File(context.noBackupFilesDir, "versola-oauth"), configuration.storageKey)
            // One wrapping key per configuration, like the DPoP key and the files: the key's
            // user-authentication requirement is this configuration's unlock policy, not the
            // first client's in the process.
            val keys = keyProvider ?: HardwareKeyProvider(
                alias = "versola-oauth-${configuration.storageKey}",
                unlockPolicy = configuration.unlockPolicy,
            )

            val discovery = when (val endpoints = configuration.endpoints) {
                null -> DiscoveryService(
                    issuer = core.issuer,
                    client = EndSessionOverride(HttpDiscoveryClient(httpClient), configuration.endSessionEndpoint),
                    cache = FileProviderMetadataCache(File(directory, "provider-metadata.json")),
                )
                // Explicit endpoints: no well-known request, ever. A memory cache so the
                // configuration, not a file, is always what is served.
                else -> DiscoveryService(
                    issuer = core.issuer,
                    client = StaticDiscoveryClient(endpoints.toMetadata().let { metadata ->
                        configuration.endSessionEndpoint?.let { metadata.copy(endSessionEndpoint = it) } ?: metadata
                    }),
                    cache = MemoryMetadataCache(),
                )
            }

            val dpopKey = when (val binding = configuration.tokenBinding) {
                is TokenBinding.Dpop -> KeystoreDpopKey(
                    alias = "versola-oauth-${configuration.storageKey}",
                    requireHardware = binding.requireHardware,
                    logger = logger,
                )
                TokenBinding.Bearer -> null
            }
            val proofs = dpopKey?.let { DpopProofFactory(it) }

            val credentialStore = DataStoreCredentialStore.forFile(
                file = File(directory, "credentials"),
                keyProvider = keys,
            )
            val flow = AuthorizationFlow(
                configuration = core,
                discovery = discovery,
                pendingStore = FilePendingAuthorizationStore(
                    file = File(directory, "pending-authorization"),
                    keyProvider = keys,
                ),
                // Auth Tab where the device's browser supports it, Custom Tabs otherwise.
                browser = browser ?: AuthTabAuthorizationSession(context, logger),
                tokenBinding = configuration.tokenBinding,
                dpopKey = dpopKey,
                hasStoredGrant = credentialStore::hasGrant,
                // Pushes the request when the provider advertises PAR (or the policy says so),
                // else sends the plain request; decided per login from the metadata.
                starter = PushedAuthorizationStarter(core, httpClient, configuration.pushedAuthorization),
            )
            val jwks = JwksClient(httpClient, FileJwksCache(File(directory, "jwks.json")))
            val validator = JwksIdTokenValidator(
                // The issuer the provider signs under: discovery's, which may carry a trailing
                // slash the configured value does not (Auth0), and which the ID token repeats.
                issuer = { discovery.metadata().issuer },
                clientId = core.clientId,
                jwksUri = { discovery.metadata().jwksUri },
                allowedAlgorithms = { discovery.metadata().idTokenSigningAlgValuesSupported },
                jwks = jwks,
                clockSkewTolerance = configuration.clockSkewTolerance,
            )
            val coordinator = SessionCoordinator(
                flow = flow,
                tokenClient = HttpTokenClient(
                    configuration = core,
                    discovery = discovery,
                    httpClient = httpClient,
                    dpop = proofs,
                    tokenBinding = configuration.tokenBinding,
                    // Nothing a standard does not define (ADR 0001).
                    sendIdempotencyKey = false,
                ),
                credentialStore = credentialStore,
                retryPolicy = configuration.retryPolicy,
                // No Idempotency-Key is sent (above): a refresh is repeated only when it provably
                // was not processed, so a replay never spends a token the provider already rotated.
                repeatsRefreshAfterAmbiguousFailure = false,
                // The cooldown a Retry-After starts must run while the phone sleeps: Retry-After is wall
                // time and the default clock (System.nanoTime) stops in deep sleep.
                retryClock = { android.os.SystemClock.elapsedRealtime() },
                onCredentialsWiped = {
                    proofs?.nonces?.clear()
                    dpopKey?.destroy()
                },
                logger = logger,
                refreshTokens = RefreshTokenPolicy.Optional,
                idTokenValidator = validator,
            )
            val userInfo = HttpUserInfoClient(
                userinfoEndpoint = { discovery.metadata().userinfoEndpoint },
                httpClient = httpClient,
                dpop = proofs,
                // A signed UserInfo response is verified with the same key set as the ID token.
                verifier = JwsVerifier(
                    jwksUri = { discovery.metadata().jwksUri },
                    allowedAlgorithms = { discovery.metadata().idTokenSigningAlgValuesSupported },
                    jwks = jwks,
                ),
            )
            return OAuthClient(configuration, flow, coordinator, userInfo, proofs, dpopKey)
        }
    }
}

/** Serves the configured endpoints as a discovery document; never touches the network. */
private class StaticDiscoveryClient(private val metadata: ProviderMetadata) : DiscoveryClient {
    override suspend fun fetch(issuer: String): ProviderMetadata = metadata
}

/**
 * The one discovered value a configuration may replace: sign-out URLs are where vendors most
 * often leave the standard (`spec/oauth-sdk-api.md` section 3). Applied on fetch, so the cache
 * holds what the SDK uses.
 */
private class EndSessionOverride(
    private val delegate: DiscoveryClient,
    private val endSessionEndpoint: String?,
) : LifetimeAwareDiscoveryClient {
    override suspend fun fetch(issuer: String): ProviderMetadata = fetchWithLifetime(issuer).first

    // The delegate's lifetime travels through: the override changes a value, not how long the
    // document it came in may be kept.
    override suspend fun fetchWithLifetime(issuer: String): Pair<ProviderMetadata, Long> {
        val (metadata, lifetime) = delegate.fetchWithLifetime(issuer)
        return (endSessionEndpoint?.let { metadata.copy(endSessionEndpoint = it) } ?: metadata) to lifetime
    }
}

private class MemoryMetadataCache : ProviderMetadataCache {
    @Volatile
    private var metadata: ProviderMetadata? = null

    override suspend fun load(): ProviderMetadata? = metadata

    override suspend fun save(metadata: ProviderMetadata) {
        this.metadata = metadata
    }

    override suspend fun clear() {
        metadata = null
    }
}
