package versola.oauth

import android.content.Context
import android.content.Intent
import android.net.Uri
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.NonCancellable
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
import versola.oauth.core.SdkDispatchers
import versola.oauth.core.SessionCoordinator
import versola.oauth.core.SessionState
import versola.oauth.core.TokenBinding
import versola.oauth.core.UserInfo
import versola.oauth.core.UserInfoClient
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaLogger
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
     * The state now, after the restore a cold start owes (a stored grant yields `Authenticated`, a
     * request still pending `Authorizing`). For code that has to decide at once between a login
     * screen and a home screen, an `Activity.onCreate` say, and has no use for a stream; a later
     * change is [sessionState]'s to report.
     */
    public suspend fun currentSessionState(): SessionState = flow.sessionState.first()

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
     * one leaves the session as it was. The same call made again while one is in flight (a
     * double-tapped button) joins it: one browser, one exchange, and both calls return together or
     * fail together. A call asking for something else while one is in flight is refused with
     * `Configuration(InvalidConfiguration)`: the app observes [sessionState] before asking.
     */
    public suspend fun login(options: LoginOptions = LoginOptions.Default) {
        try {
            coordinator.login(
                scopes = (options.scopes ?: configuration.scopes) + "openid",
                acrValues = options.acrValues,
                maxAge = options.maxAge,
                parameters = options.parameters,
                ephemeralBrowser = options.ephemeralBrowser,
                refuseWhileAuthorizing = true,
            )
        } catch (e: CancellationException) {
            finishInBackgroundIfAbandoned()
            throw e
        }
    }

    /**
     * Answers a [VersolaError.StepUp] by re-authorizing at the authentication context the
     * resource server asked for, then leaves the app to re-issue the refused call. The scopes
     * are the configured ones unless [options] says otherwise.
     */
    public suspend fun stepUp(challenge: VersolaError.StepUp, options: LoginOptions = LoginOptions.Default) {
        try {
            coordinator.login(
                scopes = (options.scopes ?: configuration.scopes) + "openid",
                acrValues = challenge.acrValues,
                maxAge = challenge.maxAge,
                parameters = options.parameters,
                ephemeralBrowser = options.ephemeralBrowser,
                refuseWhileAuthorizing = true,
            )
        } catch (e: CancellationException) {
            finishInBackgroundIfAbandoned()
            throw e
        }
    }

    /**
     * A caller cancelled while its browser was up leaves the request stored for a resume, and the tab
     * can still deliver its redirect (the screen that asked went away, not the sign-in). Only a
     * cold-start restore used to start that resume, so in a live process the redirect that came later
     * was buffered for nobody, or discarded by the next `login()` (`AUDIT C8`). The process finishes it
     * now, as it does after a restart: the redirect is awaited for what is left of the request's ten
     * minutes, validated and exchanged, and the session ends `Authenticated`. A request the cancel
     * did not leave `Authorizing` has nothing to resume.
     */
    private suspend fun finishInBackgroundIfAbandoned() {
        val abandoned = withContext(NonCancellable) { flow.sessionState.first() == SessionState.Authorizing }
        if (!abandoned) return
        resumeScope.launch {
            try {
                coordinator.resumePendingLogin()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                warnResumeFailed(e)
            }
        }
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
            // No session to ask for: not `GrantRejected`, which says the token endpoint answered
            // `invalid_grant`, and nothing was asked here (`AUDIT D3`).
            ?: throw VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.SessionExpired)
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
        // The restore finding `Authorizing` is the cue, whenever it happens: at once, or on a
        // later read after a restore that failed because the store was out of reach (a locked
        // key). Nothing but the restore starts a resume, so a `login()` of this process is
        // never mistaken for a sign-in to finish.
        flow.onRestoredAuthorizing = {
            scope.launch {
                try {
                    coordinator.resumePendingLogin()
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    warnResumeFailed(e)
                }
            }
        }
        scope.launch {
            try {
                flow.sessionState.first()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                warnResumeFailed(e)
            }
        }
    }

    // The class name, and the typed error's own text, which carries no secret; an exception
    // message from a parser or a provider could.
    private fun warnResumeFailed(e: Throwable) {
        configuration.logger.warn("resuming the pending authorization failed: ${if (e is VersolaError) e.toString() else e.javaClass.simpleName}")
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
     * It blocks the calling thread while it waits for the token, a refresh included, so use `enqueue`
     * or [call] where a thread is dear. `execute()` is safe from any thread that may block, a
     * coroutine on `Dispatchers.IO` included, however many callers wait on one refresh: the refresh
     * does its own work (the token request, discovery, the key set, storage, the DPoP key) on a
     * dispatcher of the SDK's, so callers that have parked every thread of `Dispatchers.IO` cannot
     * starve it. Each blocked caller still holds its own thread until the answer is in.
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
     * interceptor waits for the access token). That thread comes from a view of `Dispatchers.IO` with a
     * quota of its own, 64 calls at most and the rest queued, so a burst of calls neither takes the
     * threads the app's own work shares nor waits on them; what the refresh behind them needs runs
     * on a dispatcher of the SDK's own.
     */
    public suspend fun call(request: Request, origins: Set<String> = configuration.protectedOrigins): Response =
        withContext(SdkDispatchers.blockedCalls) {
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
                    // Not part of the fingerprint, which is what a client *is*, but what it is built with:
                    // answering with the first client would silently drop the app's new timeouts, pinning
                    // or proxy, and send the new logger nothing. Compared by identity (`AUDIT D4`).
                    if (existing.configuration.httpClient !== configuration.httpClient) {
                        throw OAuthConfiguration.invalid(
                            "a client for ${configuration.issuerIdentifier} / ${configuration.clientId} already exists in this process with another httpClient; create it once and keep the OkHttpClient, or pass the same one",
                        )
                    }
                    if (existing.configuration.logger !== configuration.logger) {
                        throw OAuthConfiguration.invalid(
                            "a client for ${configuration.issuerIdentifier} / ${configuration.clientId} already exists in this process with another logger; create it once and keep the logger, or pass the same one",
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

        /**
         * The redirect URI resolves to an activity of this app, or the sign-in never comes back: the
         * browser delivers the response to nothing and `login()` waits until the user gives up. The
         * SDK's own redirect activity carries no intent filter until the app adds one (the manifest
         * snippet in its KDoc), which is the usual omission, and `create()` is where the integrator
         * is looking when it is made (`AUDIT D5`). A warning, not an error: an app may route the
         * redirect to its own activity.
         */
        private fun warnIfRedirectUnhandled(context: Context, redirectUri: String, logger: VersolaLogger) {
            if (redirectUri.startsWith("http://")) return
            val probe = Intent(Intent.ACTION_VIEW, Uri.parse(redirectUri))
                .addCategory(Intent.CATEGORY_BROWSABLE)
                .setPackage(context.packageName)
            val handled = try {
                context.packageManager.queryIntentActivities(probe, 0).isNotEmpty()
            } catch (e: RuntimeException) {
                return
            }
            if (!handled) {
                logger.warn(
                    "no activity of this app has an intent filter for the redirect URI $redirectUri; the sign-in cannot return to the app. " +
                        "Declare versola.sdk.browser.VersolaRedirectActivity with an intent filter for it (see its documentation).",
                )
            }
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
            warnIfRedirectUnhandled(context, core.redirectUri.value, logger)

            // noBackupFilesDir: neither the pending request nor the refresh token may be
            // restored onto another device out of a cloud backup. One directory per issuer and
            // client id, so two clients in one app never share a file.
            val directory = File(File(context.noBackupFilesDir, "versola-oauth"), configuration.storageKey)
            // One wrapping key per configuration, like the DPoP key and the files: the key's
            // user-authentication requirement is this configuration's unlock policy, not the
            // first client's in the process.
            // Two aliases, one per key: the Keystore's alias namespace is shared by every key type, and
            // generating under an alias that exists replaces the entry, so the AES storage key and the
            // EC DPoP key under one alias destroyed each other (`AUDIT Z1`).
            val keys = keyProvider ?: HardwareKeyProvider(
                alias = "versola-oauth-${configuration.storageKey}.storage",
                unlockPolicy = configuration.unlockPolicy,
            )
            val credentialStore = DataStoreCredentialStore.forFile(
                file = File(directory, "credentials"),
                keyProvider = keys,
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
                    alias = "versola-oauth-${configuration.storageKey}.dpop",
                    requireHardware = binding.requireHardware,
                    logger = logger,
                    // A proof asked for with the grant stored and the key gone is not signed by a new key.
                    isGrantHeld = credentialStore::hasGrant,
                )
                TokenBinding.Bearer -> null
            }
            val proofs = dpopKey?.let { DpopProofFactory(it) }

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
                logger = logger,
            )
            val jwks = JwksClient(httpClient, FileJwksCache(File(directory, "jwks.json")))
            discovery.logger = logger
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
                // The cached access token ages with the device's real time too: the default clock
                // (System.nanoTime) stops in deep sleep and a token an hour old would be served as
                // fresh (`AUDIT C4`).
                elapsedMillis = { android.os.SystemClock.elapsedRealtime() },
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
