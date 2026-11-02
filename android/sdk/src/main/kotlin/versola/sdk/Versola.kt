package versola.sdk

import android.content.Context
import java.io.File
import java.util.concurrent.TimeUnit
import versola.oauth.core.SdkDispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import versola.sdk.browser.AuthTabAuthorizationSession
import versola.oauth.core.AuthorizationFlow
import versola.oauth.core.AuthorizationGrant
import versola.sdk.core.BackChannel
import versola.sdk.core.EdgeAuthorizationStarter
import versola.oauth.core.BrowserAuthorizationSession
import versola.oauth.core.DiscoveryService
import versola.sdk.core.EdgeNativeTokenClient
import versola.sdk.core.FileNativeEndpointsStore
import versola.oauth.core.FileProviderMetadataCache
import versola.oauth.core.HttpDiscoveryClient
import versola.sdk.core.HttpNativeAuthorizationStarter
import versola.oauth.core.HttpTokenClient
import versola.oauth.core.TokenClient
import versola.oauth.core.ProviderMetadata
import versola.oauth.core.RetryPolicy
import versola.oauth.core.SessionCoordinator
import versola.oauth.core.SessionState
import versola.oauth.core.TokenBinding
import versola.oauth.core.VersolaConfiguration
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaLogger
import versola.sdk.dpop.DpopProofFactory
import versola.sdk.dpop.KeyAttestation
import versola.sdk.dpop.KeystoreDpopKey
import versola.sdk.okhttp.VersolaHttpException
import versola.sdk.okhttp.VersolaInterceptor
import versola.sdk.okhttp.authenticated
import versola.sdk.storage.DataStoreCredentialStore
import versola.sdk.storage.FilePendingAuthorizationStore
import versola.sdk.storage.HardwareKeyProvider
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response

/**
 * The SDK's entry point: the Android wiring of [AuthorizationFlow], which holds the protocol
 * behaviour itself.
 *
 * What #5 delivers is the browser leg — discovery, the authorization request, the system
 * browser, and a validated [AuthorizationGrant]. Redeeming that grant at the token endpoint
 * is #8, and `login()` — `authorize()` plus that exchange, ending in
 * [SessionState.Authenticated] — arrives with it. #9 adds the other end: [httpClient] and
 * [call], through which most integrators should never see a token at all.
 */
public class Versola internal constructor(
    private val flow: AuthorizationFlow,
    /**
     * Null under [TokenBinding.Bearer], and the one place that difference is visible: every
     * caller that needs a proof already has to ask whether the session is key-bound.
     */
    public val dpop: DpopProofFactory?,
    private val dpopKey: KeystoreDpopKey?,
    private val coordinator: SessionCoordinator,
    private val baseHttpClient: OkHttpClient,
    /** Null when `configure()` was not told where edge is; see [requireEdge]. */
    private val edgeBaseUrl: HttpUrl?,
) {

    public val configuration: VersolaConfiguration get() = flow.configuration

    /**
     * Which keystore tier the DPoP key actually reached, or null under
     * [TokenBinding.Bearer]. Suspending because the key is generated on first use rather than
     * inside [configure]; asking this is what generates it.
     */
    public suspend fun keyAttestation(): KeyAttestation? = dpopKey?.attestation()

    /** The state machine of `spec/state-machine.md`, observable. */
    public val sessionState: Flow<SessionState> get() = coordinator.sessionState

    /** The state now, after the restore a cold start owes; see `OAuthClient.currentSessionState`. */
    public suspend fun currentSessionState(): SessionState = coordinator.sessionState.first()

    /** The provider's metadata, fetched once and cached on disk across restarts and logout. */
    public suspend fun metadata(): ProviderMetadata = flow.metadata()

    /** Opens the system browser, waits for the redirect, and validates it. */
    public suspend fun authorize(
        scopes: Set<String>,
        acrValues: List<String> = emptyList(),
        maxAge: Long? = null,
    ): AuthorizationGrant = flow.authorize(scopes, acrValues, maxAge)

    /** Finishes an authorization that outlived the process that started it. */
    public suspend fun resumePendingAuthorization(): AuthorizationGrant? =
        flow.resumePendingAuthorization()

    /**
     * [authorize] and the code exchange, ending in [SessionState.Authenticated] with the
     * grant durably stored.
     *
     * Returns nothing on purpose. What it produced is a session, and the session is observable
     * through [sessionState]; handing back a token here would make the escape hatch the first
     * thing an integrator saw.
     */
    public suspend fun login(
        scopes: Set<String>,
        acrValues: List<String> = emptyList(),
        maxAge: Long? = null,
    ) {
        coordinator.login(scopes, acrValues, maxAge)
    }

    /**
     * Spends the refresh grant, once, however many callers ask at the same time.
     *
     * Rarely needed directly: [httpClient] refreshes on its own when a token is within its
     * refresh skew or a call comes back 401.
     */
    public suspend fun refresh() {
        coordinator.refresh()
    }

    /**
     * The access token, refreshed first if it is at or within its refresh skew.
     *
     * **The escape hatch.** [httpClient] and [call] attach this token, the matching DPoP proof
     * and the right scheme without the value ever passing through application code, and that
     * is the path to take. A token handed out here is one an integrator can log.
     */
    public suspend fun accessToken(): String = coordinator.accessToken().value

    /**
     * Answers a [VersolaError.StepUp] by re-authorizing at the authentication context edge
     * asked for, then leaves the app to re-issue the call that was refused.
     *
     * [scopes] is required rather than remembered. The granted scope set is not persisted, so
     * a remembered one would be absent after process death — which is exactly the state a
     * step-up is most likely to be met from, a session restored from a stored grant. The app
     * passed the same set to [login] and still has it.
     *
     * The call is not replayed here either. It needs the browser, which needs an Activity and
     * an unbounded amount of the user's time, so it cannot happen inside an interceptor; and a
     * request whose body was already consumed cannot be rebuilt by anyone but the app.
     */
    public suspend fun stepUp(challenge: VersolaError.StepUp, scopes: Set<String>) {
        coordinator.login(scopes, challenge.acrValues, challenge.maxAge)
    }

    /**
     * Signs out: revokes the refresh token, ends the server session through the system
     * browser, and wipes everything credential-shaped — refresh token, pending slot, pending
     * authorization request, both nonce caches, and the DPoP key, which the next [login]
     * regenerates under a new `jkt`.
     *
     * The local wipe is unconditional: [SessionState.Unauthenticated] is reached even when the
     * browser is dismissed mid-flow or either server call fails. Only the server-side teardown
     * is best effort, and the return value says whether auth acknowledged it.
     */
    public suspend fun logout(): Boolean = coordinator.logout().sessionEnded

    /**
     * A client that authenticates every call to edge: the access token, a DPoP proof over it,
     * one nonce retry, one proof retry, and one refresh-and-replay on a 401 that is neither.
     *
     * Built over the client `configure()` was given, so its timeouts, connection pool and
     * cache are the integrator's. Redirects are switched off for the same reason
     * `HttpTokenClient` switches them off: a `Location` from anything answering as edge would
     * repeat the request — and the proof minted for *this* origin — at another one.
     */
    public fun httpClient(): OkHttpClient = authenticated(baseHttpClient, interceptor())

    /**
     * The authentication behind [httpClient] and [call]. Not offered on its own: an application
     * interceptor on a client that follows redirects would send its `DPoP` proof to whatever a
     * `Location` names, so the only client it is installed on is the one built with redirects off.
     */
    private fun interceptor(): Interceptor = VersolaInterceptor(coordinator, requireEdge(), dpop)

    /**
     * One authenticated call, with the error taxonomy raised as itself.
     *
     * The primary path. Through [httpClient] alone a failure arrives as a
     * [VersolaHttpException], because an OkHttp interceptor may raise nothing else without
     * crashing an asynchronous call; here it is unwrapped, and an app matches on
     * [VersolaError] the way it does everywhere else in the SDK.
     */
    public suspend fun call(request: Request): Response = withContext(SdkDispatchers.blockedCalls) {
        try {
            httpClient().newCall(request).execute()
        } catch (e: VersolaHttpException) {
            throw e.error
        }
    }

    private fun requireEdge(): HttpUrl = edgeBaseUrl ?: throw VersolaError.Configuration(
        VersolaError.Configuration.Detail.InvalidConfiguration(
            "configure() needs edgeBaseUrl to reach edge; it is not in the OAuth metadata (#1 §2.1)",
        ),
    )

    public companion object {

        /**
         * TEST SEAM (internal): where the credential and pending-request wrapping key comes from.
         * The Keystore does not exist on the JVM, so a Robolectric test that must get past the first
         * wrap swaps it; nothing in production assigns it.
         */
        internal var keyProviders: () -> versola.oauth.core.CredentialKeyProvider = { HardwareKeyProvider() }

        /**
         * Validates the configuration eagerly and wires the default implementations.
         *
         * [edgeBaseUrl] is separate configuration rather than something discovery could
         * supply, because it is not in the OAuth metadata (#1 §2.1). Optional so that an app
         * using only the authorization legs need not invent one; [httpClient], [interceptor]
         * and [call] then raise a `Configuration` error naming it.
         */
        public fun configure(
            context: Context,
            issuer: String,
            clientId: String,
            redirectUri: String,
            logger: VersolaLogger = AndroidLogger(),
            httpClient: OkHttpClient = defaultHttpClient,
            // Appended rather than inserted: every parameter before this one keeps the
            // position it had in #5, so a call written against that signature still compiles.
            tokenBinding: TokenBinding = TokenBinding.Dpop(),
            edgeBaseUrl: String? = null,
            retryPolicy: RetryPolicy = RetryPolicy.Default,
            /**
             * Where auth sends the browser once `logout()` has ended the server session.
             * Optional: without it the signed-out page stays open until the user dismisses
             * it, and the local sign-out completes regardless. Must be in the tenant's
             * `postLogoutRedirectUris` and, like [redirectUri], should be a verified App Link
             * delivered to `VersolaRedirectActivity`.
             */
            postLogoutRedirectUri: String? = null,
            /**
             * [BackChannel.Edge] for a client on a FAPI 2.0 tenant — the server's default
             * profile for a new tenant — where auth refuses a public client at `/token` and
             * edge's `/native/{start,complete,token,revoke}` endpoints front the app instead. Needs [edgeBaseUrl], an
             * https [redirectUri] and DPoP. [BackChannel.Auth] is the plain OAuth public
             * client and works against any provider.
             */
            backChannel: BackChannel = BackChannel.Auth,
            /**
             * The browser leg. Auth Tab (Custom Tabs fallback) by default; the conformance harness substitutes a
             * session that drives auth's login conversation over HTTP. The interface takes
             * URIs and nothing else, so nothing a WebView could be smuggled through exists
             * here either (#1 §4).
             */
            browser: BrowserAuthorizationSession? = null,
        ): Versola {
            // Validated first, so a refused configuration is refused the same way every time.
            val configuration = VersolaConfiguration.create(issuer, clientId, redirectUri, postLogoutRedirectUri)
            // Parsed at configuration time, not at the first call: a base URL that is not a
            // URL is a deployment mistake, and `spec/errors.md` has those fail where they are
            // one line to fix rather than behind a login screen.
            val edge = edgeBaseUrl?.let {
                val url = it.toHttpUrlOrNull() ?: throw VersolaError.Configuration(
                    VersolaError.Configuration.Detail.InvalidConfiguration(
                        "edgeBaseUrl must be an absolute http or https URL: $it",
                    ),
                )
                // Tokens and proofs go to this origin: https, or cleartext to the developer's own
                // machine only, as the issuer and the generic facade's protected origins (`AUDIT Z3`).
                if (url.scheme != "https" && url.host !in LOOPBACK_HOSTS) {
                    throw VersolaError.Configuration(
                        VersolaError.Configuration.Detail.InvalidConfiguration(
                            "edgeBaseUrl must be https (http only on a loopback host: localhost, 127.0.0.1, [::1]): $it",
                        ),
                    )
                }
                url
            }

            // The combinations the flow refuses one at a time are refused here with one message naming
            // the knob, before the registry below: a refused configuration is refused whatever instance
            // exists.
            if (backChannel == BackChannel.Edge) {
                if (edge == null) {
                    throw VersolaError.Configuration(
                        VersolaError.Configuration.Detail.InvalidConfiguration(
                            "BackChannel.Edge needs edgeBaseUrl: the native endpoints are edge's",
                        ),
                    )
                }
                if (tokenBinding !is TokenBinding.Dpop) {
                    throw VersolaError.Configuration(
                        VersolaError.Configuration.Detail.InvalidConfiguration(
                            "BackChannel.Edge needs TokenBinding.Dpop: edge's native endpoints accept no bearer presentation",
                        ),
                    )
                }
            }
            // One instance per process, because the storage directory below is one per app: a second
            // `configure()` (every `Activity.onCreate`, every rotation) with the same configuration
            // returns the first instance instead of building a second coordinator, with its own refresh
            // epoch and token cache, over the one credential store, so a `logout()` on one could not
            // fence the other's in-flight refresh (`AUDIT C2`). A different configuration is refused,
            // like `OAuthClient.create`. `logger` and `browser` of a later call are not part of it and
            // are ignored: the first is kept.
            val fingerprint = listOf(
                issuer, clientId, redirectUri, postLogoutRedirectUri, tokenBinding.toString(), edgeBaseUrl, backChannel,
                listOf(
                    retryPolicy.maxAttemptsPerOrigin, retryPolicy.maxTotalAttempts, retryPolicy.initialBackoff,
                    retryPolicy.backoffMultiplier, retryPolicy.maxBackoff, retryPolicy.totalBudget,
                ),
            ).joinToString("\u0000")
            synchronized(registry) {
                registry.instance?.let { existing ->
                    if (registry.fingerprint != fingerprint) {
                        throw VersolaError.Configuration(
                            VersolaError.Configuration.Detail.InvalidConfiguration(
                                "configure() was already called in this process with a different configuration",
                            ),
                        )
                    }
                    if (registry.httpClient !== httpClient) {
                        throw VersolaError.Configuration(
                            VersolaError.Configuration.Detail.InvalidConfiguration(
                                "configure() was already called in this process with another httpClient; keep the OkHttpClient, or pass the same one",
                            ),
                        )
                    }
                    return existing
                }
                return build(
                    context, logger, httpClient, tokenBinding, edge, retryPolicy, backChannel, browser, configuration,
                ).also {
                    registry.instance = it
                    registry.fingerprint = fingerprint
                    registry.httpClient = httpClient
                }
            }
        }

        /** The one instance of this process and what it was configured with; see [configure]. */
        private class Registry {
            var instance: Versola? = null
            var fingerprint: String? = null
            var httpClient: OkHttpClient? = null
        }

        private val registry = Registry()

        /** TEST SEAM (internal): forgets the instance, so the next [configure] builds anew. */
        internal fun forgetAll() {
            synchronized(registry) { registry.instance = null }
        }

        private fun build(
            context: Context,
            logger: VersolaLogger,
            httpClient: OkHttpClient,
            tokenBinding: TokenBinding,
            edge: HttpUrl?,
            retryPolicy: RetryPolicy,
            backChannel: BackChannel,
            browser: BrowserAuthorizationSession?,
            configuration: VersolaConfiguration,
        ): Versola {
            configuration.redirectUriWarning?.let(logger::warn)
            val applicationContext = context.applicationContext
            // noBackupFilesDir: neither the pending request nor, later, the refresh token may
            // be restored onto a different device out of a cloud backup.
            val directory = File(applicationContext.noBackupFilesDir, "versola")

            // Constructed, not generated: nothing touches the Keystore until the first call
            // that needs a thumbprint or a proof, so configure() stays a cheap main-thread
            // call even on a device where a StrongBox keygen takes a noticeable moment.
            val dpopKey = when (tokenBinding) {
                is TokenBinding.Dpop -> KeystoreDpopKey(
                    requireHardware = tokenBinding.requireHardware,
                    logger = logger,
                )
                TokenBinding.Bearer -> null
            }

            val discovery = DiscoveryService(
                issuer = configuration.issuer,
                client = HttpDiscoveryClient(httpClient),
                cache = FileProviderMetadataCache(File(directory, "provider-metadata.json")),
            ).also { it.logger = logger }
            // One instance per file per process, which is DataStore's constraint: a second
            // `configure()` in the same process — every `Activity.onCreate`, every rotation —
            // shares the store the first one opened. Opening it reads nothing; the file is
            // read on first access, and the Keystore is not touched until something asks to
            // unwrap.
            val credentialStore = DataStoreCredentialStore.forFile(
                file = File(directory, "credentials"),
                keyProvider = keyProviders(),
            )
            val proofFactory = dpopKey?.let { DpopProofFactory(it) }
            // One factory across auth and edge, deliberately. Its `DpopNonceCache` is keyed by
            // origin, so the two servers already hold independent nonces within it — which is
            // scenario 04's requirement — while a second factory would split the clock offset
            // learned from one server's `Date` header away from the other's proofs.

            // Through edge, the three things the flow refuses one at a time are refused here
            // with one message naming the knob, before any of the flow's own checks run.
            val nativeStarter = when (backChannel) {
                BackChannel.Auth -> null
                BackChannel.Edge -> {
                    if (edge == null) {
                        throw VersolaError.Configuration(
                            VersolaError.Configuration.Detail.InvalidConfiguration(
                                "BackChannel.Edge needs edgeBaseUrl: the native endpoints are edge's",
                            ),
                        )
                    }
                    if (proofFactory == null) {
                        throw VersolaError.Configuration(
                            VersolaError.Configuration.Detail.InvalidConfiguration(
                                "BackChannel.Edge needs TokenBinding.Dpop: edge's native endpoints accept no bearer presentation",
                            ),
                        )
                    }
                    HttpNativeAuthorizationStarter(configuration, edge.toString(), httpClient, proofFactory)
                }
            }
            val flow = AuthorizationFlow(
                configuration = configuration,
                discovery = discovery,
                pendingStore = FilePendingAuthorizationStore(
                    file = File(directory, "pending-authorization"),
                    keyProvider = keyProviders(),
                ),
                browser = browser ?: AuthTabAuthorizationSession(applicationContext, logger),
                tokenBinding = tokenBinding,
                dpopKey = dpopKey,
                hasStoredGrant = credentialStore::hasGrant,
                starter = nativeStarter?.let { EdgeAuthorizationStarter(configuration, tokenBinding, it) },
            )
            val tokenClient: TokenClient = if (nativeStarter == null) {
                HttpTokenClient(
                    configuration = configuration,
                    discovery = discovery,
                    httpClient = httpClient,
                    dpop = proofFactory,
                    tokenBinding = tokenBinding,
                )
            } else {
                EdgeNativeTokenClient(
                    configuration = configuration,
                    edgeBaseUrl = checkNotNull(edge).toString(),
                    httpClient = httpClient,
                    dpop = checkNotNull(proofFactory),
                    discovery = discovery,
                    // Unencrypted and kept across logout, like discovery metadata: two URLs
                    // edge hands to anyone who asks.
                    endpoints = FileNativeEndpointsStore(File(directory, "native-endpoints.json")),
                    tokenBinding = tokenBinding as TokenBinding.Dpop,
                )
            }

            return Versola(
                flow = flow,
                dpop = proofFactory,
                dpopKey = dpopKey,
                coordinator = SessionCoordinator(
                    flow = flow,
                    tokenClient = tokenClient,
                    credentialStore = credentialStore,
                    retryPolicy = retryPolicy,
                    // What `:core` cannot reach and `spec/state-machine.md` wipes with the
                    // grant: the per-origin nonce caches and the DPoP key (scenario 18).
                    onCredentialsWiped = {
                        proofFactory?.nonces?.clear()
                        dpopKey?.destroy()
                    },
                    logger = logger,
                    // The cache of the access token ages, and a `Retry-After` cooldown runs, with the
                    // device's real time: the default clock (System.nanoTime) stops in deep sleep, and
                    // an hour-old token would be served as fresh (`AUDIT C4`).
                    retryClock = { android.os.SystemClock.elapsedRealtime() },
                    elapsedMillis = { android.os.SystemClock.elapsedRealtime() },
                ),
                baseHttpClient = httpClient,
                edgeBaseUrl = edge,
            )
        }

        private val LOOPBACK_HOSTS = setOf("localhost", "127.0.0.1", "::1", "[::1]")

        // One for the process, so that two `configure()` calls with the default are the same
        // client; the call deadline bounds a call that connects and then drips (`AUDIT C5`).
        private val defaultHttpClient: OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .callTimeout(60, TimeUnit.SECONDS)
            .build()
    }
}
