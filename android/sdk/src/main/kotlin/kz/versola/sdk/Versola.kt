package kz.versola.sdk

import android.content.Context
import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import kz.versola.sdk.browser.CustomTabsAuthorizationSession
import kz.versola.sdk.core.AuthorizationFlow
import kz.versola.sdk.core.AuthorizationGrant
import kz.versola.sdk.core.DiscoveryService
import kz.versola.sdk.core.FileProviderMetadataCache
import kz.versola.sdk.core.HttpDiscoveryClient
import kz.versola.sdk.core.HttpTokenClient
import kz.versola.sdk.core.ProviderMetadata
import kz.versola.sdk.core.RetryPolicy
import kz.versola.sdk.core.SessionCoordinator
import kz.versola.sdk.core.SessionState
import kz.versola.sdk.core.TokenBinding
import kz.versola.sdk.core.VersolaConfiguration
import kz.versola.sdk.core.VersolaError
import kz.versola.sdk.core.VersolaLogger
import kz.versola.sdk.dpop.DpopProofFactory
import kz.versola.sdk.dpop.KeyAttestation
import kz.versola.sdk.dpop.KeystoreDpopKey
import kz.versola.sdk.okhttp.VersolaHttpException
import kz.versola.sdk.okhttp.VersolaInterceptor
import kz.versola.sdk.storage.DataStoreCredentialStore
import kz.versola.sdk.storage.FilePendingAuthorizationStore
import kz.versola.sdk.storage.HardwareKeyProvider
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
    public suspend fun logout(): Boolean = coordinator.logout()

    /**
     * A client that authenticates every call to edge: the access token, a DPoP proof over it,
     * one nonce retry, one proof retry, and one refresh-and-replay on a 401 that is neither.
     *
     * Built over the client `configure()` was given, so its timeouts, connection pool and
     * cache are the integrator's. Redirects are switched off for the same reason
     * `HttpTokenClient` switches them off: a `Location` from anything answering as edge would
     * repeat the request — and the proof minted for *this* origin — at another one.
     */
    public fun httpClient(): OkHttpClient = baseHttpClient.newBuilder()
        .followRedirects(false)
        .followSslRedirects(false)
        .addInterceptor(interceptor())
        .build()

    /**
     * The same behaviour for an app that already has an `OkHttpClient` it is not going to give
     * up. Add it as an **application** interceptor.
     *
     * Requests that do not address edge pass through untouched, so installing this on a client
     * shared with the rest of the app — including the one `configure()` was given — is safe.
     * What such a client does not get is [httpClient]'s redirect policy, which is the
     * integrator's to set.
     */
    public fun interceptor(): Interceptor = VersolaInterceptor(coordinator, requireEdge(), dpop)

    /**
     * One authenticated call, with the error taxonomy raised as itself.
     *
     * The primary path. Through [httpClient] alone a failure arrives as a
     * [VersolaHttpException], because an OkHttp interceptor may raise nothing else without
     * crashing an asynchronous call; here it is unwrapped, and an app matches on
     * [VersolaError] the way it does everywhere else in the SDK.
     */
    public suspend fun call(request: Request): Response = withContext(Dispatchers.IO) {
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
            httpClient: OkHttpClient = defaultHttpClient(),
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
        ): Versola {
            val configuration = VersolaConfiguration.create(issuer, clientId, redirectUri, postLogoutRedirectUri)
            configuration.redirectUriWarning?.let(logger::warn)
            // Parsed at configuration time, not at the first call: a base URL that is not a
            // URL is a deployment mistake, and `spec/errors.md` has those fail where they are
            // one line to fix rather than behind a login screen.
            val edge = edgeBaseUrl?.let {
                it.toHttpUrlOrNull() ?: throw VersolaError.Configuration(
                    VersolaError.Configuration.Detail.InvalidConfiguration(
                        "edgeBaseUrl must be an absolute http or https URL: $it",
                    ),
                )
            }

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
            )
            // One instance per file per process, which is DataStore's constraint and the
            // reason it is built here rather than per caller. Constructing it opens nothing:
            // the file is read on first access, and the Keystore is not touched until
            // something asks to unwrap.
            val credentialStore = DataStoreCredentialStore(
                file = File(directory, "credentials"),
                keyProvider = HardwareKeyProvider(),
            )
            val proofFactory = dpopKey?.let { DpopProofFactory(it) }
            // One factory across auth and edge, deliberately. Its `DpopNonceCache` is keyed by
            // origin, so the two servers already hold independent nonces within it — which is
            // scenario 04's requirement — while a second factory would split the clock offset
            // learned from one server's `Date` header away from the other's proofs.
            val flow = AuthorizationFlow(
                configuration = configuration,
                discovery = discovery,
                pendingStore = FilePendingAuthorizationStore(
                    file = File(directory, "pending-authorization"),
                    keyProvider = HardwareKeyProvider(),
                ),
                browser = CustomTabsAuthorizationSession(applicationContext, logger),
                tokenBinding = tokenBinding,
                dpopKey = dpopKey,
                hasStoredGrant = credentialStore::hasGrant,
            )

            return Versola(
                flow = flow,
                dpop = proofFactory,
                dpopKey = dpopKey,
                coordinator = SessionCoordinator(
                    flow = flow,
                    tokenClient = HttpTokenClient(
                        configuration = configuration,
                        discovery = discovery,
                        httpClient = httpClient,
                        dpop = proofFactory,
                        tokenBinding = tokenBinding,
                    ),
                    credentialStore = credentialStore,
                    retryPolicy = retryPolicy,
                    // What `:core` cannot reach and `spec/state-machine.md` wipes with the
                    // grant: the per-origin nonce caches and the DPoP key (scenario 18).
                    onCredentialsWiped = {
                        proofFactory?.nonces?.clear()
                        dpopKey?.destroy()
                    },
                    logger = logger,
                ),
                baseHttpClient = httpClient,
                edgeBaseUrl = edge,
            )
        }

        private fun defaultHttpClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .build()
    }
}
