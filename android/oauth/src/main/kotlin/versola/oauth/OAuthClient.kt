package versola.oauth

import android.content.Context
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
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
import versola.sdk.browser.CustomTabsAuthorizationSession
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
     * a placeholder (scenario 12).
     */
    public val sessionState: Flow<SessionState> get() = flow.sessionState

    /**
     * The claims of the validated ID token of this session, or null when there is no session.
     * Memory only; the raw token and the `nonce` are not exposed.
     */
    public val claims: IdTokenClaims? get() = coordinator.claims

    /** The provider's metadata, discovered once and cached on disk across restarts and logout. */
    public suspend fun metadata(): ProviderMetadata = flow.metadata()

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
        )
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
    public suspend fun userInfo(): UserInfo {
        // After a cold start the claims are read back from the stored ID token first.
        val subject = coordinator.restoreClaims()?.subject
            ?: throw VersolaError.Reauthenticate(VersolaError.Reauthenticate.Reason.GrantRejected)
        return userInfoClient.fetch(coordinator, subject)
    }

    /**
     * `spec/oauth-sdk-api.md` section 5: a `login()` while one is outstanding, in this process
     * or a previous one, is refused rather than queued behind the open browser or allowed to
     * supersede a request the redirect may still complete. The restored state is read first,
     * so a cold start mid-browser counts.
     */
    private suspend fun refuseWhileAuthorizing() {
        if (flow.sessionState.first() == SessionState.Authorizing) {
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

    /** One authenticated call through [authenticatedClient], with the error taxonomy raised as itself. */
    public suspend fun call(request: Request, origins: Set<String> = configuration.protectedOrigins): Response =
        withContext(Dispatchers.IO) {
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
                }
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
                browser = browser ?: CustomTabsAuthorizationSession(context, logger),
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
) : DiscoveryClient {
    override suspend fun fetch(issuer: String): ProviderMetadata {
        val metadata = delegate.fetch(issuer)
        return endSessionEndpoint?.let { metadata.copy(endSessionEndpoint = it) } ?: metadata
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
