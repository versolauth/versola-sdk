package kz.versola.sdk

import android.content.Context
import java.io.File
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.flow.Flow
import kz.versola.sdk.browser.CustomTabsAuthorizationSession
import kz.versola.sdk.core.AuthorizationFlow
import kz.versola.sdk.core.AuthorizationGrant
import kz.versola.sdk.core.DiscoveryService
import kz.versola.sdk.core.FileProviderMetadataCache
import kz.versola.sdk.core.HttpDiscoveryClient
import kz.versola.sdk.core.ProviderMetadata
import kz.versola.sdk.core.SessionState
import kz.versola.sdk.core.VersolaConfiguration
import kz.versola.sdk.core.VersolaLogger
import kz.versola.sdk.storage.FilePendingAuthorizationStore
import kz.versola.sdk.storage.HardwareKeyProvider
import okhttp3.OkHttpClient

/**
 * The SDK's entry point: the Android wiring of [AuthorizationFlow], which holds the protocol
 * behaviour itself.
 *
 * What #5 delivers is the browser leg — discovery, the authorization request, the system
 * browser, and a validated [AuthorizationGrant]. Redeeming that grant at the token endpoint
 * is #8, and `login()` — `authorize()` plus that exchange, ending in
 * [SessionState.Authenticated] — arrives with it.
 */
public class Versola internal constructor(
    private val flow: AuthorizationFlow,
) {

    public val configuration: VersolaConfiguration get() = flow.configuration

    /** The state machine of `spec/state-machine.md`, observable. */
    public val sessionState: Flow<SessionState> get() = flow.sessionState

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

    public companion object {

        /**
         * Validates the configuration eagerly and wires the default implementations.
         *
         * The issuer is the only URL supplied here. Edge's base URL is separate
         * configuration, because it is not in the OAuth metadata (#1 §2.1), and it belongs to
         * the authenticated client (#9) rather than to this leg.
         */
        public fun configure(
            context: Context,
            issuer: String,
            clientId: String,
            redirectUri: String,
            logger: VersolaLogger = AndroidLogger(),
            httpClient: OkHttpClient = defaultHttpClient(),
        ): Versola {
            val configuration = VersolaConfiguration.create(issuer, clientId, redirectUri)
            configuration.redirectUriWarning?.let(logger::warn)

            val applicationContext = context.applicationContext
            // noBackupFilesDir: neither the pending request nor, later, the refresh token may
            // be restored onto a different device out of a cloud backup.
            val directory = File(applicationContext.noBackupFilesDir, "versola")

            return Versola(
                AuthorizationFlow(
                    configuration = configuration,
                    discovery = DiscoveryService(
                        issuer = configuration.issuer,
                        client = HttpDiscoveryClient(httpClient),
                        cache = FileProviderMetadataCache(File(directory, "provider-metadata.json")),
                    ),
                    pendingStore = FilePendingAuthorizationStore(
                        file = File(directory, "pending-authorization"),
                        keyProvider = HardwareKeyProvider(),
                    ),
                    browser = CustomTabsAuthorizationSession(applicationContext, logger),
                ),
            )
        }

        private fun defaultHttpClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .build()
    }
}
