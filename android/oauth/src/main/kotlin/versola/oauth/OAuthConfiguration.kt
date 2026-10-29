package versola.oauth

import java.net.URI
import java.net.URISyntaxException
import java.security.MessageDigest
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import okhttp3.OkHttpClient
import java.util.Base64
import versola.oauth.core.ProviderMetadata
import versola.oauth.core.PushedAuthorization
import versola.oauth.core.RetryPolicy
import versola.oauth.core.TokenBinding
import versola.oauth.core.UnlockPolicy
import versola.oauth.core.VersolaConfiguration
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaLogger

/**
 * The endpoints of a provider that publishes no discovery document, or publishes it where the
 * SDK will not look (`spec/oauth-sdk-api.md` section 3). Every URL is `https`. Capabilities not
 * listed here are absent: no `revocationEndpoint` means sign-out skips revocation, no
 * `pushedAuthorizationRequestEndpoint` means the plain request, and so on.
 */
public class ProviderEndpoints(
    /** What the ID token's `iss` must equal, byte for byte. */
    public val issuer: String,
    public val authorizationEndpoint: String,
    public val tokenEndpoint: String,
    /** Where the ID-token signing keys are. Required: an ID token that cannot be verified is refused. */
    public val jwksUri: String,
    public val userinfoEndpoint: String? = null,
    public val revocationEndpoint: String? = null,
    public val endSessionEndpoint: String? = null,
    public val pushedAuthorizationRequestEndpoint: String? = null,
    /** `id_token_signing_alg_values_supported`; empty means the closed set of section 11 as a whole. */
    public val idTokenSigningAlgValuesSupported: List<String> = emptyList(),
) {
    internal fun toMetadata(): ProviderMetadata = ProviderMetadata(
        issuer = issuer,
        authorizationEndpoint = authorizationEndpoint,
        tokenEndpoint = tokenEndpoint,
        userinfoEndpoint = userinfoEndpoint,
        revocationEndpoint = revocationEndpoint,
        endSessionEndpoint = endSessionEndpoint,
        jwksUri = jwksUri,
        codeChallengeMethodsSupported = listOf("S256"),
        responseTypesSupported = listOf("code"),
        grantTypesSupported = listOf("authorization_code", "refresh_token"),
        pushedAuthorizationRequestEndpoint = pushedAuthorizationRequestEndpoint,
        idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported,
    )

    internal fun urls(): List<Pair<String, String?>> = listOf(
        "issuer" to issuer,
        "authorizationEndpoint" to authorizationEndpoint,
        "tokenEndpoint" to tokenEndpoint,
        "jwksUri" to jwksUri,
        "userinfoEndpoint" to userinfoEndpoint,
        "revocationEndpoint" to revocationEndpoint,
        "endSessionEndpoint" to endSessionEndpoint,
        "pushedAuthorizationRequestEndpoint" to pushedAuthorizationRequestEndpoint,
    )
}

/**
 * What [OAuthClient.create] is given (`spec/oauth-sdk-api.md` section 3). Validated eagerly: a
 * bad value is `Configuration(InvalidConfiguration)` here, not behind a login screen.
 *
 * There is no `clientSecret`, on purpose: a native app cannot keep one (RFC 8252 section 8.5),
 * so the type does not let an integrator pretend otherwise.
 */
public class OAuthConfiguration(
    /** The issuer whose discovery document configures everything else. Exclusive with [endpoints]. */
    public val issuer: String? = null,
    /** Explicit endpoints for a provider without discovery. Exclusive with [issuer]. */
    public val endpoints: ProviderEndpoints? = null,
    public val clientId: String,
    /** A verified `https` link (preferred), a loopback URI, or a private-use scheme (warned about). */
    public val redirectUri: String,
    /** Where RP-initiated logout sends the browser; not sent when absent. */
    public val postLogoutRedirectUri: String? = null,
    /** The scopes `login()` asks for unless its options say otherwise; `openid` is always included. */
    public val scopes: Set<String> = setOf("openid"),
    /** Bearer unless the resource servers verify DPoP (section 9). */
    public val tokenBinding: TokenBinding = TokenBinding.Bearer,
    /** Push the request when the provider advertises an endpoint for it (section 7). */
    public val pushedAuthorization: PushedAuthorization = PushedAuthorization.WhenAdvertised,
    /**
     * The only origins the authenticated client sends a token to, `https://host[:port]`.
     * May be empty here and given per client instead (section 10).
     */
    public val protectedOrigins: Set<String> = emptySet(),
    /**
     * Replaces the discovered `end_session_endpoint`, or supplies one when discovery has none.
     * The parameters stay those of RP-Initiated Logout 1.0 (section 12).
     */
    public val endSessionEndpoint: String? = null,
    public val retryPolicy: RetryPolicy = RetryPolicy.Default,
    public val unlockPolicy: UnlockPolicy = UnlockPolicy.None,
    /** Tolerance for `exp`, `iat` and `auth_time` in ID-token validation; at most five minutes. */
    public val clockSkewTolerance: Duration = 60.seconds,
    public val logger: VersolaLogger = LogcatLogger(),
    /** The client the SDK's own requests go through; its timeouts and pool are the app's. */
    public val httpClient: OkHttpClient = defaultHttpClient(),
) {
    /** The issuer the ID token's `iss` is held to, whichever way it was configured. */
    public val issuerIdentifier: String = (issuer ?: endpoints?.issuer ?: "").trimEnd('/')

    /** The scopes as they are sent: the configured set, with `openid` present. */
    public val effectiveScopes: Set<String> = scopes + "openid"

    internal val core: VersolaConfiguration

    /**
     * What keeps one client's storage apart from another's in the same app: the issuer and the
     * client id, hashed. Two configurations with the same key must be the same configuration
     * (`OAuthClient.create`), and a later multi-account feature keys accounts under it.
     */
    internal val storageKey: String

    /** Everything that makes two configurations the same client, excluding the HTTP client and the logger. */
    internal val fingerprint: String

    init {
        if ((issuer == null) == (endpoints == null)) {
            throw invalid("exactly one of issuer and endpoints must be given")
        }
        endpoints?.urls()?.forEach { (name, url) -> url?.let { requireHttps(name, it) } }
        endSessionEndpoint?.let { requireHttps("endSessionEndpoint", it) }
        protectedOrigins.forEach { requireOrigin(it) }
        if (clockSkewTolerance.isNegative() || clockSkewTolerance > 5.minutes) {
            throw invalid("clockSkewTolerance must be between 0 and 5 minutes: $clockSkewTolerance")
        }
        if (scopes.any { it.isBlank() || it.any(Char::isWhitespace) }) {
            throw invalid("a scope is a single token without whitespace: $scopes")
        }
        // The shared validation of issuer, client id and redirect URIs lives in the core.
        core = VersolaConfiguration.create(
            issuer = issuer ?: checkNotNull(endpoints).issuer,
            clientId = clientId,
            redirectUri = redirectUri,
            postLogoutRedirectUri = postLogoutRedirectUri,
        )
        storageKey = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest("$issuerIdentifier\n$clientId".toByteArray()),
        ).take(STORAGE_KEY_LENGTH)
        fingerprint = listOf(
            issuerIdentifier, endpoints?.urls()?.toString(), clientId, redirectUri, postLogoutRedirectUri,
            effectiveScopes.sorted(), tokenBinding.toString(), pushedAuthorization, protectedOrigins.sorted(),
            endSessionEndpoint, retryPolicy.toString(), unlockPolicy, clockSkewTolerance,
        ).joinToString("\u0000")
    }

    private fun requireHttps(name: String, url: String) {
        val uri = try {
            URI(url)
        } catch (e: URISyntaxException) {
            throw invalid("$name is not a valid URI: $url")
        }
        val scheme = uri.scheme?.lowercase()
        // The same allowance the core gives the issuer: cleartext to the developer's own
        // machine (a stack under `adb reverse`, a test server), never to a remote host.
        val loopback = scheme == "http" && uri.host in LOOPBACK_HOSTS
        if (!uri.isAbsolute || uri.host.isNullOrEmpty() || !(scheme == "https" || loopback)) {
            throw invalid("$name must be an absolute https URL (http only on loopback): $url")
        }
    }

    private fun requireOrigin(origin: String) {
        requireHttps("protectedOrigins", origin)
        val uri = URI(origin)
        if (!(uri.rawPath.isNullOrEmpty() || uri.rawPath == "/") || uri.rawQuery != null || uri.rawFragment != null) {
            throw invalid("a protected origin is scheme://host[:port] with no path, query or fragment: $origin")
        }
    }

    public companion object {
        private const val STORAGE_KEY_LENGTH = 16
        private val LOOPBACK_HOSTS = setOf("127.0.0.1", "localhost", "[::1]")

        internal fun invalid(detail: String): VersolaError.Configuration = VersolaError.Configuration(
            VersolaError.Configuration.Detail.InvalidConfiguration(detail),
        )

        private fun defaultHttpClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
            .readTimeout(10, java.util.concurrent.TimeUnit.SECONDS)
            .build()
    }
}
