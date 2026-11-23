package versola.sdk

import java.security.MessageDigest
import java.util.Base64
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import versola.oauth.core.RedirectUriKind
import versola.oauth.core.RetryPolicy
import versola.oauth.core.UnlockPolicy
import versola.oauth.core.VersolaError
import versola.oauth.core.VersolaLogger
import versola.oauth.core.VersolaConfiguration as CoreConfiguration

/**
 * What the `Versola` facade is configured with (`spec/versola-sdk-api.md` section 3): the edge
 * the app signs in and calls APIs through, and the client it is registered as. Validated here,
 * so a bad value is `Configuration(InvalidConfiguration)` at construction and never behind a
 * login screen.
 *
 * There is nothing to choose about the protocol: an edge-fronted native client is always
 * DPoP-bound, always pushes its request and always redirects to an `https` link, so none of
 * those is a parameter.
 */
public class VersolaConfiguration(
    /**
     * The public origin of the edge, as its own configuration names it (`edge-url`): `https`, or
     * `http` on `localhost`, `127.0.0.1` or `[::1]` for an edge on the developer's machine. An
     * origin and nothing more: edge computes what every DPoP proof must name from its own origin
     * and the request's path, so a path, query or fragment here could only produce proofs it
     * refuses.
     */
    public val edgeUrl: String,
    public val clientId: String,
    /**
     * Where the browser returns to: an `https` App Link of the app, delivered to
     * `VersolaRedirectActivity`. A private-use scheme or a loopback address is refused, as the
     * server refuses to register one for a client fronted by edge.
     */
    public val redirectUri: String,
    /**
     * The issuer of the deployment, compared as written with the `iss` of the redirect (RFC 9207)
     * and of the ID token. Null takes [edgeUrl]'s origin without a trailing slash, which is what it
     * is for a deployment's own edge; [issuer] then reads as that origin. Set it when the issuer
     * is another address: always for a partner's edge (the issuer is the operator's), and when the
     * deployment writes its issuer differently, a trailing slash included: an issuer passed here
     * is kept exactly as written, since `https://a/` and `https://a` are two issuers. A wrong
     * value fails the first sign-in with `Configuration(IssuerMismatch)`, before any token request.
     */
    issuer: String? = null,
    /**
     * Where the browser returns to after `logout()` ended the server session; an `https` App
     * Link like [redirectUri], registered among the tenant's post-logout redirect URIs. Without
     * it the signed-out page stays open until the user dismisses it and `logout()` reports
     * `sessionEnded = false`; the local sign-out completes either way.
     */
    public val postLogoutRedirectUri: String? = null,
    /**
     * Refuse to sign in with a DPoP key that did not land in hardware
     * (`Configuration(HardwareBindingUnavailable)`, before any request). Off, a software key is
     * used and reported by `keyAttestation()`; the app decides whether it accepts one.
     */
    public val requireHardwareKey: Boolean = false,
    public val unlockPolicy: UnlockPolicy = UnlockPolicy.None,
    public val retryPolicy: RetryPolicy = RetryPolicy.Default,
    /** How far the device clock may be from the server's when the ID token's times are judged; at most 5 minutes. */
    public val clockSkewTolerance: Duration = 60.seconds,
    /**
     * Where the SDK's warnings go. The default is one instance shared by every configuration, so
     * that two configurations built with defaults are the same client for `create()`, which compares
     * loggers by identity.
     */
    public val logger: VersolaLogger = defaultLogger,
    /**
     * The client the SDK's own requests and the authenticated client are built on, so that its
     * timeouts, pool, pinning and proxy are the app's. Null uses one shared client with 10 s
     * connect and read timeouts and a 60 s deadline on a whole call. Redirects are switched off on
     * every request the SDK makes whatever this client does. Its application interceptors stay on
     * those requests: one that logs bodies sees token traffic, and keeping secrets out of logs
     * there is the app's.
     */
    public val httpClient: OkHttpClient? = null,
) {

    /** The issuer the sign-in is held to: the app's own, as written, or the edge's origin. See the constructor's `issuer`. */
    public val issuer: String = issuer ?: edgeUrl.trimEnd('/')

    internal val core: CoreConfiguration

    init {
        val edge = edgeUrl.toHttpUrlOrNull() ?: throw invalid("edgeUrl must be an absolute https URL")
        if (edge.scheme != "https" && edge.host !in LOOPBACK_HOSTS) {
            throw invalid("edgeUrl must be https (http only on a loopback host: localhost, 127.0.0.1, [::1])")
        }
        if (edge.encodedPath != "/" || edge.query != null || edge.fragment != null ||
            edge.username.isNotEmpty() || edge.password.isNotEmpty()
        ) {
            throw invalid("edgeUrl must be an origin: no path, query, fragment or credentials")
        }
        if (clockSkewTolerance < Duration.ZERO || clockSkewTolerance > 5.minutes) {
            throw invalid("clockSkewTolerance must be between zero and 5 minutes")
        }
        // The issuer, the client id and the two redirect URIs are held to the core's rules
        // (https or loopback, no query or fragment, non-blank), and to one more of this facade's:
        // an edge-fronted native client redirects to an https link only.
        core = CoreConfiguration.create(this.issuer, clientId, redirectUri, postLogoutRedirectUri)
        if (core.redirectUri.kind != RedirectUriKind.AppLink) {
            throw invalid("redirectUri must be an https App Link: a client fronted by edge has no other kind")
        }
        if (core.postLogoutRedirectUri?.let { it.kind != RedirectUriKind.AppLink } == true) {
            throw invalid("postLogoutRedirectUri must be an https App Link")
        }
    }

    /** The edge's origin without a trailing slash: what native URLs and the request scope are built on. */
    internal val edgeOrigin: String get() = edgeUrl.trimEnd('/')

    /**
     * Names this client's storage and its Keystore key: a hash, so that neither a file name nor a
     * key alias carries an address, and two clients in one process (two edges, or two client ids)
     * never share a store.
     */
    internal val storageKey: String = Base64.getUrlEncoder().withoutPadding().encodeToString(
        MessageDigest.getInstance("SHA-256")
            .digest("$edgeOrigin\n${this.issuer}\n$clientId".toByteArray(Charsets.UTF_8)),
    ).take(STORAGE_KEY_LENGTH)

    /** Everything a second `create()` for the same storage must agree on; the client and the logger by identity. */
    internal val fingerprint: List<Any?>
        get() = listOf(
            redirectUri, postLogoutRedirectUri, requireHardwareKey, unlockPolicy, clockSkewTolerance,
            retryPolicy.maxAttemptsPerOrigin, retryPolicy.maxTotalAttempts, retryPolicy.initialBackoff,
            retryPolicy.backoffMultiplier, retryPolicy.maxBackoff, retryPolicy.totalBudget,
        )

    internal companion object {
        private const val STORAGE_KEY_LENGTH = 16

        private val defaultLogger: VersolaLogger = AndroidLogger()

        // OkHttp spells the IPv6 loopback without brackets.
        private val LOOPBACK_HOSTS = setOf("localhost", "127.0.0.1", "::1")

        fun invalid(detail: String): VersolaError.Configuration =
            VersolaError.Configuration(VersolaError.Configuration.Detail.InvalidConfiguration(detail))
    }
}
