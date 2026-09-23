package kz.versola.sdk.core

import java.net.URI
import java.net.URISyntaxException

/** How the redirect gets back to the app, which decides how much it can be trusted. */
public enum class RedirectUriKind {
    /**
     * An `https` URI backed by Digital Asset Links. The OS verifies the association, so no
     * other app can claim it. Preferred, per RFC 8252 §7.2 and #5.
     */
    AppLink,

    /** `http://127.0.0.1` or `http://localhost`. RFC 8252 §7.3; rare on mobile. */
    Loopback,

    /**
     * A private-use scheme. Accepted, but **any app on the device can register the same
     * scheme** — Android resolves the collision arbitrarily. Carries a first-run warning.
     */
    CustomScheme,
}

/**
 * The redirect target, already checked against what the authorization endpoint will accept:
 * `AuthorizeRequestParser.parseRedirectUri` requires an absolute URI with no fragment and
 * refuses anything the client is not registered for.
 */
public class RedirectUri internal constructor(
    public val value: String,
    public val kind: RedirectUriKind,
) {
    override fun toString(): String = value

    public companion object {
        internal fun parse(raw: String): RedirectUri {
            val uri = try {
                URI(raw)
            } catch (e: URISyntaxException) {
                throw invalid("redirectUri is not a valid URI: $raw", e)
            }
            if (!uri.isAbsolute) throw invalid("redirectUri must be absolute: $raw")
            if (uri.fragment != null) throw invalid("redirectUri must not carry a fragment: $raw")

            val scheme = uri.scheme.lowercase()
            val host = uri.host?.lowercase()
            val kind = when {
                // An opaque https value such as "https:callback" has no host and is not
                // something Android can route as an HTTPS App Link redirect.
                scheme == "https" && host.isNullOrEmpty() ->
                    throw invalid("redirectUri must have a host: $raw")
                scheme == "https" -> RedirectUriKind.AppLink
                scheme == "http" && (host == "127.0.0.1" || host == "localhost" || host == "[::1]") ->
                    RedirectUriKind.Loopback
                // Plain http to anywhere else is cleartext to a host the app does not control.
                scheme == "http" -> throw invalid("redirectUri must not be cleartext http: $raw")
                else -> RedirectUriKind.CustomScheme
            }
            return RedirectUri(raw, kind)
        }

        private fun invalid(detail: String, cause: Throwable? = null) = VersolaError.Configuration(
            VersolaError.Configuration.Detail.InvalidConfiguration(detail),
            cause,
        )
    }
}

/**
 * What `configure()` was given. Validated eagerly: a bad issuer or redirect URI is a
 * deployment mistake, and `spec/errors.md` puts those in `Configuration` — fail at
 * configuration time rather than behind a login screen.
 */
public class VersolaConfiguration internal constructor(
    public val issuer: String,
    public val clientId: String,
    public val redirectUri: RedirectUri,
) {
    /**
     * The warning to emit on a redirect scheme the OS does not verify. Non-null exactly when
     * one is warranted, so the caller has nothing to decide.
     */
    public val redirectUriWarning: String?
        get() = when (redirectUri.kind) {
            RedirectUriKind.AppLink -> null
            RedirectUriKind.Loopback -> null
            RedirectUriKind.CustomScheme ->
                "redirectUri '$redirectUri' uses a private-use scheme. Any app on this device " +
                    "can register the same scheme and receive the authorization response. Prefer " +
                    "a verified App Link (https) with a matching assetlinks.json."
        }

    public companion object {
        /**
         * Public because [AuthorizationFlow] is: anything wiring the core directly needs a
         * validated configuration, and the validation is the reason this type exists.
         */
        public fun create(issuer: String, clientId: String, redirectUri: String): VersolaConfiguration {
            val parsedIssuer = try {
                URI(issuer)
            } catch (e: URISyntaxException) {
                throw invalid("issuer is not a valid URI: $issuer", e)
            }
            if (parsedIssuer.scheme?.lowercase() != "https") {
                throw invalid("issuer must be https: $issuer")
            }
            if (parsedIssuer.host.isNullOrEmpty()) {
                // An opaque value such as "https:issuer" passes the scheme check above but has
                // no host to append the well-known path to; catch it here rather than letting
                // discovery fail later outside the Configuration error contract.
                throw invalid("issuer must have a host: $issuer")
            }
            if (!parsedIssuer.query.isNullOrEmpty() || !parsedIssuer.fragment.isNullOrEmpty()) {
                // RFC 8414 §2: the issuer identifier carries no query or fragment, because the
                // well-known path is appended to it verbatim.
                throw invalid("issuer must not carry a query or fragment: $issuer")
            }
            if (clientId.isBlank()) throw invalid("clientId must not be blank")

            return VersolaConfiguration(
                issuer = issuer.trimEnd('/'),
                clientId = clientId,
                redirectUri = RedirectUri.parse(redirectUri),
            )
        }

        private fun invalid(detail: String, cause: Throwable? = null) = VersolaError.Configuration(
            VersolaError.Configuration.Detail.InvalidConfiguration(detail),
            cause,
        )
    }
}
