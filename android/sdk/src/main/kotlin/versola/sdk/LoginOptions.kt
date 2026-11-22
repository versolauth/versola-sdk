package versola.sdk

import versola.oauth.core.AuthorizationParameters
import versola.sdk.core.EdgeAuthorizationStarter

/**
 * What one `login()` asks for (`spec/versola-sdk-api.md` section 5). Each option is one of the
 * authorization parameters edge forwards from `/native/start`, and there is no other: edge drops
 * a parameter it does not forward without an error, so a free-form map here would let an app set
 * something that silently does nothing.
 *
 * The SDK always sends the redirect URI and a fresh `nonce`; PKCE, `state` and the binding to the
 * device key are edge's and cannot be supplied.
 */
public class LoginOptions(
    /** Added to `openid` and `offline_access`, which every sign-in asks for: the facade is a session. */
    public val scopes: Set<String> = emptySet(),
    /** The authentication contexts to ask for; [Acr.Sensitive] is the built-in one. Set by `stepUp()` from the challenge. */
    public val acrValues: List<String> = emptyList(),
    /** Seconds since the user last authenticated; when set, the ID token's `auth_time` is checked against it. */
    public val maxAge: Long? = null,
    public val prompt: AuthorizationParameters.Prompt? = null,
    public val loginHint: String? = null,
    /** `ui_locales`, in order of preference. */
    public val uiLocales: List<String> = emptyList(),
    /** RFC 8707 `resource`, one per value. */
    public val resources: List<String> = emptyList(),
    /** OpenID Connect Core 5.5 `claims`: a JSON object as text, sent as given. */
    public val claims: String? = null,
    /** RFC 9396 `authorization_details`: a JSON array as text, sent as given. */
    public val authorizationDetails: String? = null,
    /**
     * Open the browser without the user's shared browsing state. Off by default: it breaks
     * passkeys and single sign-on. Best effort where the browser supports it.
     */
    public val ephemeralBrowser: Boolean = false,
) {
    internal val parameters: AuthorizationParameters = AuthorizationParameters(
        prompt = prompt,
        loginHint = loginHint,
        uiLocales = uiLocales,
        resources = resources,
        // The two the core has no field for travel under their wire names; the edge starter
        // forwards exactly these two and nothing else of the map.
        extra = buildMap {
            claims?.let { put(EdgeAuthorizationStarter.CLAIMS, it) }
            authorizationDetails?.let { put(EdgeAuthorizationStarter.AUTHORIZATION_DETAILS, it) }
        },
    )
}

/** What `logout()` does beyond the local wipe, which is unconditional (`spec/versola-sdk-api.md` section 12). */
public class LogoutOptions(
    /**
     * End the user's session at the issuer through the system browser. Off, no browser opens on
     * sign-out, the single sign-on session survives, and the next `login()` may complete without
     * asking who the user is.
     */
    public val endSession: Boolean = true,
    /** Revoke the refresh token through edge. */
    public val revoke: Boolean = true,
)

/** Authentication context class references a Versola deployment has built in. */
public object Acr {
    /**
     * The strongest factor the user has that the client's sign-in flow can ask for (a passkey,
     * else a password, else a one-time code). What an endpoint that guards something sensitive
     * asks for; pair it with a maximum age, since it says how and not how recently.
     */
    public const val Sensitive: String = "sensitive"
}
