package versola.oauth

import versola.oauth.core.AuthorizationParameters

/**
 * What one `login()` adds to the configured defaults (`spec/oauth-sdk-api.md` section 6). The
 * SDK always sends `response_type=code`, PKCE `S256`, a fresh `state` and `nonce`; nothing here
 * can change that, and a key in [extraParameters] that collides with a parameter the SDK sets
 * is refused at construction.
 */
public class LoginOptions(
    /** Replaces the configured scopes for this request; `openid` is still added. */
    public val scopes: Set<String>? = null,
    public val prompt: AuthorizationParameters.Prompt? = null,
    public val loginHint: String? = null,
    public val uiLocales: List<String> = emptyList(),
    public val acrValues: List<String> = emptyList(),
    /** Seconds; when set, the ID token must carry `auth_time` and it is checked. */
    public val maxAge: Long? = null,
    /** RFC 8707 `resource`, repeated; also sent on the token request. */
    public val resources: List<String> = emptyList(),
    /** A provider's own parameters (`audience`, `claims`, `kc_idp_hint`), sent verbatim. */
    public val extraParameters: Map<String, String> = emptyMap(),
    /**
     * Open the browser without the user's shared browsing state (section 6). Off by default:
     * it breaks passkeys and single sign-on. Honoured by Auth Tab and Custom Tabs providers
     * that support ephemeral browsing; otherwise logged once and the session opens shared.
     */
    public val ephemeralBrowser: Boolean = false,
) {
    internal val parameters: AuthorizationParameters = AuthorizationParameters(
        prompt = prompt,
        loginHint = loginHint,
        uiLocales = uiLocales,
        resources = resources,
        extra = extraParameters,
    )

    public companion object {
        public val Default: LoginOptions = LoginOptions()
    }
}

/** What `logout()` does beyond the unconditional local wipe (`spec/oauth-sdk-api.md` section 12). */
public class LogoutOptions(
    /** End the provider's session through the browser when an `end_session_endpoint` is known. */
    public val endSession: Boolean = true,
    /** Revoke the refresh token when a `revocation_endpoint` is advertised. */
    public val revoke: Boolean = true,
) {
    public companion object {
        public val Default: LogoutOptions = LogoutOptions()
    }
}
