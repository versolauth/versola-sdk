package versola.oauth.core

/**
 * What a `login()` may add to the authorization request beyond scopes, `acr_values` and
 * `max_age` (`spec/oauth-sdk-api.md` section 6). Every value is sent as given; the SDK adds
 * nothing to it and never reorders a list.
 *
 * [extra] is for a provider's own parameters (`audience`, `claims`, `kc_idp_hint`). A key that
 * collides with a parameter the SDK sets itself is refused at construction with
 * `Configuration(InvalidConfiguration)`, so an app cannot override `redirect_uri` or `state`
 * by accident or on purpose.
 */
public class AuthorizationParameters(
    /** OpenID Connect Core 3.1.2.1 `prompt`, space-separated values already validated by [Prompt]. */
    public val prompt: Prompt? = null,
    public val loginHint: String? = null,
    /** `ui_locales`, in order of preference. */
    public val uiLocales: List<String> = emptyList(),
    /** RFC 8707 `resource`, repeated; also sent on the token request. */
    public val resources: List<String> = emptyList(),
    public val extra: Map<String, String> = emptyMap(),
) {
    init {
        val reserved = extra.keys.filter { it in RESERVED }
        if (reserved.isNotEmpty()) {
            throw VersolaError.Configuration(
                VersolaError.Configuration.Detail.InvalidConfiguration(
                    "extra authorization parameters cannot override ${reserved.joinToString()}; they are the SDK's",
                ),
            )
        }
    }

    /** The `prompt` values OpenID Connect Core 3.1.2.1 and the `create` extension define. */
    public enum class Prompt(public val value: String) {
        None("none"),
        Login("login"),
        Consent("consent"),
        SelectAccount("select_account"),
        Create("create"),
    }

    public companion object {
        /** The parameters the SDK sets itself; none may arrive through [extra]. */
        public val RESERVED: Set<String> = setOf(
            "client_id", "redirect_uri", "response_type", "response_mode", "scope", "state", "nonce",
            "code_challenge", "code_challenge_method", "request", "request_uri", "prompt", "max_age",
            "acr_values", "resource", "login_hint", "ui_locales", "dpop_jkt", "client_secret",
        )
    }
}

/** Whether a request is pushed (RFC 9126) before the browser opens; `spec/oauth-sdk-api.md` section 7. */
public enum class PushedAuthorization {
    /** Never push, even when advertised; refused when the provider requires pushing. */
    Never,

    /** Push when `pushed_authorization_request_endpoint` is advertised, else the plain request. The default. */
    WhenAdvertised,

    /** Push, and refuse to proceed (`ProviderUnsupported("par")`) when no endpoint is advertised. */
    Required,
}
