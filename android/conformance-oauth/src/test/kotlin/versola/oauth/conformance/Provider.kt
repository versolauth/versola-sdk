package versola.oauth.conformance

import okhttp3.FormBody
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response

/**
 * The staged OpenID Provider (`conformance/providers/<name>/docker-compose.yml`) and the user the
 * harness signs in as, from the environment. With no issuer set every scenario is skipped as a
 * JUnit assumption: the build job's `test` must stay a unit run, and a half-configured provider
 * must not pass as "no scenarios failed".
 *
 * What differs per provider is a [Profile]: where its issuer path sits, which port the proxy
 * must listen on (Hydra builds its URLs from configuration, so it is told the proxy's address
 * in advance), the scopes that buy a refresh token, and the login conversation. Everything the
 * scenarios assert is read from the live discovery document, never from the profile
 * (`spec/providers.md` section 4 is what each provider is expected to advertise).
 */
class Provider private constructor(
    /** The provider's issuer as it is reached directly: where the proxy forwards to. */
    val issuer: String,
    val profile: Profile,
    val username: String,
    val password: String,
) {
    val name: String get() = profile.key
    val login: ProviderLogin get() = profile.login

    /** `scheme://host[:port]` of the issuer: where the proxy forwards to. */
    val origin: String = issuer.substringBefore("://") + "://" + issuer.substringAfter("://").substringBefore('/')

    /** The issuer's path (`/realms/conformance` on Keycloak, nothing on Hydra), re-rooted at the proxy's origin. */
    val issuerPath: String = if (profile.issuerAtRoot) "" else issuer.removePrefix(origin)

    /** The scopes the main client is configured with: a refresh token is issued for them. */
    val scopes: Set<String> get() = profile.scopes

    /** The scopes for [NO_REFRESH_CLIENT_ID]: no refresh token is issued for them (scenario 31). */
    val noRefreshScopes: Set<String> get() = profile.noRefreshScopes

    /** The port the proxy listens on; 0 picks a free one. */
    val proxyPort: Int = System.getenv("OAUTH_CONFORMANCE_PROXY_PORT")?.trim()?.toIntOrNull() ?: profile.proxyPort

    /** One per `conformance/providers/<name>/`. */
    enum class Profile(
        val login: ProviderLogin,
        val issuerAtRoot: Boolean,
        val proxyPort: Int,
        val scopes: Set<String>,
        val noRefreshScopes: Set<String>,
        val defaultUsername: String,
        val defaultPassword: String,
    ) {
        /** Refresh tokens by default (`spec/providers.md`); the issuer is derived from the request. */
        KEYCLOAK(
            login = KeycloakLogin,
            issuerAtRoot = false,
            proxyPort = 0,
            scopes = setOf("openid", "profile"),
            noRefreshScopes = setOf("openid", "profile"),
            defaultUsername = "alice",
            defaultPassword = "alice-password",
        ),

        /**
         * A refresh token needs `offline_access` and the consent app granting it; the issuer
         * is `urls.self.issuer` from `hydra.yml`, which names the proxy's fixed port.
         */
        HYDRA(
            login = HydraLogin,
            issuerAtRoot = true,
            proxyPort = 14444,
            scopes = setOf("openid", "profile", "offline_access"),
            noRefreshScopes = setOf("openid", "profile"),
            defaultUsername = "foo@bar.com",
            defaultPassword = "foobar",
        );

        /** The directory name under `conformance/providers/` and the `OAUTH_CONFORMANCE_PROVIDER` value. */
        val key: String get() = name.lowercase()
    }

    companion object {
        /** The public client: authorization code + PKCE, refresh tokens for [scopes]. */
        const val CLIENT_ID = "conformance-app"

        /** The same client without refresh tokens and with ten-second access tokens (scenario 31). */
        const val NO_REFRESH_CLIENT_ID = "conformance-app-norefresh"

        /** Registered on both clients; `example.com` because no browser ever opens it. */
        const val REDIRECT_URI = "https://conformance.example.com/oauth"
        const val POST_LOGOUT_REDIRECT_URI = "https://conformance.example.com/signed-out"

        fun fromEnvironment(): Provider? {
            val issuer = System.getenv("OAUTH_CONFORMANCE_ISSUER")?.trim()?.trimEnd('/')?.takeIf { it.isNotEmpty() }
                ?: return null
            val name = System.getenv("OAUTH_CONFORMANCE_PROVIDER")?.trim()?.takeIf { it.isNotEmpty() } ?: "keycloak"
            val profile = Profile.entries.firstOrNull { it.key == name }
                ?: error("no profile for provider '$name' (conformance/README.md, Providers)")
            return Provider(
                issuer = issuer,
                profile = profile,
                username = System.getenv("OAUTH_CONFORMANCE_USERNAME")?.takeIf { it.isNotEmpty() } ?: profile.defaultUsername,
                password = System.getenv("OAUTH_CONFORMANCE_PASSWORD")?.takeIf { it.isNotEmpty() } ?: profile.defaultPassword,
            )
        }
    }
}

/**
 * The provider-specific half of the browser leg: given a page the conversation landed on,
 * act on it as the test user would (submit credentials, grant consent, confirm sign-out) and
 * return the provider's answer, which the caller follows; or null for a page with nothing to
 * act on, where a browser would simply stay (an error page, a confirmation the provider will
 * not redirect from), which the caller reports as the user closing the tab.
 */
interface ProviderLogin {
    fun step(http: OkHttpClient, page: String, pageUrl: String, username: String, password: String): Response?
}

/** The `action` of the first `<form>` on [page] matching [marker], HTML-unescaped and resolved against [pageUrl]. */
internal fun formAction(page: String, marker: Regex, pageUrl: String): String? {
    val form = marker.find(page) ?: return null
    val action = Regex("""action="([^"]*)"""").find(form.value)?.groupValues?.get(1)?.replace("&amp;", "&") ?: return null
    return pageUrl.toHttpUrlOrNull()?.resolve(action)?.toString()
}

internal fun post(http: OkHttpClient, action: String, fields: List<Pair<String, String>>): Response =
    http.newCall(
        Request.Builder().url(action).post(FormBody.Builder().apply { fields.forEach { (n, v) -> add(n, v) } }.build()).build(),
    ).execute()

/**
 * Keycloak 26: the authorization request lands (after one redirect under PAR) on the realm's
 * login page, whose `kc-form-login` form posts `username`, `password` and an empty
 * `credentialId` to `login-actions/authenticate?session_code=…`. The answer to a correct
 * password is a 302 to the client's redirect URI. Observed against `quay.io/keycloak/keycloak:26.4`;
 * the field names are not in Keycloak's documentation (`spec/providers.md`, Not verified).
 */
object KeycloakLogin : ProviderLogin {
    private val LOGIN_FORM = Regex("""<form[^>]*id="kc-form-login"[^>]*>""")

    override fun step(http: OkHttpClient, page: String, pageUrl: String, username: String, password: String): Response? {
        val action = formAction(page, LOGIN_FORM, pageUrl) ?: return null
        return post(http, action, listOf("username" to username, "password" to password, "credentialId" to ""))
    }
}

/**
 * Ory Hydra with Ory's reference login-consent app (`oryd/hydra-login-consent-node`): three
 * pages, each a form with a `_csrf` token (paired with the app's `_csrf` cookie) and the
 * `challenge`. Login posts `email` and `password` (the app's fixed user); consent posts every
 * `grant_scope` checkbox the page offers (the scopes the request asked for) and
 * `submit=Allow access`; the logout page confirms unless `submit=No`. Each answer is a 302
 * back to hydra, which redirects on. Observed against `v26.2.0` (`spec/providers.md`).
 */
object HydraLogin : ProviderLogin {
    private val FORM = Regex("""<form[^>]*>""")
    private val CSRF = Regex("""name="_csrf"\s+value="([^"]*)"""")
    private val CHALLENGE = Regex("""name="challenge"\s+value="([^"]*)"""")
    private val GRANT_SCOPE = Regex("""<input[^>]*name="grant_scope"[^>]*>""")
    private val VALUE = Regex("""value="([^"]*)"""")

    override fun step(http: OkHttpClient, page: String, pageUrl: String, username: String, password: String): Response? {
        val action = formAction(page, FORM, pageUrl) ?: return null
        val csrf = CSRF.find(page)?.groupValues?.get(1) ?: return null
        val challenge = CHALLENGE.find(page)?.groupValues?.get(1) ?: return null
        val common = listOf("_csrf" to csrf, "challenge" to challenge)
        return when {
            page.contains("name=\"email\"") ->
                post(http, action, common + listOf("email" to username, "password" to password, "submit" to "Log in"))
            page.contains("name=\"grant_scope\"") -> {
                val scopes = GRANT_SCOPE.findAll(page).mapNotNull { VALUE.find(it.value)?.groupValues?.get(1) }.toList()
                post(http, action, common + scopes.map { "grant_scope" to it } + ("submit" to "Allow access"))
            }
            // The logout confirmation: anything but "No" confirms.
            pageUrl.contains("/logout") -> post(http, action, common + ("submit" to "Yes"))
            else -> null
        }
    }
}
