package versola.oauth.conformance

import okhttp3.OkHttpClient
import okhttp3.Response

/**
 * The staged OpenID Provider (`conformance/providers/<name>/docker-compose.yml`) and the user the
 * harness signs in as, from the environment. With no issuer set every scenario is skipped as a
 * JUnit assumption: the build job's `test` must stay a unit run, and a half-configured provider
 * must not pass as "no scenarios failed".
 *
 * `spec/providers.md` section 4 lists what each provider is expected to advertise; the tests
 * read the live discovery document rather than trusting that table.
 */
class Provider private constructor(
    /** The issuer as the provider announces it: what the SDK is configured with, through the proxy. */
    val issuer: String,
    val name: String,
    val username: String,
    val password: String,
    val login: ProviderLogin,
) {
    /** `scheme://host[:port]` of the issuer: where the proxy forwards to. */
    val origin: String = issuer.substringBefore("://") + "://" + issuer.substringAfter("://").substringBefore('/')

    /** The issuer's path (`/realms/conformance`), re-rooted at the proxy's origin. */
    val issuerPath: String = issuer.removePrefix(origin)

    companion object {
        /** The public client of the realm: authorization code + PKCE, refresh tokens on. */
        const val CLIENT_ID = "conformance-app"

        /** The same client with refresh tokens off and ten-second access tokens (scenario 31). */
        const val NO_REFRESH_CLIENT_ID = "conformance-app-norefresh"

        /** Registered on both clients; `example.com` because no browser ever opens it. */
        const val REDIRECT_URI = "https://conformance.example.com/oauth"
        const val POST_LOGOUT_REDIRECT_URI = "https://conformance.example.com/signed-out"

        fun fromEnvironment(): Provider? {
            val issuer = System.getenv("OAUTH_CONFORMANCE_ISSUER")?.trim()?.trimEnd('/')?.takeIf { it.isNotEmpty() }
                ?: return null
            val name = System.getenv("OAUTH_CONFORMANCE_PROVIDER")?.trim()?.takeIf { it.isNotEmpty() } ?: "keycloak"
            val login = when (name) {
                "keycloak" -> KeycloakLogin
                else -> error("no login driver for provider '$name' (conformance/README.md, Providers)")
            }
            return Provider(
                issuer = issuer,
                name = name,
                username = System.getenv("OAUTH_CONFORMANCE_USERNAME")?.takeIf { it.isNotEmpty() } ?: "alice",
                password = System.getenv("OAUTH_CONFORMANCE_PASSWORD")?.takeIf { it.isNotEmpty() } ?: "alice-password",
                login = login,
            )
        }
    }
}

/**
 * The one provider-specific step of the browser leg: given the page the authorization request
 * ended on, submit the test user's credentials and return the provider's answer, which the
 * caller follows until it leaves the provider. Everything else about the leg (redirect hops,
 * cookies, the end-session page) is the same for every provider.
 */
interface ProviderLogin {
    fun submit(http: OkHttpClient, page: String, pageUrl: String, username: String, password: String): Response
}

/**
 * Keycloak 26: the authorization request lands (after one redirect under PAR) on the realm's
 * login page, whose `kc-form-login` form posts `username`, `password` and an empty
 * `credentialId` to `login-actions/authenticate?session_code=…`. The answer to a correct
 * password is a 302 to the client's redirect URI. Observed against `quay.io/keycloak/keycloak:26.4`;
 * the field names are not in Keycloak's documentation (`spec/providers.md`, Not verified).
 */
object KeycloakLogin : ProviderLogin {
    private val ACTION = Regex("""<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"""")

    override fun submit(http: OkHttpClient, page: String, pageUrl: String, username: String, password: String): Response {
        val action = ACTION.find(page)?.groupValues?.get(1)?.replace("&amp;", "&")
            ?: error("no kc-form-login form on $pageUrl: ${page.take(400)}")
        return http.newCall(
            okhttp3.Request.Builder()
                .url(action)
                .post(
                    okhttp3.FormBody.Builder()
                        .add("username", username)
                        .add("password", password)
                        .add("credentialId", "")
                        .build(),
                )
                .build(),
        ).execute()
    }
}
