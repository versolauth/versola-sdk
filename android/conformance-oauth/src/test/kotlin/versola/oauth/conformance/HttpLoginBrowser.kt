package versola.oauth.conformance

import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import versola.oauth.core.BrowserAuthorizationSession
import versola.oauth.core.BrowserOutcome

/**
 * The browser leg without a browser, for a generic provider: opens the URI the SDK asks for,
 * follows the provider's own redirects, submits the test user's credentials on the login page
 * through the provider's [ProviderLogin], and hands the SDK the redirect to the client the way
 * the OS would. Nothing is followed into the client's redirect URI itself. The same object
 * answers the end-session URI `logout()` opens.
 *
 * Deterministic and headless, which is what a conformance run needs. Custom Tabs, Auth Tab, App
 * Link delivery and the foreground-return detector are the device tier's to prove.
 *
 * Cookies are kept per name and sent to every request, `Secure` or not: Keycloak marks its
 * session cookies `Secure` even over plain HTTP, and a browser sends them to `localhost` because
 * loopback is a secure context; this jar does the same for the proxy's loopback origin.
 */
class HttpLoginBrowser(
    base: OkHttpClient,
    private val provider: Provider,
    /** Prefixes a redirect to the client starts with: the redirect URI and the post-logout one. */
    private val clientUris: List<String> = listOf(Provider.REDIRECT_URI, Provider.POST_LOGOUT_REDIRECT_URI),
) : BrowserAuthorizationSession {

    /** Every URI the SDK asked to open, in order: the authorization request is assertable from it. */
    val opened = mutableListOf<String>()

    /** When set, the next open is dismissed without a request, as a user closing the tab. */
    var dismissNext: Boolean = false

    private val cookies = object : CookieJar {
        private val store = mutableMapOf<String, Cookie>()
        override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
            cookies.forEach { store[it.name] = it }
        }
        override fun loadForRequest(url: HttpUrl): List<Cookie> = store.values.toList()
    }

    private val http = base.newBuilder().followRedirects(false).followSslRedirects(false).cookieJar(cookies).build()

    override suspend fun authorize(uri: String): BrowserOutcome {
        opened += uri
        if (dismissNext) {
            dismissNext = false
            return BrowserOutcome.UserCancelled
        }
        var response = http.newCall(Request.Builder().url(uri).get().build()).execute()
        // Hops: the provider's own redirects (PAR lands on the login page through one), then
        // the login form, then the redirect to the client. A fresh user with a password form and
        // no consent step takes three; the bound is for a provider that loops.
        repeat(8) {
            val location = response.header("Location")
            when {
                response.code in 300..399 && location != null && clientUris.any { location.startsWith(it) } -> {
                    response.close()
                    return BrowserOutcome.Redirect(location)
                }
                response.code in 300..399 && location != null -> {
                    response.close()
                    response = http.newCall(Request.Builder().url(response.request.url.resolve(location)!!).get().build()).execute()
                }
                response.code == 200 -> {
                    val page = response.body.string()
                    val pageUrl = response.request.url.toString()
                    // A 200 with no login form is where a browser would stay: the end-session
                    // confirmation page a provider shows when it will not redirect, or an error
                    // page. The user "closes the tab".
                    if (!provider.login.hasLoginForm(page)) return BrowserOutcome.UserCancelled
                    response = provider.login.submit(http, page, pageUrl, provider.username, provider.password)
                }
                else -> error("the provider answered ${response.code} at ${response.request.url}: ${response.body.string().take(300)}")
            }
        }
        error("the login conversation did not end in a redirect to the client")
    }

    override suspend fun awaitPendingRedirect(): BrowserOutcome =
        throw UnsupportedOperationException("process death is scenario 12's, driven differently")
}

/** Whether [page] is the provider's login page; a page without the form is left as is. */
fun ProviderLogin.hasLoginForm(page: String): Boolean = when (this) {
    KeycloakLogin -> page.contains("id=\"kc-form-login\"")
    else -> true
}

/** Reads [Response]'s body as text and closes it. */
fun Response.text(): String = use { it.body.string() }
