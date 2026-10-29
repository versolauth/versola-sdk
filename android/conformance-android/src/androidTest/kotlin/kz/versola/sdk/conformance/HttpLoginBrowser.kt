package kz.versola.sdk.conformance

import kz.versola.sdk.core.BrowserAuthorizationSession
import kz.versola.sdk.core.BrowserOutcome
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.FormBody
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * The browser leg without a browser: auth's login conversation driven over HTTP the way
 * `e2e/.../support/OAuthClient.scala` and `EdgeApi.nativeAuthorize` drive it — open the
 * authorization URI, take the `SSO_CONVERSATION` cookie, read the challenge page's CSRF
 * token, post the login and password, and hand the SDK the redirect auth answers with, the
 * way the OS would hand it to the app. Nothing is followed into the redirect URI itself.
 *
 * Deterministic and headless, which is what a conformance run needs. What it does not prove
 * — Custom Tabs, App Link delivery, the foreground-return detector — is the device tier's.
 *
 * The same object answers the end-session URI `logout()` opens: it fetches the signed-out
 * page with the session cookie the login left behind and "navigates" to the
 * `post_logout_redirect_uri` the page embeds, as the page's script would.
 */
class HttpLoginBrowser(
    base: OkHttpClient,
    private val login: String,
    private val password: String,
) : BrowserAuthorizationSession {

    /** Every URI the SDK asked to open, in order: the authorization request is assertable from it. */
    val opened = mutableListOf<String>()

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
        return if (uri.contains("/logout")) endSession(uri) else signIn(uri)
    }

    override suspend fun awaitPendingRedirect(): BrowserOutcome =
        throw UnsupportedOperationException("process death is scenario 12's, driven differently")

    private fun signIn(uri: String): BrowserOutcome {
        val started = http.newCall(Request.Builder().url(uri).get().build()).execute().use { it.code to it.header("Location") }
        check(started.first in 300..399 || started.first == 200) { "authorize answered ${started.first}" }
        val authUrl = uri.toHttpUrl().let { "${it.scheme}://${it.host}:${it.port}" }

        // One or more conversation steps until auth redirects to the client. A fresh user with
        // a login+password flow and no consent step takes exactly one.
        repeat(5) {
            val challenge = http.newCall(Request.Builder().url("$authUrl/challenge").get().build()).execute().use {
                check(it.code == 200) { "challenge page answered ${it.code}" }
                it.body.string()
            }
            val csrf = CSRF.find(challenge)?.groupValues?.get(1) ?: error("no CSRF token on the challenge page")
            val submit = http.newCall(
                Request.Builder()
                    .url("$authUrl/challenge/login-password")
                    .post(FormBody.Builder().add("login", login).add("password", password).add("csrf", csrf).build())
                    .build(),
            ).execute().use { it.code to it.header("Location") }
            val location = submit.second
            if (submit.first in 300..399 && location != null && !location.contains("/challenge")) {
                return BrowserOutcome.Redirect(location)
            }
        }
        error("the login conversation did not end in a redirect to the client")
    }

    private fun endSession(uri: String): BrowserOutcome {
        val page = http.newCall(Request.Builder().url(uri).get().build()).execute().use {
            check(it.code == 200) { "end_session_endpoint answered ${it.code}" }
            it.body.string()
        }
        // The signed-out page carries the validated redirect (with `state` already appended)
        // for its script to navigate to; a page with none means auth refused the redirect URI
        // or had no session to end, and the browser would simply stay there.
        val redirect = REDIRECT.find(page)?.groupValues?.get(1)?.replace("\\/", "/")
            ?: return BrowserOutcome.UserCancelled
        return BrowserOutcome.Redirect(redirect)
    }

    private companion object {
        val CSRF = Regex(""""csrf"\s*:\s*"([^"]+)"""")
        val REDIRECT = Regex(""""redirectUri"\s*:\s*"([^"]+)"""")
    }
}
