package versola.oauth.flutter.conformance

import io.flutter.embedding.engine.plugins.FlutterPlugin
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import versola.oauth.OAuthClient
import versola.oauth.ProviderEndpoints
import versola.oauth.conformance.Provider
import versola.oauth.conformance.ProviderConformance
import versola.oauth.conformance.ReversingKeyProvider
import versola.oauth.core.BrowserAuthorizationSession
import versola.oauth.core.BrowserOutcome
import versola.oauth.core.PushedAuthorization
import versola.oauth.flutter.AccessTokenFailure
import versola.oauth.flutter.AccessTokenMessage
import versola.oauth.flutter.AccessTokenOk
import versola.oauth.flutter.AccessTokenResult
import versola.oauth.flutter.ConfigurationMessage
import versola.oauth.flutter.CreateFailure
import versola.oauth.flutter.CreateResult
import versola.oauth.flutter.EndpointsMessage
import versola.oauth.flutter.ErrorCategoryMessage
import versola.oauth.flutter.ErrorMessage
import versola.oauth.flutter.PushedAuthorizationMessage
import versola.oauth.flutter.TokenBindingMessage
import versola.oauth.flutter.UnlockPolicyMessage
import versola.oauth.flutter.UserInfoFailure
import versola.oauth.flutter.UserInfoOk
import versola.oauth.flutter.UserInfoResult
import versola.oauth.flutter.VersolaOAuthPlugin
import versola.oauth.flutter.VoidFailure
import versola.oauth.flutter.VoidOk
import versola.oauth.flutter.VoidResult

/**
 * What every bridge scenario starts from: the generic facade's conformance driver
 * ([ProviderConformance]: the provider from the environment or the class skipped, the rewriting
 * proxy, the HTTP browser leg, the transcript on the SDK's HTTP client), with the plugin's
 * `VersolaOAuthPlugin` attached to a [FakeBinaryMessenger] and every operation under test sent
 * through its Pigeon host API by a [DartSide], as a Flutter app's Dart code would.
 *
 * **How the driver's wiring reaches the plugin.** The browser leg and the Keystore-wrapped key
 * are replaced through the SDK's opt-in constructor, which the plugin must not call
 * (`flutter.md`: the plugin uses the public API only). [bridge] therefore builds the native
 * client first, with the driver's wiring, and then asks the plugin to `create` the same
 * configuration through the host API. The SDK keeps one instance per configuration per process
 * and returns the first one to a second `create` with the same configuration (its fingerprint:
 * everything but the HTTP client and the logger), so the plugin ends up holding the driver's
 * instance. A bridge that converted any field differently from the native configuration the
 * test built would not find that instance: `create` would be refused for a different
 * configuration, and the test fails at its first line.
 *
 * What the bridge does not carry stays on the native instance, used only to *observe* (the
 * discovery document, the configuration's retry policy): `metadata()` and the authenticated HTTP
 * client are not Flutter API (`spec/oauth-sdk-api.md` section 10: Flutter has `accessToken()`
 * only), so a scenario's authenticated calls are made here the way a Flutter app makes them, with
 * the token the bridge hands over.
 */
abstract class BridgeConformance : ProviderConformance() {

    protected val messenger = FakeBinaryMessenger()
    private val engine = unsafeNull<io.flutter.embedding.engine.FlutterEngine>()
    private lateinit var plugin: VersolaOAuthPlugin
    private lateinit var binding: FlutterPlugin.FlutterPluginBinding
    private val darts = mutableListOf<DartSide>()

    /** The app's own HTTP client: what `dio` or `http` is in a Flutter app. Not the SDK's, so not in the transcript. */
    protected val app = OkHttpClient()

    @Before
    fun attachPlugin() {
        plugin = VersolaOAuthPlugin()
        binding = FlutterPlugin.FlutterPluginBinding(
            application, engine, messenger, unsafeNull(), unsafeNull(), unsafeNull(), unsafeNull(),
        )
        plugin.onAttachedToEngine(binding)
    }

    @After
    fun detachPlugin() {
        if (!::plugin.isInitialized) return
        plugin.onDetachedFromEngine(binding)
        // Nothing credential-shaped crossed the bridge (flutter.md, "What crosses the bridge"): no
        // refresh token, no raw ID token, no authorization code, no PKCE verifier in any reply or
        // event, and the access token only in the reply of accessToken().
        val secrets = transcript.entries.flatMap { entry ->
            listOfNotNull(
                entry.responseJson?.get("refresh_token")?.toString()?.trim('"'),
                entry.responseJson?.get("id_token")?.toString()?.trim('"'),
                entry.form["code"],
                entry.form["code_verifier"],
            )
        }.filter { it.length > 8 }
        val accessTokens = transcript.entries.mapNotNull { it.responseJson?.get("access_token")?.toString()?.trim('"') }.filter { it.length > 8 }
        darts.flatMap { it.received }.forEach { value ->
            (secrets + accessTokens).forEach { secret -> assertFalse("a credential crossed the bridge: $value", value.contains(secret)) }
        }
    }

    /** A native client and its handle, once the plugin has created it through the host API. */
    protected inner class Bridge(val native: OAuthClient, val dart: DartSide) {
        /** What the test reads off the SDK's own instance: not bridged, never used to drive anything. */
        fun <T> observe(what: String, block: suspend OAuthClient.() -> T): T = Waiting.blocking(what) { native.block() }
    }

    /**
     * Wires the native client of one configuration the way the native driver does, then creates
     * it through the host API exactly as Dart's `OAuth.create` would (the handle is what native answers
     * with, not derived here). The parameters are those of
     * [configuration]; the message is built from the same values.
     */
    protected fun bridge(
        clientId: String = Provider.CLIENT_ID,
        endpoints: ProviderEndpoints? = null,
        redirectUri: String = Provider.REDIRECT_URI,
        scopes: Set<String> = provider.scopes,
        protectedOrigins: Set<String> = setOf(resource.origin),
        pushedAuthorization: PushedAuthorization = PushedAuthorization.WhenAdvertised,
    ): Bridge {
        val native = OAuthClient.create(
            application,
            configuration(clientId, endpoints, redirectUri, scopes, protectedOrigins, pushedAuthorization),
            browser = OffTheMainThread(browser),
            keyProvider = ReversingKeyProvider,
        )
        val dart = dart()
        dart.create(message(clientId, endpoints, redirectUri, scopes, protectedOrigins, pushedAuthorization)).failureOrNull()?.let {
            throw AssertionError("expected CreateOk, got ${it.category}/${it.kind}: ${it.message}")
        }
        return Bridge(native, dart)
    }

    /** A Dart side with no client yet: what `create` is sent through, a failing one included. */
    protected fun dart(): DartSide = DartSide(messenger).also { darts += it }

    /** The configuration Dart's `toMessage` produces for the values [bridge] takes; every other field at its documented default. */
    protected fun message(
        clientId: String = Provider.CLIENT_ID,
        endpoints: ProviderEndpoints? = null,
        redirectUri: String = Provider.REDIRECT_URI,
        scopes: Set<String> = provider.scopes,
        protectedOrigins: Set<String> = setOf(resource.origin),
        pushedAuthorization: PushedAuthorization = PushedAuthorization.WhenAdvertised,
        issuer: String? = if (endpoints == null) proxy.issuer else null,
    ): ConfigurationMessage = ConfigurationMessage(
        issuer = issuer,
        endpoints = endpoints?.let {
            EndpointsMessage(
                issuer = it.issuer,
                authorizationEndpoint = it.authorizationEndpoint,
                tokenEndpoint = it.tokenEndpoint,
                jwksUri = it.jwksUri,
                userinfoEndpoint = it.userinfoEndpoint,
                revocationEndpoint = it.revocationEndpoint,
                endSessionEndpoint = it.endSessionEndpoint,
                pushedAuthorizationRequestEndpoint = it.pushedAuthorizationRequestEndpoint,
                idTokenSigningAlgValuesSupported = it.idTokenSigningAlgValuesSupported,
            )
        },
        clientId = clientId,
        redirectUri = redirectUri,
        postLogoutRedirectUri = Provider.POST_LOGOUT_REDIRECT_URI,
        scopes = scopes.toList(),
        tokenBinding = TokenBindingMessage.BEARER,
        pushedAuthorization = when (pushedAuthorization) {
            PushedAuthorization.Never -> PushedAuthorizationMessage.NEVER
            PushedAuthorization.WhenAdvertised -> PushedAuthorizationMessage.WHEN_ADVERTISED
            PushedAuthorization.Required -> PushedAuthorizationMessage.REQUIRED
        },
        protectedOrigins = protectedOrigins.toList(),
        endSessionEndpoint = null,
        unlockPolicy = UnlockPolicyMessage.NONE,
        clockSkewToleranceSeconds = 60,
        retryPolicy = null,
    )

    // ---- the typed answers, as a Flutter app reads them ----

    private fun CreateResult.failureOrNull(): ErrorMessage? = (this as? CreateFailure)?.error

    /** The error a `create` answered with, or fails when it succeeded. */
    protected fun CreateResult.failure(): ErrorMessage = failureOrNull() ?: throw AssertionError("expected CreateFailure, the client was created")

    protected fun VoidResult.assertOk() {
        if (this is VoidFailure) throw AssertionError("expected VoidOk, got ${error.category}/${error.kind}: ${error.message}")
    }

    /** The error a Void operation answered with, or fails when it succeeded. */
    protected fun VoidResult.failure(): ErrorMessage =
        (this as? VoidFailure)?.error ?: throw AssertionError("expected VoidFailure, the operation succeeded")

    protected fun AccessTokenResult.token(): AccessTokenMessage =
        (this as? AccessTokenOk)?.token ?: throw AssertionError("expected AccessTokenOk, got ${(this as AccessTokenFailure).error.let { "${it.category}/${it.kind}" }}")

    protected fun AccessTokenResult.failure(): ErrorMessage =
        (this as? AccessTokenFailure)?.error ?: throw AssertionError("expected AccessTokenFailure, a token was handed over")

    protected fun UserInfoResult.failure(): ErrorMessage =
        (this as? UserInfoFailure)?.error ?: throw AssertionError("expected UserInfoFailure, the operation succeeded")

    protected fun UserInfoResult.subject(): String =
        (this as? UserInfoOk)?.userInfo?.subject ?: throw AssertionError("expected UserInfoOk, got ${(this as UserInfoFailure).error.let { "${it.category}/${it.kind}" }}")

    /** [error] is the category and case the native error `spec/errors.md` names, as the wire spells them. */
    protected fun assertError(error: ErrorMessage, category: ErrorCategoryMessage, kind: String) {
        assertEquals("${error.category}/${error.kind}: ${error.message}", category to kind, error.category to error.kind)
    }

    /** A Flutter app's authenticated call: the token the bridge handed over, attached by the app. */
    protected fun appCall(token: AccessTokenMessage, url: String): Response =
        app.newCall(Request.Builder().url(url).header("Authorization", "${token.tokenType} ${token.value}").build()).execute()

    protected fun assertTokenIsUsableAtTheResource(token: AccessTokenMessage, subject: String) {
        assertEquals("Bearer", token.tokenType)
        val response = appCall(token, resource.url("/api"))
        val body = response.use { it.body.string() }
        assertEquals(body, 200, response.code)
        assertTrue(body.contains(subject))
    }

    /** The query of a URI as a decoded map. */
    protected fun String.queryMap(): Map<String, String> = substringAfter('?', "").split('&').filter { it.contains('=') }.associate {
        java.net.URLDecoder.decode(it.substringBefore('='), "UTF-8") to java.net.URLDecoder.decode(it.substringAfter('='), "UTF-8")
    }

    companion object {
        /** A Java `@NonNull` parameter the code under test never reads (the engine, the texture registry): null, honestly. */
        @Suppress("UNCHECKED_CAST")
        private fun <T> unsafeNull(): T = null as T
    }
}

/**
 * A browser leg that suspends instead of blocking the thread it was called on, as a Custom Tab
 * does. The HTTP conversation of the driver's browser blocks in OkHttp; run in the host call's
 * coroutine on the platform (main) thread it would also stop that thread answering the bridge,
 * and a scenario that asks the bridge a question while the browser is open (the session state at
 * that moment) would wait on a thread that is waiting on it.
 */
private class OffTheMainThread(private val delegate: BrowserAuthorizationSession) : BrowserAuthorizationSession {
    override suspend fun authorize(uri: String): BrowserOutcome = withContext(Dispatchers.IO) { delegate.authorize(uri) }
    override suspend fun awaitPendingRedirect(): BrowserOutcome = delegate.awaitPendingRedirect()
}
