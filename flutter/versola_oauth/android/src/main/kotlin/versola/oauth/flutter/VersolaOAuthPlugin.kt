// The Android half of the binding (`.claude/rules/flutter.md`): one Pigeon host API over the
// public surface of `versola.oauth.OAuthClient`, and one event channel per client for the state
// machine. It converts types and nothing else; every behaviour is the SDK's.
package versola.oauth.flutter

import android.content.Context
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.BinaryMessenger
import java.io.IOException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import kotlinx.coroutines.launch
import versola.oauth.LoginOptions
import versola.oauth.LogoutOptions
import versola.oauth.OAuthClient
import versola.oauth.core.SessionState
import versola.oauth.core.VersolaError

public class VersolaOAuthPlugin : FlutterPlugin, OAuthHostApi {
    private lateinit var context: Context
    private lateinit var messenger: BinaryMessenger

    /** The handle native chose for a client, by the client's identity: one handle per configuration. */
    private val handles = ConcurrentHashMap<String, String>()
    private val nextHandle = AtomicInteger()

    /** Clients by handle; the SDK's own registry keeps one instance per configuration. */
    private val clients = ConcurrentHashMap<String, OAuthClient>()

    /** Event channels already registered, one per handle: registering twice would replace the handler mid-stream. */
    private val streams = ConcurrentHashMap<String, SessionStateStream>()

    /** Collections of the state flow live here so detaching the engine ends every one of them. */
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        messenger = binding.binaryMessenger
        OAuthHostApi.setUp(messenger, this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        OAuthHostApi.setUp(messenger, null)
        scope.cancel()
        streams.clear()
        // The SDK's clients outlive the engine on purpose: they are one per configuration per
        // process, and the next engine asks for the same ones.
    }

    private fun client(handle: String): OAuthClient = clients[handle] ?: throw VersolaError.Configuration(
        VersolaError.Configuration.Detail.InvalidConfiguration("no client for this handle; call create first"),
    )

    /**
     * Every answer is a Result (`flutter.md`): a `VersolaError` crosses as itself, anything else as
     * a `Configuration` naming only its class, and a cancellation stays a cancellation. A thrown
     * exception would reach Dart as a `PlatformException` carrying native text.
     */
    private inline fun <R> attempt(failure: (ErrorMessage) -> R, block: () -> R): R = try {
        block()
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        failure(e.toErrorMessage())
    }

    // MARK: OAuthHostApi

    override suspend fun create(configuration: ConfigurationMessage): CreateResult = attempt(::CreateFailure) {
        // The SDK validates eagerly (a bad URL, a skew over five minutes, a second configuration
        // for the same issuer and client id) and throws Configuration; that is the answer here.
        val client = OAuthClient.create(context, configuration.toConfiguration())
        val identity = "${client.configuration.issuerIdentifier}\n${client.configuration.clientId}"
        val handle = handles.computeIfAbsent(identity) { "client-${nextHandle.incrementAndGet()}" }
        clients[handle] = client
        streams.computeIfAbsent(handle) {
            SessionStateStream(client, scope).also { SessionStatesStreamHandler.register(messenger, it, handle) }
        }
        CreateOk(handle)
    }

    /** The flow replays the current (restored) state first, so its first value is the answer. */
    override suspend fun sessionState(handle: String): SessionStateResult = attempt(::SessionStateFailure) {
        SessionStateOk(client(handle).sessionState.first().toMessage())
    }

    override suspend fun login(handle: String, options: LoginOptionsMessage): VoidResult = voidResult {
        client(handle).login(options.toLoginOptions())
    }

    override suspend fun stepUp(handle: String, acrValues: List<String>, maxAge: Long?, options: LoginOptionsMessage): VoidResult =
        voidResult { client(handle).stepUp(VersolaError.StepUp(acrValues, maxAge), options.toLoginOptions()) }

    override suspend fun logout(handle: String, options: LogoutOptionsMessage): LogoutResult = attempt(::LogoutFailure) {
        val outcome = client(handle).logout(LogoutOptions(endSession = options.endSession, revoke = options.revoke))
        LogoutOk(LogoutOutcomeMessage(sessionEnded = outcome.sessionEnded, tokenRevoked = outcome.tokenRevoked))
    }

    override suspend fun accessToken(handle: String): AccessTokenResult = attempt(::AccessTokenFailure) {
        val token = client(handle).accessToken()
        // The one credential that crosses (issue #46 decision 7). The scheme is read off the
        // token the way the SDK's own client does, not off configuration.
        AccessTokenOk(AccessTokenMessage(value = token.value, tokenType = if (token.isDpopBound) "DPoP" else "Bearer"))
    }

    override suspend fun refresh(handle: String): VoidResult = voidResult { client(handle).refresh() }

    override suspend fun claims(handle: String): ClaimsResult = attempt(::ClaimsFailure) {
        ClaimsOk(
            client(handle).claims?.let { c ->
                IdTokenClaimsMessage(
                    subject = c.subject,
                    issuer = c.issuer,
                    audience = c.audience,
                    issuedAtEpochSeconds = c.issuedAt.epochSecond,
                    expiresAtEpochSeconds = c.expiresAt.epochSecond,
                    authTimeEpochSeconds = c.authTime?.epochSecond,
                    acr = c.acr,
                    amr = c.amr,
                    authorizedParty = c.authorizedParty,
                    all = c.all,
                )
            },
        )
    }

    override suspend fun userInfo(handle: String): UserInfoResult = attempt(::UserInfoFailure) {
        val info = client(handle).userInfo()
        UserInfoOk(UserInfoMessage(subject = info.subject, claims = info.claims))
    }

    /** Asking generates the key, so `Configuration(HardwareBindingUnavailable)` is a reachable answer here. */
    override suspend fun keyAttestation(handle: String): KeyAttestationResult = attempt(::KeyAttestationFailure) {
        KeyAttestationOk(client(handle).keyAttestation()?.toWireName())
    }

    /**
     * `OAuthClient.call`: the SDK's own authenticated client runs the request, so the token, the
     * proof, the refresh and the origin check stay here. The body is read to the end inside the
     * IO dispatcher (a blocking read must not run on the main thread). A call that produced no
     * HTTP response is not an SDK error: it crosses as its class name alone, since the
     * exception's message can carry the URL.
     */
    override suspend fun httpRequest(handle: String, request: HttpRequestMessage): HttpResult = attempt(::HttpFailure) {
        val client = client(handle)
        val prepared = request.toRequest()
        val origins = request.origins?.toSet() ?: client.configuration.protectedOrigins
        try {
            withContext(Dispatchers.IO) { client.call(prepared, origins).use { HttpOk(it.toMessage()) } }
        } catch (e: IOException) {
            HttpTransportFailure(e.javaClass.simpleName)
        }
    }

    private inline fun voidResult(block: () -> Unit): VoidResult = attempt(::VoidFailure) {
        block()
        VoidOk()
    }
}

/**
 * One event channel per client. `onListen` starts collecting the SDK's `Flow<SessionState>`
 * on the main thread (an `EventSink` is called there and nowhere else) and `onCancel` ends the
 * collection, so a Dart subscription and the native collection have the same lifetime.
 */
internal class SessionStateStream(
    private val client: OAuthClient,
    private val scope: CoroutineScope,
) : SessionStatesStreamHandler() {
    private var job: Job? = null

    override fun onListen(p0: Any?, sink: PigeonEventSink<SessionStateMessage>) {
        job?.cancel()
        job = scope.launch {
            client.sessionState.collect { sink.success(it.toMessage()) }
        }
    }

    override fun onCancel(p0: Any?) {
        job?.cancel()
        job = null
    }
}

internal fun SessionState.toMessage(): SessionStateMessage = when (this) {
    SessionState.Unauthenticated -> SessionStateMessage.UNAUTHENTICATED
    SessionState.Authorizing -> SessionStateMessage.AUTHORIZING
    SessionState.Authenticated -> SessionStateMessage.AUTHENTICATED
    SessionState.Refreshing -> SessionStateMessage.REFRESHING
    SessionState.StepUpRequired -> SessionStateMessage.STEP_UP_REQUIRED
    SessionState.Locked -> SessionStateMessage.LOCKED
    SessionState.LoggingOut -> SessionStateMessage.LOGGING_OUT
}

internal fun LoginOptionsMessage.toLoginOptions(): LoginOptions = LoginOptions(
    scopes = scopes?.toSet(),
    prompt = prompt?.let {
        when (it) {
            PromptMessage.NONE -> versola.oauth.core.AuthorizationParameters.Prompt.None
            PromptMessage.LOGIN -> versola.oauth.core.AuthorizationParameters.Prompt.Login
            PromptMessage.CONSENT -> versola.oauth.core.AuthorizationParameters.Prompt.Consent
            PromptMessage.SELECT_ACCOUNT -> versola.oauth.core.AuthorizationParameters.Prompt.SelectAccount
            PromptMessage.CREATE -> versola.oauth.core.AuthorizationParameters.Prompt.Create
        }
    },
    loginHint = loginHint,
    uiLocales = uiLocales,
    acrValues = acrValues,
    maxAge = maxAge,
    resources = resources,
    extraParameters = extraParameters,
    ephemeralBrowser = ephemeralBrowser,
)
