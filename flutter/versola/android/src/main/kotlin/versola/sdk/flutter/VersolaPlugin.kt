// The Android half of the binding (`.claude/rules/flutter.md`): one Pigeon host API over the
// public surface of `versola.sdk.Versola`, and one event channel per client for the state
// machine. It converts types and nothing else; every behaviour is the SDK's. Nothing
// credential-shaped is reachable from here: the facade has no access-token accessor, and the
// authenticated call goes through `Versola.call`, which attaches the token and the proof itself.
package versola.sdk.flutter

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
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import versola.oauth.core.VersolaError
import versola.sdk.LogoutOptions
import versola.sdk.Versola

public class VersolaPlugin : FlutterPlugin, VersolaHostApi {
    private lateinit var context: Context
    private lateinit var messenger: BinaryMessenger

    /** The handle native chose for a client, by the client's identity: one handle per configuration. */
    private val handles = ConcurrentHashMap<String, String>()
    private val nextHandle = AtomicInteger()

    /** Clients by handle; the SDK's own registry keeps one instance per configuration. */
    private val clients = ConcurrentHashMap<String, Versola>()

    /** Event channels already registered, one per handle: registering twice would replace the handler mid-stream. */
    private val streams = ConcurrentHashMap<String, SessionStateStream>()

    /** Collections of the state flow live here so detaching the engine ends every one of them. */
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        context = binding.applicationContext
        messenger = binding.binaryMessenger
        VersolaHostApi.setUp(messenger, this)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        VersolaHostApi.setUp(messenger, null)
        scope.cancel()
        streams.clear()
        // The SDK's clients outlive the engine on purpose: they are one per configuration per
        // process, and the next engine asks for the same ones.
    }

    private fun client(handle: String): Versola = clients[handle] ?: throw VersolaError.Configuration(
        VersolaError.Configuration.Detail.InvalidConfiguration("no client for this handle; call create first"),
    )

    /**
     * Every answer is a Result (`flutter.md`): a `VersolaError` crosses as itself, anything else as
     * a `Configuration` naming only its class, and a cancellation stays a cancellation. A thrown
     * exception would reach Dart as a `PlatformException` carrying native text.
     */
    private inline fun <R> attempt(failure: (VersolaErrorMessage) -> R, block: () -> R): R = try {
        block()
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        failure(e.toErrorMessage())
    }

    // MARK: VersolaHostApi

    override suspend fun create(configuration: VersolaConfigurationMessage): VersolaCreateResult = attempt(::VersolaCreateFailure) {
        // The SDK validates eagerly (an edge URL that is not an origin, a skew over five minutes, a
        // second configuration for the same edge, issuer and client id) and throws Configuration;
        // that is the answer here.
        val client = Versola.create(context, configuration.toConfiguration())
        val identity = "${client.configuration.edgeUrl}\n${client.configuration.issuer}\n${client.configuration.clientId}"
        val handle = handles.computeIfAbsent(identity) { "client-${nextHandle.incrementAndGet()}" }
        clients[handle] = client
        streams.computeIfAbsent(handle) {
            SessionStateStream(client, scope).also { SessionStatesStreamHandler.register(messenger, it, handle) }
        }
        VersolaCreateOk(handle)
    }

    /** The flow replays the current (restored) state first, so its first value is the answer. */
    override suspend fun sessionState(handle: String): VersolaSessionStateResult = attempt(::VersolaSessionStateFailure) {
        VersolaSessionStateOk(client(handle).sessionState.first().toMessage())
    }

    override suspend fun login(handle: String, options: VersolaLoginOptionsMessage): VersolaVoidResult = voidResult {
        client(handle).login(options.toLoginOptions())
    }

    /** No options is `null`: the SDK then uses the scopes the session was granted. */
    override suspend fun stepUp(handle: String, acrValues: List<String>, maxAge: Long?, options: VersolaLoginOptionsMessage?): VersolaVoidResult =
        voidResult { client(handle).stepUp(VersolaError.StepUp(acrValues, maxAge), options?.toLoginOptions()) }

    override suspend fun logout(handle: String, options: VersolaLogoutOptionsMessage): VersolaLogoutResult = attempt(::VersolaLogoutFailure) {
        val outcome = client(handle).logout(LogoutOptions(endSession = options.endSession, revoke = options.revoke))
        VersolaLogoutOk(VersolaLogoutOutcomeMessage(sessionEnded = outcome.sessionEnded, tokenRevoked = outcome.tokenRevoked))
    }

    override suspend fun refresh(handle: String): VersolaVoidResult = voidResult { client(handle).refresh() }

    override suspend fun claims(handle: String): VersolaClaimsResult = attempt(::VersolaClaimsFailure) {
        VersolaClaimsOk(
            client(handle).claims?.let { c ->
                VersolaIdTokenClaimsMessage(
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

    /** Asking generates the key, so `Configuration(HardwareBindingUnavailable)` is a reachable answer here. */
    override suspend fun keyAttestation(handle: String): VersolaKeyAttestationResult = attempt(::VersolaKeyAttestationFailure) {
        VersolaKeyAttestationOk(client(handle).keyAttestation()?.toWireName())
    }

    /**
     * `Versola.call`: the SDK's own authenticated client runs the request, so the token, the proof,
     * the refresh and the edge-only scope stay here. The body is read to the end inside the IO
     * dispatcher (a blocking read must not run on the main thread). A call that produced no HTTP
     * response is not an SDK error: it crosses as its class name alone, since the exception's
     * message can carry the URL.
     */
    override suspend fun httpRequest(handle: String, request: VersolaHttpRequestMessage): VersolaHttpResult = attempt(::VersolaHttpFailure) {
        val client = client(handle)
        val prepared = request.toRequest()
        try {
            withContext(Dispatchers.IO) { client.call(prepared).use { VersolaHttpOk(it.toMessage()) } }
        } catch (e: IOException) {
            VersolaHttpTransportFailure(e.javaClass.simpleName)
        }
    }

    private inline fun voidResult(block: () -> Unit): VersolaVoidResult = attempt(::VersolaVoidFailure) {
        block()
        VersolaVoidOk()
    }
}

/**
 * One event channel per client. `onListen` starts collecting the SDK's `Flow<SessionState>`
 * on the main thread (an `EventSink` is called there and nowhere else) and `onCancel` ends the
 * collection, so a Dart subscription and the native collection have the same lifetime.
 */
internal class SessionStateStream(
    private val client: Versola,
    private val scope: CoroutineScope,
) : SessionStatesStreamHandler() {
    private var job: Job? = null

    override fun onListen(p0: Any?, sink: PigeonEventSink<VersolaSessionStateMessage>) {
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
