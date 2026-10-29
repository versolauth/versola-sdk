package versola.oauth.flutter.conformance

import io.flutter.plugin.common.MethodCall
import java.nio.ByteBuffer
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import versola.oauth.flutter.AccessTokenResult
import versola.oauth.flutter.ClaimsFailure
import versola.oauth.flutter.ClaimsOk
import versola.oauth.flutter.ClaimsResult
import versola.oauth.flutter.CreateOk
import versola.oauth.flutter.CreateResult
import versola.oauth.flutter.ErrorMessage
import versola.oauth.flutter.LogoutFailure
import versola.oauth.flutter.LogoutOk
import versola.oauth.flutter.LogoutResult
import versola.oauth.flutter.SessionStateFailure
import versola.oauth.flutter.SessionStateOk
import versola.oauth.flutter.SessionStateResult
import versola.oauth.flutter.ConfigurationMessage
import versola.oauth.flutter.IdTokenClaimsMessage
import versola.oauth.flutter.LoginOptionsMessage
import versola.oauth.flutter.LogoutOptionsMessage
import versola.oauth.flutter.LogoutOutcomeMessage
import versola.oauth.flutter.MessagesPigeonMethodCodec
import versola.oauth.flutter.OAuthHostApi
import versola.oauth.flutter.SessionStateMessage
import versola.oauth.flutter.UserInfoResult
import versola.oauth.flutter.VoidResult

/** An operation that has no failure of interest to a scenario answered one anyway. */
class HostApiFailed(method: String, error: ErrorMessage) :
    AssertionError("$method answered ${error.category}/${error.kind}: ${error.message}")

/** The host API answered with an error envelope instead of a Result: a `PlatformException` in Dart, which the bridge must never produce (`flutter.md`, Bridge). */
class HostApiThrew(method: String, code: Any?, message: Any?) :
    AssertionError("$method answered with a PlatformException instead of a typed result: $code: $message")

/**
 * What the generated Dart code does, minus Dart: a call is the Pigeon argument list encoded with
 * the plugin's own codec and sent on the channel name the generator derives, and the answer is
 * decoded by the same codec, so an enum that does not survive the wire, a nullable that arrives
 * as something else or a type the codec cannot carry fails here as it would in a Flutter app.
 *
 * One instance per client. Everything that came back, replies and events alike, is kept in
 * [received] so a test can assert that nothing credential-shaped crossed the bridge.
 */
class DartSide(private val messenger: FakeBinaryMessenger) {

    /** The handle `create` answered with: native chooses it, Dart derives nothing. Empty until a `create` succeeded. */
    var handle: String = ""
        private set

    /** `toString()` of every decoded reply and event, and of the access token's reply apart. */
    val received = CopyOnWriteArrayList<String>()
    val receivedAccessTokenReplies = CopyOnWriteArrayList<String>()

    private val codec = OAuthHostApi.codec

    private fun call(method: String, vararg arguments: Any?): Any? {
        val channel = "dev.flutter.pigeon.versola_oauth.OAuthHostApi.$method"
        val answer = CompletableFuture<ByteBuffer?>()
        @Suppress("UNCHECKED_CAST")
        messenger.deliver(channel, codec.encodeMessage(arguments.toList())!!) { answer.complete(it) }
        val reply = Waiting.await(answer, "the reply to $method") ?: throw AssertionError("$method was never answered")
        reply.rewind()
        @Suppress("UNCHECKED_CAST")
        val envelope = codec.decodeMessage(reply) as List<Any?>
        if (envelope.size > 1) throw HostApiThrew(method, envelope[0], envelope[1])
        return envelope.single()
    }

    private fun <T> remember(method: String, value: T): T {
        if (method == "accessToken") receivedAccessTokenReplies += value.toString() else received += value.toString()
        return value
    }

    fun create(configuration: ConfigurationMessage): CreateResult {
        val result = remember("create", call("create", configuration) as CreateResult)
        if (result is CreateOk) handle = result.handle
        return result
    }

    /** The state, or fails the test naming the error when the host answered a failure. */
    fun sessionState(): SessionStateMessage = when (val r = remember("sessionState", call("sessionState", handle) as SessionStateResult)) {
        is SessionStateOk -> r.state
        is SessionStateFailure -> throw HostApiFailed("sessionState", r.error)
    }

    fun login(options: LoginOptionsMessage = loginOptions()): VoidResult = remember("login", call("login", handle, options) as VoidResult)

    fun logout(options: LogoutOptionsMessage = LogoutOptionsMessage(endSession = true, revoke = true)): LogoutOutcomeMessage =
        when (val r = remember("logout", call("logout", handle, options) as LogoutResult)) {
            is LogoutOk -> r.outcome
            is LogoutFailure -> throw HostApiFailed("logout", r.error)
        }

    fun accessToken(): AccessTokenResult = remember("accessToken", call("accessToken", handle) as AccessTokenResult)

    fun refresh(): VoidResult = remember("refresh", call("refresh", handle) as VoidResult)

    fun claims(): IdTokenClaimsMessage? = when (val r = remember("claims", call("claims", handle) as ClaimsResult)) {
        is ClaimsOk -> r.claims
        is ClaimsFailure -> throw HostApiFailed("claims", r.error)
    }

    fun userInfo(): UserInfoResult = remember("userInfo", call("userInfo", handle) as UserInfoResult)

    /**
     * `SessionStateEvents.sessionStates()`: listens as Dart's `receiveBroadcastStream` does (a
     * `listen` method call on the event channel the plugin registered for this handle) and
     * collects what the plugin sends until [StateSubscription.cancel].
     */
    fun sessionStates(): StateSubscription = StateSubscription(messenger, "dev.flutter.pigeon.versola_oauth.SessionStateEvents.sessionStates.$handle") {
        received += it.toString()
    }

    companion object {
        /** `LoginOptions()` as Dart's `loginOptionsToMessage` builds it: every list empty, nothing optional set. */
        fun loginOptions(maxAge: Long? = null): LoginOptionsMessage = LoginOptionsMessage(
            scopes = null, prompt = null, loginHint = null, uiLocales = emptyList(), acrValues = emptyList(),
            maxAge = maxAge, resources = emptyList(), extraParameters = emptyMap(), ephemeralBrowser = false,
        )
    }
}

/** One Dart subscription to the state stream. */
class StateSubscription(
    private val messenger: FakeBinaryMessenger,
    private val channel: String,
    private val onEvent: (Any?) -> Unit,
) {
    /** The states in the order they arrived. */
    val states = CopyOnWriteArrayList<SessionStateMessage>()

    init {
        messenger.listen(channel) { buffer ->
            val event = MessagesPigeonMethodCodec.decodeEnvelope(buffer)
            onEvent(event)
            states += event as SessionStateMessage
        }
        invoke("listen")
    }

    fun cancel() {
        invoke("cancel")
        messenger.stopListening(channel)
    }

    private fun invoke(method: String) {
        val answer = CompletableFuture<ByteBuffer?>()
        messenger.deliver(channel, MessagesPigeonMethodCodec.encodeMethodCall(MethodCall(method, null))) { answer.complete(it) }
        val reply = Waiting.await(answer, "the reply to $method on $channel") ?: throw AssertionError("$method on $channel was never answered")
        reply.rewind()
        MessagesPigeonMethodCodec.decodeEnvelope(reply)
    }
}
