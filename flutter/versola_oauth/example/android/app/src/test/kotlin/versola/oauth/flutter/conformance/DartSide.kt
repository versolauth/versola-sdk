package versola.oauth.flutter.conformance

import io.flutter.plugin.common.MethodCall
import java.nio.ByteBuffer
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import versola.oauth.flutter.AccessTokenResult
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

/** The host API answered with an error envelope instead of a Result: a `PlatformException` in Dart, which the bridge must never produce (`flutter.md`, Bridge). */
class HostApiThrew(method: String, code: Any?, message: Any?) :
    AssertionError("$method answered with a PlatformException instead of a typed result: $code: $message")

/**
 * What the generated Dart code does, minus Dart: a call is the Pigeon argument list encoded with
 * the plugin's own codec and sent on the channel name the generator derives, and the answer is
 * decoded by the same codec, so an enum that does not survive the wire, a nullable that arrives
 * as something else or a type the codec cannot carry fails here as it would in a Flutter app.
 *
 * One instance per client handle. Everything that came back, replies and events alike, is kept in
 * [received] so a test can assert that nothing credential-shaped crossed the bridge.
 */
class DartSide(private val messenger: FakeBinaryMessenger, val handle: String) {

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

    fun create(configuration: ConfigurationMessage): VoidResult = remember("create", call("create", handle, configuration) as VoidResult)

    fun sessionState(): SessionStateMessage = remember("sessionState", call("sessionState", handle) as SessionStateMessage)

    fun login(options: LoginOptionsMessage = loginOptions()): VoidResult = remember("login", call("login", handle, options) as VoidResult)

    fun logout(options: LogoutOptionsMessage = LogoutOptionsMessage(endSession = true, revoke = true)): LogoutOutcomeMessage =
        remember("logout", call("logout", handle, options) as LogoutOutcomeMessage)

    fun accessToken(): AccessTokenResult = remember("accessToken", call("accessToken", handle) as AccessTokenResult)

    fun refresh(): VoidResult = remember("refresh", call("refresh", handle) as VoidResult)

    fun claims(): IdTokenClaimsMessage? = call("claims", handle)?.let { remember("claims", it as IdTokenClaimsMessage) }

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
