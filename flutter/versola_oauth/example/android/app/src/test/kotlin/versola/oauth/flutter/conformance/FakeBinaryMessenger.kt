package versola.oauth.flutter.conformance

import io.flutter.plugin.common.BinaryMessenger
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap

/**
 * The engine's end of the platform channels, with the Dart isolate left out. The plugin registers
 * its Pigeon handlers here exactly as it does on a [BinaryMessenger] of a real engine; [DartSide]
 * is what stands where the generated Dart code stands: it encodes a call with the plugin's own
 * codec, [deliver]s it to the handler registered for the channel, and decodes what comes back.
 *
 * [send] is the other direction, native to Dart: the event channel's success envelopes arrive
 * here and go to whoever [listen]ed on that channel name.
 */
class FakeBinaryMessenger : BinaryMessenger {
    private val handlers = ConcurrentHashMap<String, BinaryMessenger.BinaryMessageHandler>()
    private val listeners = ConcurrentHashMap<String, (ByteBuffer) -> Unit>()

    /** Dart to native: [message] is handed to the handler of [channel]; [reply] gets the handler's answer. */
    fun deliver(channel: String, message: ByteBuffer, reply: (ByteBuffer?) -> Unit) {
        val handler = handlers[channel] ?: throw AssertionError("no native handler is registered on $channel")
        // A codec leaves the position at the end of what it wrote; the engine hands the handler a rewound buffer.
        message.rewind()
        handler.onMessage(message) { answer -> reply(answer) }
    }

    /** Native to Dart: [listener] receives every message the native side sends on [channel]. */
    fun listen(channel: String, listener: (ByteBuffer) -> Unit) {
        listeners[channel] = listener
    }

    fun stopListening(channel: String) {
        listeners.remove(channel)
    }

    override fun send(channel: String, message: ByteBuffer?) {
        val buffer = message ?: return
        buffer.rewind()
        listeners[channel]?.invoke(buffer)
    }

    override fun send(channel: String, message: ByteBuffer?, callback: BinaryMessenger.BinaryReply?) {
        send(channel, message)
        callback?.reply(null)
    }

    override fun setMessageHandler(channel: String, handler: BinaryMessenger.BinaryMessageHandler?) {
        if (handler == null) handlers.remove(channel) else handlers[channel] = handler
    }
}
