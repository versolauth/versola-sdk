import Flutter
import Foundation
import UIKit

/// The engine's end of the platform channels, with the Dart isolate left out. The plugin
/// registers its Pigeon handlers here exactly as it does on the messenger of a real engine;
/// `DartSide` is what stands where the generated Dart code stands: it encodes a call with the
/// plugin's own codec, `deliver`s it to the handler registered for the channel and decodes what
/// comes back.
///
/// `send` is the other direction, native to Dart: an event channel's success envelopes arrive
/// there and go to whoever `listen`ed on that channel name.
final class FakeMessenger: NSObject, FlutterBinaryMessenger, @unchecked Sendable {
    private let lock = NSLock()
    private var handlers: [String: FlutterBinaryMessageHandler] = [:]
    private var listeners: [String: @Sendable (Data) -> Void] = [:]

    /// Dart to native: `message` is handed to the handler of `channel`; `reply` gets its answer.
    /// False when nothing is registered on the channel.
    func deliver(_ channel: String, _ message: Data, reply: @escaping @Sendable (Data?) -> Void) -> Bool {
        guard let handler = lock.withLock({ handlers[channel] }) else { return false }
        handler(message) { answer in reply(answer) }
        return true
    }

    /// Native to Dart: `listener` receives every message the native side sends on `channel`.
    func listen(_ channel: String, _ listener: @escaping @Sendable (Data) -> Void) {
        lock.withLock { listeners[channel] = listener }
    }

    func stopListening(_ channel: String) {
        lock.withLock { _ = listeners.removeValue(forKey: channel) }
    }

    func send(onChannel channel: String, message: Data?) {
        guard let message, let listener = lock.withLock({ listeners[channel] }) else { return }
        listener(message)
    }

    func send(onChannel channel: String, message: Data?, binaryReply callback: FlutterBinaryReply? = nil) {
        send(onChannel: channel, message: message)
        callback?(nil)
    }

    func setMessageHandlerOnChannel(_ channel: String, binaryMessageHandler handler: FlutterBinaryMessageHandler? = nil) -> FlutterBinaryMessengerConnection {
        lock.withLock { handlers[channel] = handler }
        return 0
    }

    func cleanUpConnection(_ connection: FlutterBinaryMessengerConnection) {}
}

/// What `VersolaOAuthPlugin.register(with:)` is given: the messenger above and nothing else the
/// plugin touches. A plugin that asked for more (textures, a view factory) would trap here.
final class FakeRegistrar: NSObject, FlutterPluginRegistrar {
    let fake: FakeMessenger

    init(_ messenger: FakeMessenger) { fake = messenger }

    var viewController: UIViewController? { nil }
    func messenger() -> FlutterBinaryMessenger { fake }
    func textures() -> FlutterTextureRegistry { preconditionFailure("the plugin does not use textures") }
    func register(_ factory: FlutterPlatformViewFactory, withId factoryId: String) { preconditionFailure("the plugin has no platform views") }
    func register(_ factory: FlutterPlatformViewFactory, withId factoryId: String, gestureRecognizersBlockingPolicy: FlutterPlatformViewGestureRecognizersBlockingPolicy) {
        preconditionFailure("the plugin has no platform views")
    }
    func publish(_ value: NSObject) {}
    func addMethodCallDelegate(_ delegate: FlutterPlugin, channel: FlutterMethodChannel) {}
    func addApplicationDelegate(_ delegate: FlutterPlugin) {}
    func addSceneDelegate(_ delegate: FlutterSceneLifeCycleDelegate) {}
    func valuePublished(byPlugin pluginKey: String) -> NSObject? { nil }
    func lookupKey(forAsset asset: String) -> String { asset }
    func lookupKey(forAsset asset: String, fromPackage package: String) -> String { asset }
}
