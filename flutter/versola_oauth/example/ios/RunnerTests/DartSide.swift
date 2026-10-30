import Flutter
import Foundation
import os
@testable import versola_oauth

/// The host API answered with an error envelope instead of a Result: a `PlatformException` in
/// Dart, which the bridge must never produce (`flutter.md`, Bridge).
struct HostApiThrew: Error, CustomStringConvertible {
    let method: String
    let detail: String
    var description: String { "\(method) answered with a PlatformException instead of a typed result: \(detail)" }
}

/// An operation that has no failure of interest to a scenario answered one anyway.
struct HostApiFailed: Error, CustomStringConvertible {
    let method: String
    let error: ErrorMessage
    var description: String { "\(method) answered \(error.category)/\(error.kind): \(error.message)" }
}

struct BridgeFailure: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

/// What the generated Dart code does, minus Dart: a call is the Pigeon argument list encoded
/// with the plugin's own codec and sent on the channel name the generator derives, and the
/// answer is decoded by the same codec, so an enum that does not survive the wire, a nullable
/// that arrives as something else or a type the codec cannot carry fails here as it would in a
/// Flutter app.
///
/// One instance per client handle. Everything that came back, replies and events alike, is kept
/// in `received` so a test can assert that nothing credential-shaped crossed the bridge.
final class DartSide: Sendable {
    private struct State: Sendable {
        /// The handle `create` answered with: native chooses it, Dart derives nothing. Empty until a `create` succeeded.
        var handle = ""
        var log: [String] = []
    }

    private let messenger: FakeMessenger
    private let state = OSAllocatedUnfairLock(initialState: State())

    init(_ messenger: FakeMessenger) {
        self.messenger = messenger
    }

    var handle: String { state.withLock { $0.handle } }

    /// `description` of every decoded reply and event except the access token's own reply.
    var received: [String] { state.withLock { $0.log } }

    private func call(_ method: String, _ arguments: [Any?]) async throws -> Any? {
        let channel = "dev.flutter.pigeon.versola_oauth.OAuthHostApi.\(method)"
        guard let message = MessagesPigeonCodec.shared.encode(arguments) else { throw BridgeFailure("\(method): the arguments do not encode") }
        let reply: Data? = await withCheckedContinuation { continuation in
            if !messenger.deliver(channel, message, reply: { continuation.resume(returning: $0) }) {
                continuation.resume(returning: nil)
            }
        }
        guard let reply else { throw BridgeFailure("\(method) was never answered (no handler on \(channel)?)") }
        guard let envelope = MessagesPigeonCodec.shared.decode(reply) as? [Any?] else { throw BridgeFailure("\(method): the reply is not a list") }
        if envelope.count > 1 { throw HostApiThrew(method: method, detail: "\(String(describing: envelope[0])): \(String(describing: envelope[1]))") }
        // A Pigeon reply is a one-element list; a null result is NSNull on the wire.
        guard let value = envelope.first ?? nil, !(value is NSNull) else { return nil }
        return value
    }

    private func remember<T>(_ method: String, _ value: T) -> T {
        if method != "accessToken" { state.withLock { $0.log.append(String(describing: value)) } }
        return value
    }

    func create(_ configuration: ConfigurationMessage) async throws -> CreateResult {
        let result = remember("create", try await call("create", [configuration]) as! CreateResult)
        if let ok = result as? CreateOk { state.withLock { $0.handle = ok.handle } }
        return result
    }

    /// The state, or throws naming the error when the host answered a failure.
    func sessionState() async throws -> SessionStateMessage {
        let result = remember("sessionState", try await call("sessionState", [handle]) as! SessionStateResult)
        if let ok = result as? SessionStateOk { return ok.state }
        throw HostApiFailed(method: "sessionState", error: (result as! SessionStateFailure).error)
    }

    func login(_ options: LoginOptionsMessage = DartSide.loginOptions()) async throws -> VoidResult {
        remember("login", try await call("login", [handle, options]) as! VoidResult)
    }

    func logout(_ options: LogoutOptionsMessage = LogoutOptionsMessage(endSession: true, revoke: true)) async throws -> LogoutOutcomeMessage {
        let result = remember("logout", try await call("logout", [handle, options]) as! LogoutResult)
        if let ok = result as? LogoutOk { return ok.outcome }
        throw HostApiFailed(method: "logout", error: (result as! LogoutFailure).error)
    }

    func accessToken() async throws -> AccessTokenResult {
        remember("accessToken", try await call("accessToken", [handle]) as! AccessTokenResult)
    }

    func refresh() async throws -> VoidResult {
        remember("refresh", try await call("refresh", [handle]) as! VoidResult)
    }

    func claims() async throws -> IdTokenClaimsMessage? {
        let result = remember("claims", try await call("claims", [handle]) as! ClaimsResult)
        if let ok = result as? ClaimsOk { return ok.claims }
        throw HostApiFailed(method: "claims", error: (result as! ClaimsFailure).error)
    }

    func userInfo() async throws -> UserInfoResult {
        remember("userInfo", try await call("userInfo", [handle]) as! UserInfoResult)
    }

    /// `SessionStateEvents.sessionStates()`: listens as Dart's `receiveBroadcastStream` does (a
    /// `listen` method call on the event channel the plugin registered for this handle) and
    /// collects what the plugin sends until `cancel()`.
    func sessionStates() async throws -> StateSubscription {
        try await StateSubscription(messenger, channel: "dev.flutter.pigeon.versola_oauth.SessionStateEvents.sessionStates.\(handle)") { [state] event in
            state.withLock { $0.log.append(String(describing: event)) }
        }
    }

    /// `LoginOptions()` as Dart's `loginOptionsToMessage` builds it: every list empty, nothing optional set.
    static func loginOptions(maxAge: Int64? = nil) -> LoginOptionsMessage {
        LoginOptionsMessage(uiLocales: [], acrValues: [], maxAge: maxAge, resources: [], extraParameters: [:], ephemeralBrowser: false)
    }
}

/// One Dart subscription to the state stream.
final class StateSubscription: Sendable {
    private let messenger: FakeMessenger
    let channel: String
    private let seen = OSAllocatedUnfairLock(initialState: [SessionStateMessage]())

    /// The states in the order they arrived.
    var states: [SessionStateMessage] { seen.withLock { $0 } }

    fileprivate init(_ messenger: FakeMessenger, channel: String, onEvent: @escaping @Sendable (Any?) -> Void) async throws {
        self.messenger = messenger
        self.channel = channel
        messenger.listen(channel) { [seen] data in
            let event = messagesPigeonMethodCodec.decodeEnvelope(data)
            onEvent(event)
            if let state = event as? SessionStateMessage { seen.withLock { $0.append(state) } }
        }
        try await invoke("listen")
    }

    func cancel() async throws {
        try await invoke("cancel")
        messenger.stopListening(channel)
    }

    private func invoke(_ method: String) async throws {
        let message = messagesPigeonMethodCodec.encode(FlutterMethodCall(methodName: method, arguments: nil))
        let reply: Data? = await withCheckedContinuation { continuation in
            if !messenger.deliver(channel, message, reply: { continuation.resume(returning: $0) }) { continuation.resume(returning: nil) }
        }
        guard let reply else { throw BridgeFailure("\(method) on \(channel) was never answered") }
        if let error = messagesPigeonMethodCodec.decodeEnvelope(reply) as? FlutterError {
            throw BridgeFailure("\(method) on \(channel): \(error.code) \(error.message ?? "")")
        }
    }
}
