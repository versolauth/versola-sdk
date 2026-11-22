// The iOS half of the binding (`.claude/rules/flutter.md`): one Pigeon host API over the public
// surface of `VersolaSDK`'s `Versola`, and one event channel per client for the state machine. It
// converts types and nothing else; every behaviour is the SDK's. Nothing credential-shaped is
// reachable from here: the facade has no access-token accessor, and the authenticated call goes
// through `Versola.session()`, which attaches the token and the proof itself.
import AuthenticationServices
import Flutter
import UIKit
import VersolaSDK

public final class VersolaPlugin: NSObject, FlutterPlugin {
    /// Where the browser sheet is presented from. The SDK takes the anchor from the app rather
    /// than finding a window itself (`ios-swift.md`); a Flutter app's native half is this
    /// plugin, so the app may set its own resolver here (in `AppDelegate`, before the first
    /// `create`). The default is the key window of the foreground scene, which is the one
    /// window a Flutter app has.
    @MainActor public static var presentationAnchor: () -> ASPresentationAnchor = {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        let scene = scenes.first { $0.activationState == .foregroundActive } ?? scenes.first
        return scene?.keyWindow ?? scene?.windows.first ?? ASPresentationAnchor()
    }

    private let clients = Clients()
    private var messenger: FlutterBinaryMessenger?

    public static func register(with registrar: FlutterPluginRegistrar) {
        let instance = VersolaPlugin()
        instance.messenger = registrar.messenger()
        VersolaHostApiSetup.setUp(binaryMessenger: registrar.messenger(), api: instance)
        // Both lifecycles: an app that has adopted UIScene (Flutter's template since 3.4x, and
        // this repository's example) receives a link in the scene delegate and never in the
        // application delegate; one that has not still receives it in the application delegate.
        registrar.addApplicationDelegate(instance)
        registrar.addSceneDelegate(instance)
    }

    /// A redirect that reached the app while no `ASWebAuthenticationSession` was waiting (the
    /// app was killed mid-browser and the link cold-started it) goes to the client whose
    /// redirect URI it is. The link can arrive before Dart has called `create`, so the actor
    /// holds it until a client claims it. Nothing is returned to the system as handled: the
    /// answer is asynchronous, and claiming a link here would hide it from other plugins.
    private func deliver(_ url: URL) {
        Task { await clients.deliver(url) }
    }

    /// The handle→client map behind an actor: Pigeon calls arrive on the main actor, the state
    /// collections and link deliveries run in their own tasks.
    actor Clients {
        private var byHandle: [String: Versola] = [:]
        private var handleByIdentity: [String: String] = [:]
        private var streams: [String: SessionStateStream] = [:]
        private var nextHandle = 0
        private var unclaimed: [URL] = []

        func get(_ handle: String) throws -> Versola {
            guard let client = byHandle[handle] else {
                throw OAuthError.configuration(.invalidConfiguration(detail: "no client for this handle; call create first"))
            }
            return client
        }

        /// Names the client: one handle per configuration (edge URL, issuer and client id), chosen here so
        /// Dart derives nothing. Returns the stream handler to register when this handle is new,
        /// and offers any redirect that arrived before the client existed.
        func put(_ client: Versola) async -> (handle: String, newStream: SessionStateStream?) {
            let identity = "\(client.configuration.edgeUrl)\n\(client.configuration.issuer)\n\(client.configuration.clientId)"
            let handle: String
            if let existing = handleByIdentity[identity] {
                handle = existing
            } else {
                nextHandle += 1
                handle = "client-\(nextHandle)"
                handleByIdentity[identity] = handle
            }
            byHandle[handle] = client
            var newStream: SessionStateStream?
            if streams[handle] == nil {
                let stream = SessionStateStream(client: client)
                streams[handle] = stream
                newStream = stream
            }
            let waiting = unclaimed
            unclaimed = []
            for url in waiting { await deliver(url) }
            return (handle, newStream)
        }

        func deliver(_ url: URL) async {
            for client in byHandle.values where await client.handleRedirect(url) { return }
            // Nobody's redirect yet: keep a few, newest last, in case `create` is still to come.
            unclaimed.append(url)
            if unclaimed.count > 4 { unclaimed.removeFirst() }
        }
    }
}

// MARK: Link delivery (application and scene lifecycles)

extension VersolaPlugin: FlutterSceneLifeCycleDelegate {
    public func application(_ application: UIApplication, continue userActivity: NSUserActivity, restorationHandler: @escaping ([any UIUserActivityRestoring]) -> Void) -> Bool {
        if userActivity.activityType == NSUserActivityTypeBrowsingWeb, let url = userActivity.webpageURL { deliver(url) }
        return false
    }

    public func application(_ application: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
        deliver(url)
        return false
    }

    public func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options connectionOptions: UIScene.ConnectionOptions?) -> Bool {
        // The cold-start path: the link that launched the app is in the connection options.
        for activity in connectionOptions?.userActivities ?? [] where activity.activityType == NSUserActivityTypeBrowsingWeb {
            if let url = activity.webpageURL { deliver(url) }
        }
        for context in connectionOptions?.urlContexts ?? [] { deliver(context.url) }
        return false
    }

    public func scene(_ scene: UIScene, continue userActivity: NSUserActivity) -> Bool {
        if userActivity.activityType == NSUserActivityTypeBrowsingWeb, let url = userActivity.webpageURL { deliver(url) }
        return false
    }

    public func scene(_ scene: UIScene, openURLContexts URLContexts: Set<UIOpenURLContext>) -> Bool {
        for context in URLContexts { deliver(context.url) }
        return false
    }
}

extension VersolaPlugin: VersolaHostApi {
    /// Every answer is a Result (`flutter.md`): an `OAuthError` crosses as itself, anything else
    /// as a `Configuration` naming only its type; a thrown error would reach Dart as a
    /// `PlatformException` carrying native text.
    private func attempt<R>(_ failure: (VersolaErrorMessage) -> R, _ body: () async throws -> R) async -> R {
        do {
            return try await body()
        } catch {
            return failure(error.toErrorMessage())
        }
    }

    private func voidResult(_ body: () async throws -> Void) async -> VersolaVoidResult {
        await attempt(VersolaVoidFailure.init(error:)) {
            try await body()
            return VersolaVoidOk()
        }
    }

    func create(configuration: VersolaConfigurationMessage) async throws -> VersolaCreateResult {
        await attempt(VersolaCreateFailure.init(error:)) {
            // The SDK validates eagerly (a bad URL, a skew over five minutes, a second
            // configuration for the same issuer and client id) and throws; that is the answer.
            let client = try await Versola.create(
                configuration: try configuration.toConfiguration(),
                presentationAnchor: { Self.presentationAnchor() }
            )
            let (handle, newStream) = await clients.put(client)
            if let newStream, let messenger {
                // Flutter requires a stream handler to be installed on the platform thread; the
                // actor above runs on the cooperative pool, so this hop is not optional (the
                // engine aborts the process otherwise).
                await MainActor.run {
                    SessionStatesStreamHandler.register(with: messenger, instanceName: handle, streamHandler: newStream)
                }
            }
            return VersolaCreateOk(handle: handle)
        }
    }

    func sessionState(handle: String) async throws -> VersolaSessionStateResult {
        await attempt(VersolaSessionStateFailure.init(error:)) {
            VersolaSessionStateOk(state: try await clients.get(handle).sessionState.toMessage())
        }
    }

    func login(handle: String, options: VersolaLoginOptionsMessage) async throws -> VersolaVoidResult {
        await voidResult { try await clients.get(handle).login(options.toLoginOptions()) }
    }

    /// `options` is nil when the app passed none: the SDK then re-authorizes with the scopes the
    /// session was granted, which is not the same as passing empty options.
    func stepUp(handle: String, acrValues: [String], maxAge: Int64?, options: VersolaLoginOptionsMessage?) async throws -> VersolaVoidResult {
        await voidResult {
            try await clients.get(handle).stepUp(
                .stepUp(acrValues: acrValues, maxAge: maxAge.map(Int.init)),
                options: options?.toLoginOptions()
            )
        }
    }

    func logout(handle: String, options: VersolaLogoutOptionsMessage) async throws -> VersolaLogoutResult {
        await attempt(VersolaLogoutFailure.init(error:)) {
            let outcome = try await clients.get(handle).logout(LogoutOptions(endSession: options.endSession, revoke: options.revoke))
            return VersolaLogoutOk(outcome: VersolaLogoutOutcomeMessage(sessionEnded: outcome.sessionEnded, tokenRevoked: outcome.tokenRevoked))
        }
    }

    func refresh(handle: String) async throws -> VersolaVoidResult {
        await voidResult { try await clients.get(handle).refresh() }
    }

    func claims(handle: String) async throws -> VersolaClaimsResult {
        await attempt(VersolaClaimsFailure.init(error:)) {
            guard let c = try await clients.get(handle).claims else { return VersolaClaimsOk(claims: nil) }
            return VersolaClaimsOk(claims: VersolaIdTokenClaimsMessage(
                subject: c.subject,
                issuer: c.issuer,
                audience: c.audience,
                issuedAtEpochSeconds: Int64(c.issuedAt.timeIntervalSince1970),
                expiresAtEpochSeconds: Int64(c.expiresAt.timeIntervalSince1970),
                authTimeEpochSeconds: c.authTime.map { Int64($0.timeIntervalSince1970) },
                acr: c.acr,
                amr: c.amr,
                authorizedParty: c.authorizedParty,
                all: c.all
            ))
        }
    }

    /// `Versola.session()`: the SDK's own session runs the request, so the token, the proof, the
    /// refresh and the edge-only scope stay here. A call that produced no HTTP response is
    /// not an SDK error: it crosses as the error's type and code alone, since a `URLError`'s text
    /// carries the URL.
    func httpRequest(handle: String, request: VersolaHttpRequestMessage) async throws -> VersolaHttpResult {
        await attempt(VersolaHttpFailure.init(error:)) {
            let client = try await clients.get(handle)
            let prepared = try request.toURLRequest()
            let session = try client.session()
            do {
                let (data, response) = try await session.data(for: prepared)
                return VersolaHttpOk(response: VersolaHttpResponseMessage(data, response))
            } catch let error as URLError {
                return VersolaHttpTransportFailure(exception: "URLError(\(error.code.rawValue))")
            }
        }
    }

    /// Asking generates the key, so `hardwareBindingUnavailable` is a reachable answer here.
    func keyAttestation(handle: String) async throws -> VersolaKeyAttestationResult {
        await attempt(VersolaKeyAttestationFailure.init(error:)) {
            VersolaKeyAttestationOk(tier: try await clients.get(handle).keyAttestation().map { $0.tier.rawValue })
        }
    }
}

/// One event channel per client. `onListen` starts consuming the SDK's `AsyncStream` (one
/// stream per observer, as the SDK promises) and forwards each state on the main thread, where
/// a `FlutterEventSink` must be called; `onCancel` ends the task, so a Dart subscription and
/// the native consumption have the same lifetime.
final class SessionStateStream: SessionStatesStreamHandler {
    private let client: Versola
    private var task: Task<Void, Never>?

    init(client: Versola) {
        self.client = client
    }

    override func onListen(withArguments arguments: Any?, sink: PigeonEventSink<VersolaSessionStateMessage>) {
        task?.cancel()
        let client = client
        task = Task {
            for await state in await client.sessionStates() {
                if Task.isCancelled { return }
                await MainActor.run { sink.success(state.toMessage()) }
            }
        }
    }

    override func onCancel(withArguments arguments: Any?) {
        task?.cancel()
        task = nil
    }
}
