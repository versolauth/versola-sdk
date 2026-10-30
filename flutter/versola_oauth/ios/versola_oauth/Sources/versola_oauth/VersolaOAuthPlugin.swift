// The iOS half of the binding (`.claude/rules/flutter.md`): one Pigeon host API over the public
// surface of `VersolaOAuth`'s `OAuthClient`, and one event channel per client for the state
// machine. It converts types and nothing else; every behaviour is the SDK's.
import AuthenticationServices
import Flutter
import OAuthClient
import UIKit

public final class VersolaOAuthPlugin: NSObject, FlutterPlugin {
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
        let instance = VersolaOAuthPlugin()
        instance.messenger = registrar.messenger()
        OAuthHostApiSetup.setUp(binaryMessenger: registrar.messenger(), api: instance)
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
        private var byHandle: [String: OAuthClient] = [:]
        private var handleByIdentity: [String: String] = [:]
        private var streams: [String: SessionStateStream] = [:]
        private var nextHandle = 0
        private var unclaimed: [URL] = []

        func get(_ handle: String) throws -> OAuthClient {
            guard let client = byHandle[handle] else {
                throw OAuthError.configuration(.invalidConfiguration(detail: "no client for this handle; call create first"))
            }
            return client
        }

        /// Names the client: one handle per configuration (issuer and client id), chosen here so
        /// Dart derives nothing. Returns the stream handler to register when this handle is new,
        /// and offers any redirect that arrived before the client existed.
        func put(_ client: OAuthClient) async -> (handle: String, newStream: SessionStateStream?) {
            let identity = "\(client.configuration.issuerIdentifier)\n\(client.configuration.clientId)"
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

extension VersolaOAuthPlugin: FlutterSceneLifeCycleDelegate {
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

extension VersolaOAuthPlugin: OAuthHostApi {
    /// Every answer is a Result (`flutter.md`): an `OAuthError` crosses as itself, anything else
    /// as a `Configuration` naming only its type; a thrown error would reach Dart as a
    /// `PlatformException` carrying native text.
    private func attempt<R>(_ failure: (ErrorMessage) -> R, _ body: () async throws -> R) async -> R {
        do {
            return try await body()
        } catch {
            return failure(error.toErrorMessage())
        }
    }

    private func voidResult(_ body: () async throws -> Void) async -> VoidResult {
        await attempt(VoidFailure.init(error:)) {
            try await body()
            return VoidOk()
        }
    }

    func create(configuration: ConfigurationMessage) async throws -> CreateResult {
        await attempt(CreateFailure.init(error:)) {
            // The SDK validates eagerly (a bad URL, a skew over five minutes, a second
            // configuration for the same issuer and client id) and throws; that is the answer.
            let client = try await OAuthClient.create(
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
            return CreateOk(handle: handle)
        }
    }

    func sessionState(handle: String) async throws -> SessionStateResult {
        await attempt(SessionStateFailure.init(error:)) {
            SessionStateOk(state: await try clients.get(handle).sessionState.toMessage())
        }
    }

    func login(handle: String, options: LoginOptionsMessage) async throws -> VoidResult {
        await voidResult { try await clients.get(handle).login(try options.toLoginOptions()) }
    }

    func stepUp(handle: String, acrValues: [String], maxAge: Int64?, options: LoginOptionsMessage) async throws -> VoidResult {
        await voidResult {
            try await clients.get(handle).stepUp(acrValues: acrValues, maxAge: maxAge.map(Int.init), options: try options.toLoginOptions())
        }
    }

    func logout(handle: String, options: LogoutOptionsMessage) async throws -> LogoutResult {
        await attempt(LogoutFailure.init(error:)) {
            let outcome = try await clients.get(handle).logout(LogoutOptions(endSession: options.endSession, revoke: options.revoke))
            return LogoutOk(outcome: LogoutOutcomeMessage(sessionEnded: outcome.sessionEnded, tokenRevoked: outcome.tokenRevoked))
        }
    }

    func accessToken(handle: String) async throws -> AccessTokenResult {
        await attempt(AccessTokenFailure.init(error:)) {
            // The one credential that crosses (issue #46 decision 7).
            let token = try await clients.get(handle).accessToken()
            return AccessTokenOk(token: AccessTokenMessage(value: token.value, tokenType: token.tokenType))
        }
    }

    func refresh(handle: String) async throws -> VoidResult {
        await voidResult { try await clients.get(handle).refresh() }
    }

    func claims(handle: String) async throws -> ClaimsResult {
        await attempt(ClaimsFailure.init(error:)) {
            guard let c = try await clients.get(handle).claims else { return ClaimsOk(claims: nil) }
            return ClaimsOk(claims: IdTokenClaimsMessage(
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

    func userInfo(handle: String) async throws -> UserInfoResult {
        await attempt(UserInfoFailure.init(error:)) {
            let info = try await clients.get(handle).userInfo()
            return UserInfoOk(userInfo: UserInfoMessage(subject: info.subject, claims: info.claims))
        }
    }

    /// Asking generates the key, so `hardwareBindingUnavailable` is a reachable answer here.
    func keyAttestation(handle: String) async throws -> KeyAttestationResult {
        await attempt(KeyAttestationFailure.init(error:)) {
            KeyAttestationOk(tier: try await clients.get(handle).keyAttestation().map { $0.tier.rawValue })
        }
    }
}

/// One event channel per client. `onListen` starts consuming the SDK's `AsyncStream` (one
/// stream per observer, as the SDK promises) and forwards each state on the main thread, where
/// a `FlutterEventSink` must be called; `onCancel` ends the task, so a Dart subscription and
/// the native consumption have the same lifetime.
final class SessionStateStream: SessionStatesStreamHandler {
    private let client: OAuthClient
    private var task: Task<Void, Never>?

    init(client: OAuthClient) {
        self.client = client
    }

    override func onListen(withArguments arguments: Any?, sink: PigeonEventSink<SessionStateMessage>) {
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
