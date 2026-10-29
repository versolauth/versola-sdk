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
        registrar.addApplicationDelegate(instance)
    }

    /// A Universal Link that reached the app while `ASWebAuthenticationSession` was not up
    /// (a cold start) is handed to the client whose redirect URI it is.
    public func application(_ application: UIApplication, continue userActivity: NSUserActivity, restorationHandler: @escaping ([any UIUserActivityRestoring]) -> Void) -> Bool {
        guard userActivity.activityType == NSUserActivityTypeBrowsingWeb, let url = userActivity.webpageURL else { return false }
        Task { await clients.deliver(url) }
        return false
    }

    /// The handle→client map behind an actor: Pigeon calls arrive on the main actor, the
    /// state collections run in their own tasks.
    actor Clients {
        private var byHandle: [String: OAuthClient] = [:]
        private var streams: [String: SessionStateStream] = [:]

        func get(_ handle: String) throws -> OAuthClient {
            guard let client = byHandle[handle] else {
                throw OAuthError.configuration(.invalidConfiguration(detail: "no client for this handle; call create first"))
            }
            return client
        }

        /// Records the client and answers with the stream to register for it, or nil when this
        /// handle already has one. Registering is not done here: this actor runs on the
        /// cooperative pool, and an event channel may only be registered on the platform thread.
        func put(_ handle: String, _ client: OAuthClient) -> SessionStateStream? {
            byHandle[handle] = client
            guard streams[handle] == nil else { return nil }
            let stream = SessionStateStream(client: client)
            streams[handle] = stream
            return stream
        }

        func deliver(_ url: URL) async {
            for client in byHandle.values where await client.handleRedirect(url) { return }
        }
    }
}

extension VersolaOAuthPlugin: OAuthHostApi {
    func create(handle: String, configuration: ConfigurationMessage) async throws -> VoidResult {
        try await voidResult {
            // The SDK validates eagerly (a bad URL, a skew over five minutes, a second
            // configuration for the same issuer and client id) and throws; that is the answer.
            let client = try await OAuthClient.create(
                configuration: try configuration.toConfiguration(),
                presentationAnchor: { Self.presentationAnchor() }
            )
            if let stream = await clients.put(handle, client), let messenger {
                // The engine checks that a channel handler is registered on the platform thread
                // (a debug build aborts otherwise); a Pigeon call reaches this method on the pool.
                await MainActor.run {
                    SessionStatesStreamHandler.register(with: messenger, instanceName: handle, streamHandler: stream)
                }
            }
        }
    }

    func sessionState(handle: String) async throws -> SessionStateMessage {
        try await clients.get(handle).sessionState.toMessage()
    }

    func login(handle: String, options: LoginOptionsMessage) async throws -> VoidResult {
        try await voidResult { try await clients.get(handle).login(try options.toLoginOptions()) }
    }

    func stepUp(handle: String, acrValues: [String], maxAge: Int64?, options: LoginOptionsMessage) async throws -> VoidResult {
        try await voidResult {
            try await clients.get(handle).stepUp(acrValues: acrValues, maxAge: maxAge.map(Int.init), options: try options.toLoginOptions())
        }
    }

    func resumePendingAuthorization(handle: String) async throws -> VoidResult {
        try await voidResult { try await clients.get(handle).resumePendingAuthorization() }
    }

    func logout(handle: String, options: LogoutOptionsMessage) async throws -> LogoutOutcomeMessage {
        let outcome = try await clients.get(handle).logout(LogoutOptions(endSession: options.endSession, revoke: options.revoke))
        return LogoutOutcomeMessage(sessionEnded: outcome.sessionEnded, tokenRevoked: outcome.tokenRevoked)
    }

    func accessToken(handle: String) async throws -> AccessTokenResult {
        do {
            // The one credential that crosses (issue #46 decision 7).
            let token = try await clients.get(handle).accessToken()
            // The scheme as the spec names it (`Bearer` or `DPoP`), as the Android half sends it: the
            // SDK's `tokenType` is the provider's own spelling, and Hydra answers `bearer`.
            let scheme = token.tokenType.caseInsensitiveCompare("DPoP") == .orderedSame ? "DPoP" : "Bearer"
            return AccessTokenOk(token: AccessTokenMessage(value: token.value, tokenType: scheme))
        } catch let error as OAuthError {
            return AccessTokenFailure(error: error.toMessage())
        }
    }

    func refresh(handle: String) async throws -> VoidResult {
        try await voidResult { try await clients.get(handle).refresh() }
    }

    func claims(handle: String) async throws -> IdTokenClaimsMessage? {
        guard let c = try await clients.get(handle).claims else { return nil }
        return IdTokenClaimsMessage(
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
        )
    }

    func userInfo(handle: String) async throws -> UserInfoResult {
        do {
            let info = try await clients.get(handle).userInfo()
            return UserInfoOk(userInfo: UserInfoMessage(subject: info.subject, claims: info.claims))
        } catch let error as OAuthError {
            return UserInfoFailure(error: error.toMessage())
        }
    }

    func keyAttestation(handle: String) async throws -> String? {
        try await clients.get(handle).keyAttestation().map { $0.tier.rawValue }
    }

    /// Result-shaped answers: an `OAuthError` crosses typed; anything else (there is nothing
    /// else on the SDK's API) would surface as a `PlatformException`, which is a bug.
    private func voidResult(_ body: () async throws -> Void) async throws -> VoidResult {
        do {
            try await body()
            return VoidOk()
        } catch let error as OAuthError {
            return VoidFailure(error: error.toMessage())
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
