import AuthenticationServices
import Foundation

/// A redirect handed over by the app for an authorization this process did not start, with room
/// for those that arrive before anyone is waiting: a cold-started process is handed the redirect
/// before the resume has read the request it answers, and may be handed others (a stale link,
/// another app) before or after it. They are kept in arrival order, up to `capacity`, the oldest
/// dropped first, and the flow reads them against the request: the one that carries its `state`
/// answers it and the others are stepped over. One waiter.
actor PendingRedirects {
    static let capacity = 8

    private var buffered: [URL] = []
    private var waiter: (id: Int, continuation: CheckedContinuation<URL, any Error>)?
    private var nextId = 0

    func deliver(_ url: URL) {
        if let waiter {
            self.waiter = nil
            waiter.continuation.resume(returning: url)
        } else {
            buffered.append(url)
            if buffered.count > Self.capacity { buffered.removeFirst() }
        }
    }

    /// A new authorization is starting: redirects buffered for an older one are stale and
    /// must not be mistaken for this one's.
    func drain() {
        buffered.removeAll()
    }

    func next() async throws -> URL {
        if !buffered.isEmpty { return buffered.removeFirst() }
        try Task.checkCancellation()
        nextId += 1
        let id = nextId
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                // Only one waiter: an earlier one is superseded, not left hanging.
                waiter?.continuation.resume(throwing: CancellationError())
                waiter = (id, continuation)
                // The cancellation hop below may have run before this registration.
                if Task.isCancelled { cancelWaiter(id) }
            }
        } onCancel: {
            Task { await self.cancelWaiter(id) }
        }
    }

    private func cancelWaiter(_ id: Int) {
        guard let waiter, waiter.id == id else { return }
        self.waiter = nil
        waiter.continuation.resume(throwing: CancellationError())
    }
}

/// The browser leg on `ASWebAuthenticationSession`: the system browser with the user's
/// passkeys and single sign-on, never a web view (RFC 8252; `BrowserAuthorizationSession` takes
/// a URI and returns one, which is what keeps a web view unrepresentable).
///
/// The presentation anchor and the foreground check come from the app: the SDK does not go
/// looking for a window (`ios-swift.md`). Works on macOS too (the anchor is an `NSWindow`
/// there) so the package's host tests compile the same API.
package final class WebAuthenticationBrowser: BrowserAuthorizationSession, Sendable {
    private let anchor: @Sendable @MainActor () -> ASPresentationAnchor
    private let isForeground: @Sendable @MainActor () -> Bool
    private let logger: (any OAuthLogger)?
    private let redirects = PendingRedirects()

    /// - Parameters:
    ///   - presentationAnchor: the window the browser sheet is presented over.
    ///   - appState: whether the app is in the foreground right now. Asked at the moment a
    ///     `canceledLogin` arrives, to tell a user's dismissal from the system's teardown.
    ///   - logger: receives a warning when the session ends in a way the SDK did not expect.
    package init(
        presentationAnchor: @escaping @Sendable @MainActor () -> ASPresentationAnchor,
        appState: @escaping @Sendable @MainActor () -> Bool,
        logger: (any OAuthLogger)? = nil
    ) {
        self.anchor = presentationAnchor
        self.isForeground = appState
        self.logger = logger
    }

    // MARK: BrowserAuthorizationSession

    package func authorize(_ uri: URL, options: BrowserSessionOptions) async throws -> BrowserOutcome {
        guard let redirectURI = options.redirectURI else {
            throw OAuthError.configuration(.invalidConfiguration(detail: "a redirect URI is needed to open the browser"))
        }
        let spec = try Self.callbackSpec(for: redirectURI)
        await redirects.drain()

        let anchor = self.anchor
        let isForeground = self.isForeground
        let active = ActiveSession()
        let result: (Result<URL, any Error>, Bool) = await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                Task { @MainActor in
                    active.start(
                        url: uri, spec: spec, ephemeral: options.ephemeral, anchor: anchor,
                        foreground: isForeground
                    ) { result, foreground in continuation.resume(returning: (result, foreground)) }
                }
            }
        } onCancel: {
            Task { @MainActor in active.cancel() }
        }
        // A caller that was cancelled gets a cancellation, not an outcome it no longer wants.
        try Task.checkCancellation()
        let outcome = try Self.outcome(for: result.0, foreground: result.1, logger: logger).get()
        return Self.ended(outcome, expectedState: options.expectedState, logger: logger)
    }

    /// The redirect of an authorization this process did not start: whatever the app handed to
    /// `deliver(_:)`. `ASWebAuthenticationSession` returns its own redirect, so on iOS nothing
    /// else feeds this.
    package func awaitPendingRedirect() async throws -> BrowserOutcome {
        .redirect(try await redirects.next())
    }

    /// What the facade's `handleRedirect(_:)` calls: the URL the app's URL handler received.
    package func deliver(_ url: URL) async {
        await redirects.deliver(url)
    }

    // MARK: Mapping (pure, so the host tests can drive it)

    /// How the redirect URI is matched: a universal link by host and path (iOS 17.4), a
    /// private-use scheme by scheme. A cleartext loopback URI cannot be intercepted by the
    /// system browser session at all, so it is a configuration error here rather than a session
    /// that never returns.
    enum CallbackSpec: Equatable {
        case https(host: String, path: String)
        case customScheme(String)
    }

    static func callbackSpec(for redirect: URL) throws -> CallbackSpec {
        guard let scheme = redirect.scheme?.lowercased(), !scheme.isEmpty else {
            throw OAuthError.configuration(.invalidConfiguration(detail: "the redirect URI has no scheme"))
        }
        switch scheme {
        case "https":
            guard let host = URLRules.normalizedHost(redirect.host) else {
                throw OAuthError.configuration(.invalidConfiguration(detail: "the redirect URI has no host"))
            }
            return .https(host: host, path: redirect.path.isEmpty ? "/" : redirect.path)
        case "http":
            throw OAuthError.configuration(
                .invalidConfiguration(detail: "a cleartext redirect URI cannot be received by ASWebAuthenticationSession")
            )
        default:
            return .customScheme(scheme)
        }
    }

    /// What the session's own completion means when it carries a redirect that is not the response
    /// to the login in progress (scenario 15). `ASWebAuthenticationSession` completes the moment its
    /// page navigates to the callback URL, so the sheet is gone with that redirect: nothing can
    /// follow from it, no dismissal can be observed any more, and the genuine response cannot come
    /// from it. Waiting on would leave a login that nobody can see or cancel, so it ends as the
    /// user closing the sheet would end it (`userCancelled`, the request wiped) and not as a system
    /// cancel, which an app retries silently. A URL another app opens reaches the SDK through
    /// `handleRedirect`, not through the sheet, and the flow ignores it there.
    static func ended(_ outcome: BrowserOutcome, expectedState: String?, logger: (any OAuthLogger)?) -> BrowserOutcome {
        guard case .redirect(let url) = outcome, let expectedState,
              !AuthorizationResponseValidator.carries(url, state: expectedState) else { return outcome }
        logger?.warn("the browser session ended with a redirect that is not the response to the login in progress; the login is over")
        return .userCancelled
    }

    /// `canceledLogin` is one code for two causes; `foreground` (read at the moment it arrived)
    /// tells them apart: the user dismissed the sheet, or the system tore the session down
    /// (`spec/state-machine.md`, the cancel table). The pending request is wiped on the first
    /// and kept on the second, so getting this wrong either strands a login or nags a user.
    static func outcome(
        for result: Result<URL, any Error>, foreground: Bool, logger: (any OAuthLogger)? = nil
    ) -> Result<BrowserOutcome, OAuthError> {
        switch result {
        case .success(let url):
            return .success(.redirect(url))
        case .failure(let error):
            if let sessionError = error as? ASWebAuthenticationSessionError {
                switch sessionError.code {
                case .canceledLogin:
                    return .success(foreground ? .userCancelled : .systemCancelled)
                case .presentationContextInvalid, .presentationContextNotProvided:
                    return .failure(.configuration(.noBrowserAvailable))
                @unknown default:
                    break
                }
            }
            // Domain and code only: an error's text or user info can quote the URL.
            let nsError = error as NSError
            logger?.warn("the system browser session ended unexpectedly (\(nsError.domain) \(nsError.code))")
            return .failure(.configuration(.noBrowserAvailable))
        }
    }
}

// MARK: - The session itself (main actor only)

/// Holds the live session and its presentation provider: `ASWebAuthenticationSession` keeps
/// its provider weakly, and the session must outlive `start()`. Main-actor isolated, hence
/// `Sendable`, which is what lets the cancellation handler reach it.
@MainActor
private final class ActiveSession {
    private var session: ASWebAuthenticationSession?
    private var provider: PresentationContextProvider?
    private var cancelled = false
    private var finish: (@MainActor (Result<URL, any Error>, Bool) -> Void)?

    nonisolated init() {}

    func start(
        url: URL, spec: WebAuthenticationBrowser.CallbackSpec, ephemeral: Bool,
        anchor: @escaping @MainActor () -> ASPresentationAnchor, foreground: @escaping @MainActor () -> Bool,
        finish: @escaping @MainActor (Result<URL, any Error>, Bool) -> Void
    ) {
        // Cancelled before it started: nothing to present, and the caller is told so.
        if cancelled {
            finish(.failure(CancellationError()), foreground())
            return
        }
        self.finish = finish
        let callback: ASWebAuthenticationSession.Callback
        switch spec {
        case .https(let host, let path): callback = .https(host: host, path: path)
        case .customScheme(let scheme): callback = .customScheme(scheme)
        }
        let session = ASWebAuthenticationSession(url: url, callback: callback) { [weak self] callbackURL, error in
            // Delivered on the main queue in practice, but no queue is documented: hop rather
            // than assume, since an assumption that fails is a trap inside the SDK. The
            // lifecycle state is read on the hop, still the state the cancellation arrived in.
            Task { @MainActor in
                let result: Result<URL, any Error>
                if let callbackURL {
                    result = .success(callbackURL)
                } else {
                    result = .failure(error ?? ASWebAuthenticationSessionError(.canceledLogin))
                }
                self?.complete(result, foreground: foreground())
            }
        }
        let provider = PresentationContextProvider(anchor: anchor)
        session.presentationContextProvider = provider
        session.prefersEphemeralWebBrowserSession = ephemeral
        self.session = session
        self.provider = provider
        if !session.start() {
            // `start()` refusing means no window to present in; no completion will follow.
            complete(.failure(ASWebAuthenticationSessionError(.presentationContextInvalid)), foreground: foreground())
        }
    }

    func cancel() {
        cancelled = true
        // A started session answers with `canceledLogin`, which `complete` then reports as a
        // cancellation of the calling task; one not started yet is stopped in `start`.
        session?.cancel()
    }

    private func complete(_ result: Result<URL, any Error>, foreground: Bool) {
        guard let finish else { return }
        self.finish = nil
        session = nil
        provider = nil
        finish(result, foreground)
    }
}

@MainActor
private final class PresentationContextProvider: NSObject, ASWebAuthenticationPresentationContextProviding {
    private let anchor: @MainActor () -> ASPresentationAnchor

    init(anchor: @escaping @MainActor () -> ASPresentationAnchor) {
        self.anchor = anchor
    }

    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        anchor()
    }
}
